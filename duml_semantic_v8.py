#!/usr/bin/env python3
"""
DJI DUML parser + USBPcap extractor — semantic streaming v8.

Combines the core functionality of CunningLogic/dumlPrinter with a dependency-
free USBPcap reader. It can decode either a single DUML packet supplied as HEX
or all valid DUML packets found in a classic USBPcap .pcap capture.

Examples:
    python duml.py 550D04332A2835124000002AE4
    python duml.py flash_usb.pcap
    python duml.py flash_usb.pcap --summary-only
    python duml_semantic.py full_usb3.pcap --state-machine --filetrans --extract-files extracted

DUML fixes versus the original Java dumlPrinter:
    * source/target component IDs use the low 5 bits (& 0x1F)
    * source/target instance numbers use the high 3 bits
    * command type uses the high 3 bits (& 0xE0)
    * payload excludes the trailing CRC16
    * packet checksum is correctly called CRC16
    * Python has no Java signed-byte length issue
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import os
import struct
import sys
import tempfile
import shutil
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, Iterable, Iterator, Optional, TextIO, Tuple


MAGIC = 0x55
MIN_PACKET_LEN = 13
MAX_PACKET_LEN = 0x03FF

CRC8_SEED = 0x77
CRC16_SEED = 0x3692
CRC8_POLY = 0x8C
CRC16_POLY = 0x8408

USBPCAP_LINKTYPE = 249
USBPCAP_BASE_HEADER_LEN = 27

LOCATIONS = {
    1: "Camera",
    2: "Mobile App",
    3: "Flight Controller",
    4: "Gimbal",
    5: "Mainboard",
    6: "Remote Control",
    7: "Wifi Module Air Side",
    8: "DM368 Air Side",
    9: "HD Map Air Side",
    10: "PC",
    11: "Smart Battery",
    12: "ESC",
    13: "DM368 Ground Side",
    14: "HD Map Ground Side",
    15: "String Conversion Air Side",
    16: "String Conversion Ground Side",
    17: "VPS",
    18: "Obstacle Avoidance",
    19: "HD Graphics Air Side",
    20: "HD Map Ground Side FPGA",
    21: "Simulator",
    22: "Base Station",
    23: "Airborne Computing Platform",
    24: "RC Battery",
    25: "IMU",
    26: "GPS",
    27: "WiFi Module Ground Side",
    28: "Agricultural Machine Signal Conversion Board",
}

CMD_SETS = {
    0: "Universal",
    1: "Special",
    2: "Camera",
    3: "Flight Controller",
    4: "Gimbal",
    5: "Mainboard",
    6: "Remote Control",
    7: "WiFi",
    8: "DM368",
    9: "HD Map",
    10: "VPS / Obstacle Avoidance",
    11: "Simulator",
    12: "Order",
    13: "Smart Battery",
    14: "Data Logger",
    15: "RTK",
    16: "Automated Test",
}

CMD_TYPES = {
    0x00: "No ACK",
    0x20: "Push",
    0x40: "ACK",
    0x80: "Response",
}

TRANSFER_TYPES = {
    0: "Isochronous",
    1: "Interrupt",
    2: "Control",
    3: "Bulk",
}


PACKET_TYPES = {
    0: "Request",
    1: "Response",
}

ACK_TYPES = {
    0: "NO_ACK_NEEDED",
    1: "ACK_BEFORE_EXEC",
    2: "ACK_AFTER_EXEC",
    3: "ACK_RESERVED",
}

ENCRYPT_TYPES = {
    0: "NO_ENC",
    1: "AES_128",
    2: "SELF_DEF",
    3: "XOR",
    4: "DES_56",
    5: "DES_112",
    6: "AES_192",
    7: "AES_256",
}

# Command names are primarily based on o-gs/dji-firmware-tools.
# Newer 0x81/0x82 names are intentionally qualified because their exact role
# varies between products/transports.
COMMAND_NAMES = {
    0x00: {
        0x00: "Ping",
        0x01: "Version Inquiry",
        0x02: "Push Param Set",
        0x03: "Push Param Get",
        0x04: "Push Param Start",
        0x05: "Multi Param Set",
        0x06: "Multi Param Get",
        0x07: "Enter Loader",
        0x08: "Update Confirm",
        0x09: "Update Transmit",
        0x0A: "Update Finish",
        0x0B: "Reboot Chip",
        0x0C: "Get Device State",
        0x0D: "Set Device Version",
        0x0E: "Heartbeat / Log Message",
        0x0F: "Upgrade Self Request",
        0x20: "File List",
        0x21: "File Info",
        0x22: "File Send",
        0x23: "File Receive",
        0x24: "File Sending",
        0x25: "File Segment Error",
        0x26: "FileTrans App -> Camera",
        0x27: "FileTrans Camera -> App",
        0x28: "FileTrans Delete",
        0x2A: "FileTrans General Trans",
        0x30: "Encrypt Config",
        0x32: "Activate Config",
        0x33: "MFi Cert",
        0x34: "Safe Communication",
        0x40: "FW Update Desc Push",
        0x41: "FW Update Push Control",
        0x42: "FW Upgrade Push Status",
        0x43: "FW Upgrade Finish",
        0x45: "Sleep Control",
        0x46: "Shutdown Notification",
        0x47: "Power State",
        0x48: "LED Control",
        0x4A: "Set Date/Time",
        0x4B: "Get Date/Time",
        0x4C: "Get Module System Status",
        0x4D: "Set RT",
        0x4E: "Get RT",
        0x4F: "Get Cfg File",
        0x50: "Set Serial Number",
        0x51: "Get Serial Number",
        0x52: "Set GPS Push Config",
        0x53: "Push GPS Info",
        0x54: "Get Temperature Info",
        0x55: "Get Alive Time",
        0x56: "Over Temperature",
        0x57: "Send Network Info",
        0x58: "Time Sync",
        0x59: "Test Mode",
        0x5A: "Play Sound",
        0x5C: "UAV Fly Info",
        0x60: "Auto Test Info",
        0x61: "Set Product Newest Version",
        0x62: "Get Product Newest Version",
        0x81: "Upgrade Center Info",
        0x82: "Upgrade Center State",
        0x83: "Upgrade Prepare",
        0x84: "Upgrade Announce",
        0x85: "Upgrade Install",
        0xEF: "Send Reserved Key",
        0xF0: "Log Push",
        0xF1: "Component Self Test State",
        0xF2: "Log Control Global",
        0xF3: "Log Control Module",
        0xF4: "Test Start",
        0xF5: "Test Stop",
        0xF6: "Test Query Result",
        0xF7: "Push Test Result",
        0xF8: "Get Metadata",
        0xFA: "Log Control",
        0xFB: "Selftest State",
        0xFC: "Selftest State Count",
        0xFD: "Dump Frame Buffer",
        0xFE: "Self Define",
        0xFF: "Query Device Info",
    },
    0x03: {
        0x43: "OSD General Data Get",
        0xCE: "Push Forbid Data Infos",
        0xE0: "Config Table: Get Table Attributes",
        0xE1: "Config Table: Get Param Info by Index",
        0xE2: "Config Table: Read/Write Param by Index",
        0xE5: "Config Table: Extended Param Info",
        0xE6: "Config Table: Status/Telemetry Group Query",
        0xE9: "Config Table: Progress/Status",
        0xF0: "Config Table: Get Param Info by Index",
        0xF1: "Config Table: Read Params by Index",
        0xF2: "Config Table: Write Params by Index",
    },
    0x04: {
        0x01: "Gimbal Control",
        0x02: "Gimbal Get Position",
        0x03: "Gimbal Set Param",
        0x04: "Gimbal Get Param",
        0x05: "Gimbal Params / State Push",
        0x06: "Gimbal Push AETR",
        0x07: "Gimbal Adjust Roll",
        0x08: "Gimbal Calibrate",
        0x0A: "Gimbal External Control Degree",
        0x0B: "Gimbal External Control Status",
        0x0C: "Gimbal External Control Accel",
        0x0D: "Gimbal Suspend / Resume",
        0x14: "Gimbal Absolute Angle Control",
        0x15: "Gimbal Move",
        0x27: "Gimbal Abnormal Status",
        0x30: "Gimbal Auto Calibration Status",
        0x4C: "Gimbal Reset / Set Mode",
    },
}

UPGRADE_STATES = {
    1: "Verify",
    2: "UserConfirm",
    3: "Upgrading",
    4: "Complete",
}

UPGRADE_RESULTS = {
    1: "Success",
    2: "Failure",
    3: "FirmwareError",
    4: "SameVersion",
    5: "UserCancel",
    6: "TimeOut",
    7: "MotorWorking",
    8: "FirmNotMatch",
    9: "IllegalDegrade",
    10: "NoConnectRC",
}


class DumlError(ValueError):
    """Raised when a packet is not a valid DUML frame."""


class PcapError(ValueError):
    """Raised when the capture cannot be parsed as classic USBPcap."""


@dataclass(frozen=True)
class DumlPacket:
    raw: bytes
    length: int
    version: int
    header_crc8: int
    source: int
    source_id: int
    target: int
    target_id: int
    sequence: int
    cmd_type: int
    cmd_set: int
    cmd_id: int
    payload: bytes
    packet_crc16: int
    calculated_crc16: int

    @property
    def source_name(self) -> str:
        return LOCATIONS.get(self.source_id, "Unknown")

    @property
    def target_name(self) -> str:
        return LOCATIONS.get(self.target_id, "Unknown")

    @property
    def cmd_type_name(self) -> str:
        return CMD_TYPES.get(self.cmd_type, "Unknown")

    @property
    def cmd_set_name(self) -> str:
        return CMD_SETS.get(self.cmd_set, "Unknown")

    @property
    def command_name(self) -> str:
        return COMMAND_NAMES.get(self.cmd_set, {}).get(self.cmd_id, "Unknown")

    @property
    def packet_type(self) -> int:
        return (self.raw[8] >> 7) & 0x01

    @property
    def packet_type_name(self) -> str:
        return PACKET_TYPES.get(self.packet_type, "Unknown")

    @property
    def ack_type(self) -> int:
        return (self.raw[8] >> 5) & 0x03

    @property
    def ack_type_name(self) -> str:
        return ACK_TYPES.get(self.ack_type, "Unknown")

    @property
    def encrypt_type(self) -> int:
        return self.raw[8] & 0x07

    @property
    def encrypt_type_name(self) -> str:
        return ENCRYPT_TYPES.get(self.encrypt_type, "Unknown")

    @property
    def source_route(self) -> str:
        return route_id(self.source_id, self.source)

    @property
    def target_route(self) -> str:
        return route_id(self.target_id, self.target)


@dataclass(frozen=True)
class USBMeta:
    pcap_record: int
    timestamp: float
    bus: int
    device: int
    endpoint: int
    info: int
    transfer: int
    declared_data_len: int
    captured_data_len: int

    @property
    def direction(self) -> str:
        return "IN" if (self.endpoint & 0x80) else "OUT"

    @property
    def transfer_name(self) -> str:
        return TRANSFER_TYPES.get(self.transfer, f"Unknown({self.transfer})")


@dataclass(frozen=True)
class CapturedDuml:
    index: int
    usb: USBMeta
    usb_offset: int
    spanned_urbs: int
    packet: DumlPacket


@dataclass
class _Segment:
    remaining: int
    meta: USBMeta
    offset: int = 0


class DumlStreamDecoder:
    """Incremental DUML decoder for one USB endpoint stream."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.segments: Deque[_Segment] = deque()

    def _consume(self, count: int) -> None:
        if count <= 0:
            return
        del self.buffer[:count]
        left = count
        while left and self.segments:
            seg = self.segments[0]
            take = min(left, seg.remaining)
            seg.remaining -= take
            seg.offset += take
            left -= take
            if seg.remaining == 0:
                self.segments.popleft()

    def _origin(self) -> Tuple[USBMeta, int]:
        if not self.segments:
            raise RuntimeError("stream has data but no origin segment")
        seg = self.segments[0]
        return seg.meta, seg.offset

    def _segment_count_for(self, count: int) -> int:
        left = count
        used = 0
        for seg in self.segments:
            if left <= 0:
                break
            used += 1
            left -= min(left, seg.remaining)
        return used

    def feed(self, data: bytes, meta: USBMeta) -> Iterator[Tuple[USBMeta, int, int, DumlPacket]]:
        if not data:
            return

        self.buffer.extend(data)
        self.segments.append(_Segment(len(data), meta, 0))

        while self.buffer:
            try:
                magic_off = self.buffer.index(MAGIC)
            except ValueError:
                self._consume(len(self.buffer))
                break

            if magic_off:
                self._consume(magic_off)

            if len(self.buffer) < 4:
                break

            length = self.buffer[1] | ((self.buffer[2] & 0x03) << 8)
            version = self.buffer[2] >> 2

            if (
                version != 1
                or not (MIN_PACKET_LEN <= length <= MAX_PACKET_LEN)
                or crc8(self.buffer[:3]) != self.buffer[3]
            ):
                self._consume(1)
                continue

            if len(self.buffer) < length:
                break

            raw = bytes(self.buffer[:length])
            wire_crc = int.from_bytes(raw[-2:], "little")
            if crc16(raw[:-2]) != wire_crc:
                self._consume(1)
                continue

            origin_meta, origin_offset = self._origin()
            span_count = self._segment_count_for(length)
            packet = parse_duml(raw, verify_crc=False)
            self._consume(length)
            yield origin_meta, origin_offset, span_count, packet


# ---------------------------------------------------------------------------
# CRC + DUML
# ---------------------------------------------------------------------------


def _make_crc8_table(poly: int = CRC8_POLY) -> Tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
        table.append(crc & 0xFF)
    return tuple(table)


def _make_crc16_table(poly: int = CRC16_POLY) -> Tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
        table.append(crc & 0xFFFF)
    return tuple(table)


CRC8_TABLE = _make_crc8_table()
CRC16_TABLE = _make_crc16_table()


def crc8(data: bytes, seed: int = CRC8_SEED) -> int:
    crc = seed & 0xFF
    table = CRC8_TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF]
    return crc


def crc16(data: bytes, seed: int = CRC16_SEED) -> int:
    crc = seed & 0xFFFF
    table = CRC16_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc & 0xFFFF


def hex_to_bytes(value: str) -> bytes:
    compact = "".join(value.split())
    if len(compact) % 2:
        raise DumlError("hex string must contain an even number of characters")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise DumlError(f"invalid hexadecimal input: {exc}") from exc


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def route_id(component_id: int, instance: int) -> str:
    return f"{component_id:02d}{instance:02d}"


def parse_duml(packet: bytes, *, verify_crc: bool = True) -> DumlPacket:
    if not packet:
        raise DumlError("empty packet")
    if packet[0] != MAGIC:
        raise DumlError(f"invalid magic 0x{packet[0]:02X}; expected 0x55")
    if len(packet) < MIN_PACKET_LEN:
        raise DumlError(f"invalid packet length {len(packet)}; minimum is {MIN_PACKET_LEN}")
    if len(packet) > MAX_PACKET_LEN:
        raise DumlError(f"invalid packet length {len(packet)}; maximum is {MAX_PACKET_LEN}")

    length = packet[1] | ((packet[2] & 0x03) << 8)
    version = packet[2] >> 2
    header_crc = packet[3]

    if version != 1:
        raise DumlError(f"unsupported DUML version {version}")
    if length != len(packet):
        raise DumlError(f"defined length does not match actual length: {length} != {len(packet)}")

    expected_header_crc = crc8(packet[:3]) if verify_crc else header_crc
    if verify_crc and header_crc != expected_header_crc:
        raise DumlError(
            f"header CRC8 mismatch: 0x{header_crc:02X} != 0x{expected_header_crc:02X}"
        )

    src_byte = packet[4]
    dst_byte = packet[5]
    source = (src_byte >> 5) & 0x07
    source_id = src_byte & 0x1F
    target = (dst_byte >> 5) & 0x07
    target_id = dst_byte & 0x1F
    sequence = int.from_bytes(packet[6:8], "little")

    cmd_type = packet[8] & 0xE0
    cmd_set = packet[9]
    cmd_id = packet[10]

    packet_crc = int.from_bytes(packet[-2:], "little")
    calculated_crc = crc16(packet[:-2]) if verify_crc else packet_crc
    if verify_crc and packet_crc != calculated_crc:
        raise DumlError(
            f"packet CRC16 mismatch: 0x{packet_crc:04X} != 0x{calculated_crc:04X}"
        )

    return DumlPacket(
        raw=packet,
        length=length,
        version=version,
        header_crc8=header_crc,
        source=source,
        source_id=source_id,
        target=target,
        target_id=target_id,
        sequence=sequence,
        cmd_type=cmd_type,
        cmd_set=cmd_set,
        cmd_id=cmd_id,
        payload=packet[11:-2],
        packet_crc16=packet_crc,
        calculated_crc16=calculated_crc,
    )


def parse_hex_packet(value: str, *, verify_crc: bool = True) -> DumlPacket:
    return parse_duml(hex_to_bytes(value), verify_crc=verify_crc)



@dataclass(frozen=True)
class SemanticInfo:
    name: str
    summary: str = ""
    fields: Tuple[Tuple[str, str], ...] = ()
    confidence: str = "reference"
    category: str = "other"


def _ascii_z(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def _printable_ascii_runs(data: bytes, min_len: int = 4) -> Tuple[str, ...]:
    runs = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append(cur.decode("ascii", errors="replace"))
            cur.clear()
    if len(cur) >= min_len:
        runs.append(cur.decode("ascii", errors="replace"))
    return tuple(runs)


def _version4_le(data: bytes) -> str:
    if len(data) < 4:
        return ""
    return ".".join(str(x) for x in data[:4][::-1])



@dataclass(frozen=True)
class FileTransFrame:
    kind: str
    phase: Optional[int] = None
    total_len: Optional[int] = None
    filename: str = ""
    part_no: Optional[int] = None
    data: bytes = b""
    digest: bytes = b""
    status: Optional[int] = None
    extra: bytes = b""


def classify_filetrans_frame(pkt: DumlPacket) -> FileTransFrame:
    """
    Classify General/0x2A File Transfer.

    Matrice 4T / WA345T framing confirmed by real Assistant captures and the
    hardware-tested kewl-ua/m4_cli_flasher implementation:

      OPEN : 01 | u32 file_size | u8 name_len | name\\0 | 00 01 01
      DATA : 04 | u32 chunk_index | file bytes
      END  : 03 | MD5[16]

    On the M4T the negotiated DATA chunk size is 980 bytes.  The last chunk is
    simply shorter; it MUST NOT be filtered by a minimum payload-size heuristic.

    Replies:
      OPEN reply     : 7 bytes, 00 | u16 chunk_size | u16 value | 01 01
      DATA progress  : 5 bytes, 00 | u32 highest_received_chunk
      END reply      : 1 byte, 00
    """
    if (pkt.cmd_set, pkt.cmd_id) != (0x00, 0x2A):
        return FileTransFrame("not-filetrans")

    p = pkt.payload
    if not p:
        return FileTransFrame("empty")

    # OPEN request.
    if p[0] == 0x01 and len(p) >= 7:
        total_len = int.from_bytes(p[1:5], "little")
        fname_len = p[5]
        end = 6 + fname_len
        if fname_len > 0 and end <= len(p):
            fname_b = p[6:end]
            fname = fname_b.rstrip(b"\x00").decode("utf-8", errors="replace")
            if fname:
                return FileTransFrame(
                    "start",
                    phase=0x01,
                    total_len=total_len,
                    filename=fname,
                    # M4T normally has 00 01 01 here. It is protocol metadata,
                    # not file content.
                    extra=bytes(p[end:]),
                )

    # Exact M4T DATA request. Minimum useful frame is wrapper(5)+1 data byte.
    if p[0] == 0x04 and len(p) > 5:
        return FileTransFrame(
            "data",
            phase=0x04,
            part_no=int.from_bytes(p[1:5], "little"),
            data=bytes(p[5:]),
        )

    # END request.
    if p[0] == 0x03 and len(p) >= 17:
        return FileTransFrame(
            "finish",
            phase=0x03,
            digest=bytes(p[1:17]),
            extra=bytes(p[17:]),
        )

    # M4T OPEN response.
    if len(p) == 7 and p[0] == 0:
        chunk_size = int.from_bytes(p[1:3], "little")
        value = int.from_bytes(p[3:5], "little")
        return FileTransFrame(
            "response-start",
            status=0,
            part_no=chunk_size,
            data=p[3:],
            extra=value.to_bytes(2, "little") + p[5:7],
        )

    # Progress report: highest accepted DATA chunk.
    if len(p) == 5 and p[0] == 0:
        return FileTransFrame(
            "response-data",
            status=0,
            part_no=int.from_bytes(p[1:5], "little"),
        )

    # END response.
    if len(p) == 1:
        return FileTransFrame("response-finish", status=p[0])

    return FileTransFrame("other", status=p[0])


def semantic_decode(pkt: DumlPacket) -> SemanticInfo:
    p = pkt.payload
    name = pkt.command_name
    key = (pkt.cmd_set, pkt.cmd_id)

    if key == (0x00, 0x01):
        if pkt.packet_type == 1 and len(p) >= 30:
            hw = _ascii_z(p[2:18])
            loader = _version4_le(p[18:22])
            app = _version4_le(p[22:26])
            flags = int.from_bytes(p[26:30], "little")
            fields = (
                ("hardware", hw),
                ("loader_version", loader),
                ("app_version", app),
                ("flags", f"0x{flags:08X}"),
            )
            return SemanticInfo(
                name, f"{hw} | app {app}", fields, "reference", "identity"
            )
        rq = f"request_flags=0x{p[0]:02X}" if p else "request"
        return SemanticInfo(name, rq, category="identity")

    if key == (0x00, 0x0C):
        if pkt.packet_type == 1 and len(p) >= 6:
            status = p[0]
            state = int.from_bytes(p[2:6], "little")
            return SemanticInfo(
                name,
                f"status=0x{status:02X} state=0x{state:08X}",
                (("status", f"0x{status:02X}"), ("device_state", f"0x{state:08X}")),
                "reference",
                "state",
            )
        return SemanticInfo(name, "device-state query", category="state")

    if key == (0x00, 0x83):
        return SemanticInfo(
            name,
            f"Upgrade Prepare payload={p.hex().upper() or '<empty>'}",
            (("payload", p.hex().upper()),),
            "M4T hardware-tested",
            "upgrade",
        )

    if key == (0x00, 0x84):
        if len(p) >= 5:
            total = int.from_bytes(p[1:5], "little")
            return SemanticInfo(
                name,
                f"announce total_file_bytes={total}",
                (("total_file_bytes", str(total)), ("raw", p.hex().upper())),
                "M4T hardware-tested",
                "upgrade",
            )
        return SemanticInfo(name, f"payload={p.hex().upper()}", confidence="M4T")

    if key == (0x00, 0x85):
        return SemanticInfo(
            name,
            f"Upgrade Install payload={len(p)}B",
            (("payload", p.hex().upper()),),
            "M4T hardware-tested",
            "upgrade",
        )

    if key == (0x00, 0x41):
        val = p[0] if p else None
        summary = "empty" if val is None else f"control=0x{val:02X}"
        return SemanticInfo(
            name, summary,
            () if val is None else (("control", f"0x{val:02X}"),),
            "reference-name / payload-raw",
            "upgrade",
        )

    if key == (0x00, 0x42) and len(p) >= 1:
        state = p[0]
        state_name = UPGRADE_STATES.get(state, f"Unknown({state})")
        fields = [("state", f"{state} ({state_name})")]
        summary = state_name

        if state == 2 and len(p) >= 3:
            fields += [("user_time", str(p[1])), ("user_reserve", f"0x{p[2]:02X}")]
            summary += f" user_time={p[1]}"
        elif state == 3 and len(p) >= 3:
            progress = p[1]
            module_count = p[2]
            fields += [
                ("progress", f"{progress}%"),
                ("module_count", str(module_count)),
            ]
            if len(p) == 3 + 8 * module_count:
                modules = []
                for i in range(module_count):
                    entry = p[3 + 8*i: 11 + 8*i]
                    modules.append(
                        f"0x{entry[0]:02X}:state={entry[6]},progress={entry[7]}%"
                    )
                if modules:
                    fields.append(("modules", "; ".join(modules)))
            elif len(p) > 3:
                fields.append(("extension_bytes", str(len(p) - 3)))
            summary += f" {progress}% modules={module_count}"
        elif state == 4 and len(p) >= 3:
            result = p[1]
            result_name = UPGRADE_RESULTS.get(result, f"Unknown({result})")
            module_count = p[2]
            fields += [
                ("result", f"{result} ({result_name})"),
                ("module_count", str(module_count)),
            ]
            if len(p) == 3 + 8 * module_count and module_count:
                modules = []
                for i in range(module_count):
                    entry = p[3 + 8*i: 11 + 8*i]
                    modules.append(
                        f"0x{entry[0]:02X}:state={entry[6]},progress={entry[7]}%"
                    )
                fields.append(("modules", "; ".join(modules)))
            elif len(p) > 3:
                fields.append(("extension_bytes", str(len(p) - 3)))
            summary += f" result={result_name}"
        return SemanticInfo(name, summary, tuple(fields), "reference", "upgrade")

    if key == (0x00, 0x2A):
        ft = classify_filetrans_frame(pkt)

        if ft.kind == "start":
            return SemanticInfo(
                name,
                f"phase=START size={ft.total_len} file={ft.filename!r}",
                (
                    ("phase", "1 (START)"),
                    ("total_len", str(ft.total_len)),
                    ("filename", ft.filename),
                ),
                "reference / structural",
                "file-transfer",
            )

        if ft.kind == "data":
            return SemanticInfo(
                name,
                f"sub=0x04 DATA chunk={ft.part_no} data={len(ft.data)}B",
                (
                    ("subcommand", "0x04 (DATA)"),
                    ("part_no", str(ft.part_no)),
                    ("data_len", str(len(ft.data))),
                ),
                "reference / structural",
                "file-transfer",
            )

        if ft.kind == "finish":
            digest = ft.digest.hex()
            return SemanticInfo(
                name,
                f"phase=FINISH digest={digest}",
                (("phase", "3 (FINISH)"), ("digest16", digest)),
                "reference / structural / digest-role-probable-md5",
                "file-transfer",
            )

        if ft.kind == "response-start":
            return SemanticInfo(
                name,
                f"OPEN reply status=0x{ft.status:02X} chunk_size={ft.part_no}",
                (("reply", "OPEN"), ("status", f"0x{ft.status:02X}"), ("chunk_size", str(ft.part_no))),
                "reference",
                "file-transfer",
            )

        if ft.kind == "response-data":
            return SemanticInfo(
                name,
                f"progress status=0x{ft.status:02X} highest_chunk={ft.part_no}",
                (
                    ("reply", "DATA progress"),
                    ("status", f"0x{ft.status:02X}"),
                    ("part_no", str(ft.part_no)),
                ),
                "reference",
                "file-transfer",
            )

        if ft.kind == "response-finish":
            return SemanticInfo(
                name,
                f"END reply status=0x{ft.status:02X}",
                (("reply", "END"), ("status", f"0x{ft.status:02X}")),
                "reference",
                "file-transfer",
            )

        return SemanticInfo(
            name,
            f"unclassified FileTrans payload={len(p)}B first=0x{p[0]:02X}",
            (("payload_len", str(len(p))), ("first_byte", f"0x{p[0]:02X}")),
            "unknown-layout",
            "file-transfer",
        )

    if key == (0x00, 0x4F):
        if pkt.packet_type == 0 and len(p) >= 9:
            op = p[0]
            offset = int.from_bytes(p[1:5], "little")
            max_len = int.from_bytes(p[5:9], "little")
            return SemanticInfo(
                name,
                f"op={op} offset={offset} max={max_len}",
                (("op", str(op)), ("offset", str(offset)), ("max_len", str(max_len))),
                "recent-RE",
                "file/config",
            )
        if pkt.packet_type == 1 and len(p) >= 9:
            status = p[0]
            chunk_len = int.from_bytes(p[1:5], "little")
            remaining = int.from_bytes(p[5:9], "little")
            data = p[9:9 + chunk_len]
            fields = [
                ("status", f"0x{status:02X}"),
                ("chunk_len", str(chunk_len)),
                ("remaining", str(remaining)),
            ]
            if data:
                fields.append(("data", data.hex().upper()))
            return SemanticInfo(
                name,
                f"status={status} chunk={chunk_len} remaining={remaining}",
                tuple(fields),
                "recent-RE",
                "file/config",
            )

    if key == (0x00, 0x51):
        runs = _printable_ascii_runs(p)
        fields = tuple((f"ascii_{i}", s) for i, s in enumerate(runs))
        summary = " | ".join(runs) if runs else (f"payload={p.hex().upper()}" if p else "empty")
        return SemanticInfo(name, summary, fields, "reference-name / observed-payload", "identity")

    if key == (0x00, 0x81):
        product = _ascii_z(p)
        if product and all(0x20 <= ord(c) <= 0x7E for c in product):
            return SemanticInfo(
                name,
                f"product={product}",
                (("product", product),),
                "modern-RE / observed",
                "handshake",
            )
        return SemanticInfo(name, f"{len(p)} bytes", confidence="modern-RE", category="handshake")

    if key == (0x00, 0x82):
        product = _ascii_z(p)
        fields = ()
        summary = f"{len(p)} bytes"
        if product and all(0x20 <= ord(c) <= 0x7E for c in product):
            fields = (("product", product),)
            summary = f"product={product}"
        elif len(p) == 1:
            summary = f"status=0x{p[0]:02X}"
            fields = (("status", f"0x{p[0]:02X}"),)
        return SemanticInfo(name, summary, fields, "modern-RE / observed", "handshake")

    if key == (0x00, 0xF1):
        if len(p) >= 4:
            state = int.from_bytes(p[:4], "little")
            fields = [("current_state", f"0x{state:08X}")]
            if len(p) > 4:
                fields.append(("extra", p[4:].hex().upper()))
            return SemanticInfo(
                name, f"state=0x{state:08X}", tuple(fields), "reference", "telemetry"
            )
        return SemanticInfo(name, f"{len(p)} bytes", category="telemetry")

    if key == (0x03, 0x43):
        return SemanticInfo(name, f"{len(p)}-byte FC OSD telemetry", category="telemetry")

    if key == (0x03, 0xCE):
        return SemanticInfo(name, f"{len(p)}-byte no-fly/DB info push", category="telemetry")

    if key == (0x04, 0x05):
        fields = []
        summary = f"{len(p)}-byte gimbal state"
        if len(p) >= 24:
            seq_ctr = p[12]
            pitch_raw = int.from_bytes(p[20:22], "little", signed=True)
            roll_raw = int.from_bytes(p[22:24], "little", signed=True)
            fields = [
                ("state_seq", str(seq_ctr)),
                ("pitch_deg", f"{pitch_raw / 10.0:.1f}"),
                ("roll_deg", f"{roll_raw / 10.0:.1f}"),
            ]
            summary += f" pitch={pitch_raw/10.0:.1f}° roll={roll_raw/10.0:.1f}°"
        return SemanticInfo(name, summary, tuple(fields), "modern-RE", "telemetry")

    if name != "Unknown":
        runs = _printable_ascii_runs(p)
        summary = f"{len(p)} bytes"
        fields = ()
        if runs:
            fields = tuple((f"ascii_{i}", s) for i, s in enumerate(runs))
            summary += " | " + " | ".join(runs[:3])
        return SemanticInfo(name, summary, fields, "reference-name", "other")

    return SemanticInfo(
        f"Unknown 0x{pkt.cmd_set:02X}/0x{pkt.cmd_id:02X}",
        f"{len(p)} bytes",
        confidence="unknown",
        category="unknown",
    )


def upgrade_event_key(pkt: DumlPacket):
    if (pkt.cmd_set, pkt.cmd_id) != (0x00, 0x42) or not pkt.payload:
        return None
    p = pkt.payload
    state = p[0]
    if state == 3 and len(p) >= 2:
        return ("upgrading", p[1])
    if state == 4 and len(p) >= 2:
        return ("complete", p[1])
    if state == 2 and len(p) >= 2:
        return ("userconfirm", p[1])
    return ("state", state)


def build_upgrade_state_machine(items: Iterable[CapturedDuml], base_timestamp: Optional[float] = None) -> str:
    items = list(items)
    if not items:
        return "=== Upgrade state machine ===\nNo DUML packets."

    base = items[0].usb.timestamp if base_timestamp is None else base_timestamp
    status_items = [
        x for x in items
        if (x.packet.cmd_set, x.packet.cmd_id) == (0x00, 0x42)
        and x.packet.payload
    ]

    lines = ["=== Upgrade state machine ==="]
    if not status_items:
        lines.append("No General/0x42 FW Upgrade Push Status packets found.")
        return "\n".join(lines)

    first = status_items[0]
    first_sem = semantic_decode(first.packet)
    if first.packet.payload[0] == 3 and len(first.packet.payload) >= 2:
        first_progress = first.packet.payload[1]
        if first_progress == 0:
            lines.append(
                f"Upgrade phase begins at 0% at +{first.usb.timestamp-base:.3f}s."
            )
        else:
            lines.append(
                f"Capture begins mid-upgrade: first status is "
                f"{first_progress}% at +{first.usb.timestamp-base:.3f}s."
            )

    last_key = None
    for item in status_items:
        key = upgrade_event_key(item.packet)
        if key == last_key:
            continue
        last_key = key
        p = item.packet.payload
        t = item.usb.timestamp - base
        if p[0] == 3 and len(p) >= 3:
            module_count = p[2]
            long_ok = len(p) == 3 + 8 * module_count
            lines.append(
                f"+{t:8.3f}s  UPGRADING  {p[1]:3d}%  "
                f"modules={module_count}  payload={len(p)}B"
                + ("" if long_ok else " [nonstandard length]")
            )
        elif p[0] == 4 and len(p) >= 3:
            result = UPGRADE_RESULTS.get(p[1], f"Unknown({p[1]})")
            lines.append(
                f"+{t:8.3f}s  COMPLETE   result={result} "
                f"modules={p[2]} payload={len(p)}B"
            )
        else:
            lines.append(f"+{t:8.3f}s  {semantic_decode(item.packet).summary}")

    # Post-completion control/config operations.
    complete_ts = None
    for item in status_items:
        p = item.packet.payload
        if p and p[0] == 4:
            complete_ts = item.usb.timestamp
            break

    if complete_ts is not None:
        lines.append("")
        lines.append("Post-completion control traffic:")
        for item in items:
            if item.usb.timestamp < complete_ts:
                continue
            p = item.packet
            if p.cmd_set == 0 and p.cmd_id in (0x41, 0x4F, 0x51, 0x01, 0x0C):
                sem = semantic_decode(p)
                t = item.usb.timestamp - base
                lines.append(
                    f"+{t:8.3f}s  {p.packet_type_name:<8} "
                    f"{p.source_name} -> {p.target_name}  "
                    f"0x{p.cmd_set:02X}/0x{p.cmd_id:02X} {sem.name}: {sem.summary}"
                )

    # First-seen version identities, useful for spotting a reboot/firmware change.
    seen = set()
    versions = []
    for item in items:
        p = item.packet
        if (p.cmd_set, p.cmd_id) != (0, 1) or p.packet_type != 1:
            continue
        sem = semantic_decode(p)
        if not sem.fields:
            continue
        fd = dict(sem.fields)
        ident = (p.source_id, fd.get("hardware"), fd.get("loader_version"), fd.get("app_version"))
        if ident in seen:
            continue
        seen.add(ident)
        versions.append((item.usb.timestamp - base, p.source_name, ident[1], ident[2], ident[3]))

    if versions:
        lines.append("")
        lines.append("First-seen version identities:")
        for t, src, hw, loader, app in versions:
            lines.append(
                f"+{t:8.3f}s  {src:<20} hw={hw!r} loader={loader} app={app}"
            )

    return "\n".join(lines)



@dataclass
class FileTransferSession:
    index: int
    route: Tuple[int, int, int, int]
    source_name: str
    target_name: str
    filename: str
    declared_size: int
    start_time: float
    end_time: Optional[float] = None
    chunks: Dict[int, bytes] = None
    duplicate_parts: int = 0
    conflicting_parts: int = 0
    finish_digest: Optional[bytes] = None

    def __post_init__(self) -> None:
        if self.chunks is None:
            self.chunks = {}

    @property
    def sorted_parts(self) -> Tuple[int, ...]:
        return tuple(sorted(self.chunks))

    @property
    def missing_parts(self) -> Tuple[int, ...]:
        parts = self.sorted_parts
        if not parts:
            return ()
        # Most captures use sequential part numbers. Avoid pathological memory
        # use if a product uses byte offsets or sparse numbering instead.
        span = parts[-1] - parts[0] + 1
        if span > max(1_000_000, len(parts) * 16):
            return ()
        return tuple(i for i in range(parts[0], parts[-1] + 1) if i not in self.chunks)

    @property
    def assembled(self) -> bytes:
        return b"".join(self.chunks[i] for i in self.sorted_parts)

    @property
    def md5(self) -> bytes:
        return hashlib.md5(self.assembled).digest()

    @property
    def md5_matches_finish(self) -> Optional[bool]:
        if self.finish_digest is None:
            return None
        return self.md5 == self.finish_digest


def _reverse_route(route: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    src_id, src_inst, dst_id, dst_inst = route
    return (dst_id, dst_inst, src_id, src_inst)


def _find_active_transfer(
    active: Dict[Tuple[int, int, int, int], FileTransferSession],
    route: Tuple[int, int, int, int],
) -> Optional[FileTransferSession]:
    sess = active.get(route)
    if sess is not None:
        return sess

    sess = active.get(_reverse_route(route))
    if sess is not None:
        return sess

    # Firmware transfers observed so far are sequential.  If there is exactly
    # one active transfer, using it is safer than discarding a structurally
    # valid DATA frame because a product changed route/instance flags.
    unique = {id(v): v for v in active.values()}
    if len(unique) == 1:
        return next(iter(unique.values()))

    return None


def _remove_active_session(
    active: Dict[Tuple[int, int, int, int], FileTransferSession],
    sess: FileTransferSession,
) -> None:
    for key in [k for k, v in active.items() if v is sess]:
        active.pop(key, None)


def reconstruct_file_transfers(items: Iterable[CapturedDuml]) -> Tuple[FileTransferSession, ...]:
    active: Dict[Tuple[int, int, int, int], FileTransferSession] = {}
    sessions = []

    for item in items:
        pkt = item.packet
        if (pkt.cmd_set, pkt.cmd_id) != (0x00, 0x2A):
            continue

        ft = classify_filetrans_frame(pkt)
        if ft.kind not in {"start", "data", "finish"}:
            continue

        route = (pkt.source_id, pkt.source, pkt.target_id, pkt.target)

        if ft.kind == "start":
            sess = FileTransferSession(
                index=len(sessions) + 1,
                route=route,
                source_name=pkt.source_name,
                target_name=pkt.target_name,
                filename=ft.filename,
                declared_size=int(ft.total_len or 0),
                start_time=item.usb.timestamp,
            )
            sessions.append(sess)
            active[route] = sess
            continue

        sess = _find_active_transfer(active, route)
        if sess is None:
            # Capture may begin in the middle of a transfer.
            sess = FileTransferSession(
                index=len(sessions) + 1,
                route=route,
                source_name=pkt.source_name,
                target_name=pkt.target_name,
                filename=f"partial_transfer_{len(sessions)+1}.bin",
                declared_size=-1,
                start_time=item.usb.timestamp,
            )
            sessions.append(sess)
            active[route] = sess

        if ft.kind == "data":
            part_no = int(ft.part_no or 0)
            data = ft.data
            if part_no in sess.chunks:
                if sess.chunks[part_no] == data:
                    sess.duplicate_parts += 1
                else:
                    sess.conflicting_parts += 1
            else:
                sess.chunks[part_no] = data
            sess.end_time = item.usb.timestamp

        elif ft.kind == "finish":
            sess.finish_digest = ft.digest
            sess.end_time = item.usb.timestamp
            _remove_active_session(active, sess)

    return tuple(sessions)


def _safe_transfer_filename(name: str, fallback: str) -> str:
    base = Path(name.replace("\\", "/")).name.replace("\x00", "").strip()
    if not base or base in {".", ".."}:
        base = fallback
    safe = "".join(c if c.isalnum() or c in "._-+()[] " else "_" for c in base)
    return safe or fallback


def build_filetrans_report(items: Iterable[CapturedDuml]) -> str:
    sessions = reconstruct_file_transfers(items)
    lines = ["=== FileTrans General Trans (0x00/0x2A) ==="]
    if not sessions:
        lines.append("No request-side 0x2A file-transfer sessions found.")
        return "\n".join(lines)

    ft_packets = [
        x.packet for x in items
        if (x.packet.cmd_set, x.packet.cmd_id) == (0x00, 0x2A)
    ]
    census = Counter(classify_filetrans_frame(p).kind for p in ft_packets)
    over_511 = sum(1 for p in ft_packets if len(p.raw) > 0x01FF)
    lines.append(
        "Packet census: "
        + ", ".join(f"{k}={v}" for k, v in census.most_common())
        + f"; >511B={over_511}"
    )

    for sess in sessions:
        data = sess.assembled
        parts = sess.sorted_parts
        miss = sess.missing_parts
        declared = "unknown" if sess.declared_size < 0 else str(sess.declared_size)
        size_ok = None if sess.declared_size < 0 else (len(data) == sess.declared_size)
        md5_status = sess.md5_matches_finish
        duration = None if sess.end_time is None else sess.end_time - sess.start_time

        lines.append("")
        lines.append(
            f"Transfer #{sess.index}: {sess.source_name} -> {sess.target_name}  "
            f"file={sess.filename!r}"
        )
        lines.append(
            f"  declared_size={declared} assembled_size={len(data)} "
            f"size_match={size_ok}"
        )
        if parts:
            lines.append(
                f"  parts={len(parts)} range={parts[0]}..{parts[-1]} "
                f"missing={len(miss)} duplicates={sess.duplicate_parts} "
                f"conflicts={sess.conflicting_parts}"
            )
            if miss and len(miss) <= 32:
                lines.append("  missing_parts=" + ",".join(map(str, miss)))
        else:
            lines.append("  parts=0")
        if duration is not None:
            lines.append(f"  duration={duration:.3f}s")
        lines.append(f"  md5(assembled)={sess.md5.hex()}")
        if sess.finish_digest is not None:
            lines.append(
                f"  finish_digest16={sess.finish_digest.hex()} "
                f"md5_match={md5_status}"
            )

    return "\n".join(lines)


def extract_transferred_files(items: Iterable[CapturedDuml], out_dir: Path) -> Tuple[Path, ...]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    used = set()

    for sess in reconstruct_file_transfers(items):
        if not sess.chunks:
            continue
        fallback = f"transfer_{sess.index:03d}.bin"
        name = _safe_transfer_filename(sess.filename, fallback)
        candidate = name
        stem = Path(name).stem
        suffix = Path(name).suffix
        n = 2
        while candidate.lower() in used or (out_dir / candidate).exists():
            candidate = f"{stem}_{n}{suffix}"
            n += 1
        used.add(candidate.lower())

        data = sess.assembled
        path = out_dir / candidate
        path.write_bytes(data)
        written.append(path)

        meta = path.with_name(path.name + ".duml.txt")
        parts = sess.sorted_parts
        miss = sess.missing_parts
        size_ok = None if sess.declared_size < 0 else (len(data) == sess.declared_size)
        meta.write_text(
            "\n".join([
                f"source={sess.source_name}",
                f"target={sess.target_name}",
                f"original_filename={sess.filename}",
                f"declared_size={sess.declared_size}",
                f"assembled_size={len(data)}",
                f"size_match={size_ok}",
                f"parts={len(parts)}",
                f"part_range={(str(parts[0]) + '..' + str(parts[-1])) if parts else ''}",
                f"missing_parts={','.join(map(str, miss))}",
                f"duplicate_parts={sess.duplicate_parts}",
                f"conflicting_parts={sess.conflicting_parts}",
                f"md5={sess.md5.hex()}",
                f"finish_digest16={sess.finish_digest.hex() if sess.finish_digest else ''}",
                f"finish_digest_matches_md5={sess.md5_matches_finish}",
            ]) + "\n",
            encoding="utf-8",
        )

    return tuple(written)


def write_filetrans_report(path: Path, items: Iterable[CapturedDuml]) -> None:
    path.write_text(build_filetrans_report(items) + "\n", encoding="utf-8")


def is_interesting_packet(pkt: DumlPacket) -> bool:
    sem = semantic_decode(pkt)
    return sem.category not in {"telemetry", "handshake"}


def write_semantic_report(path: Path, items: Iterable[CapturedDuml]) -> None:
    items = list(items)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(build_upgrade_state_machine(items))
        fh.write("\n\n")
        fh.write(build_filetrans_report(items))
        fh.write("\n\n=== Semantic command inventory ===\n")
        counts = Counter(
            (x.packet.cmd_set, x.packet.cmd_id, semantic_decode(x.packet).name)
            for x in items
        )
        for (cmdset, cmdid, name), count in counts.most_common():
            fh.write(f"{count:6d}  0x{cmdset:02X}/0x{cmdid:02X}  {name}\n")


def format_packet(pkt: DumlPacket) -> str:
    sem = semantic_decode(pkt)
    lines = [
        f"Packet:\t\t{bytes_to_hex(pkt.raw)}",
        f"CRC16:\t\t0x{pkt.packet_crc16:04X}",
        "",
        f"Header:\t\t{bytes_to_hex(pkt.raw[:4])}",
        f"Length:\t\t{pkt.length}",
        f"Version:\t{pkt.version}",
        f"CRC8:\t\t0x{pkt.header_crc8:02X}",
        "",
        f"Transit:\t{bytes_to_hex(pkt.raw[4:8])}",
        f"Route:\t\t{pkt.source_route} -> {pkt.target_route}",
        f"Source:\t\t{pkt.source}",
        f"Source ID:\t{pkt.source_id}\t\t{pkt.source_name}",
        f"Target:\t\t{pkt.target}",
        f"Target ID:\t{pkt.target_id}\t\t{pkt.target_name}",
        f"Sequence:\t{pkt.sequence}",
        "",
        f"Command:\t{bytes_to_hex(pkt.raw[8:11])}",
        f"Raw type:\t0x{pkt.raw[8]:02X}",
        f"Packet type:\t{pkt.packet_type}\t\t{pkt.packet_type_name}",
        f"ACK policy:\t{pkt.ack_type}\t\t{pkt.ack_type_name}",
        f"Encryption:\t{pkt.encrypt_type}\t\t{pkt.encrypt_type_name}",
        f"cmdSet:\t\t0x{pkt.cmd_set:02X}\t\t{pkt.cmd_set_name}",
        f"cmdID:\t\t0x{pkt.cmd_id:02X}\t\t{sem.name}",
    ]
    if pkt.payload:
        lines.extend([
            "",
            f"Payload:\t{bytes_to_hex(pkt.payload)}",
            f"Length:\t\t{len(pkt.payload)}",
        ])
    lines.extend([
        "",
        f"Semantic:\t{sem.summary or sem.name}",
        f"Confidence:\t{sem.confidence}",
    ])
    for key, value in sem.fields:
        lines.append(f"  {key}:\t{value}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PCAP / USBPcap
# ---------------------------------------------------------------------------


def read_pcap(path: Path) -> Iterator[Tuple[int, float, bytes]]:
    with path.open("rb") as fh:
        gh = fh.read(24)
        if len(gh) != 24:
            raise PcapError("file is too short for a classic pcap global header")

        magic = gh[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
        }
        if magic not in formats:
            if magic == b"\x0a\x0d\x0d\x0a":
                raise PcapError("pcapng is not supported; save/export as classic pcap (USBPcap)")
            raise PcapError(f"unsupported pcap magic {magic.hex()}")

        endian, fraction_divisor = formats[magic]
        linktype = struct.unpack_from(endian + "I", gh, 20)[0]
        if linktype != USBPCAP_LINKTYPE:
            raise PcapError(
                f"expected USBPcap linktype {USBPCAP_LINKTYPE}, got {linktype}"
            )

        record = 0
        while True:
            rh = fh.read(16)
            if not rh:
                break
            if len(rh) != 16:
                raise PcapError("truncated pcap record header")
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", rh)
            blob = fh.read(incl_len)
            if len(blob) != incl_len:
                raise PcapError(f"truncated pcap record #{record}")
            yield record, ts_sec + ts_frac / fraction_divisor, blob
            record += 1


def parse_usbpcap_record(record: int, timestamp: float, blob: bytes) -> Optional[Tuple[USBMeta, bytes]]:
    if len(blob) < USBPCAP_BASE_HEADER_LEN:
        return None

    header_len = struct.unpack_from("<H", blob, 0)[0]
    if header_len < USBPCAP_BASE_HEADER_LEN or header_len > len(blob):
        return None

    info = blob[16]
    bus = struct.unpack_from("<H", blob, 17)[0]
    device = struct.unpack_from("<H", blob, 19)[0]
    endpoint = blob[21]
    transfer = blob[22]
    declared_data_len = struct.unpack_from("<I", blob, 23)[0]

    available = len(blob) - header_len
    # USBPcap normally makes these equal. Clamp defensively for truncated/snaplen captures.
    captured_len = min(declared_data_len, available)
    data = blob[header_len : header_len + captured_len]

    meta = USBMeta(
        pcap_record=record,
        timestamp=timestamp,
        bus=bus,
        device=device,
        endpoint=endpoint,
        info=info,
        transfer=transfer,
        declared_data_len=declared_data_len,
        captured_data_len=captured_len,
    )
    return meta, data


def extract_pcap(path: Path) -> Iterator[CapturedDuml]:
    decoders: Dict[Tuple[int, int, int], DumlStreamDecoder] = defaultdict(DumlStreamDecoder)
    index = 0

    for record, timestamp, blob in read_pcap(path):
        parsed = parse_usbpcap_record(record, timestamp, blob)
        if parsed is None:
            continue
        meta, data = parsed
        if not data:
            continue

        key = (meta.bus, meta.device, meta.endpoint)
        decoder = decoders[key]
        for origin, usb_offset, span_count, packet in decoder.feed(data, meta):
            index += 1
            yield CapturedDuml(
                index=index,
                usb=origin,
                usb_offset=usb_offset,
                spanned_urbs=span_count,
                packet=packet,
            )


def iso_timestamp(timestamp: float) -> str:
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()


def captured_row(item: CapturedDuml) -> dict:
    p = item.packet
    u = item.usb
    return {
        "index": item.index,
        "pcap_record": u.pcap_record,
        "timestamp_unix": f"{u.timestamp:.6f}",
        "timestamp_utc": iso_timestamp(u.timestamp),
        "usb_bus": u.bus,
        "usb_device": u.device,
        "endpoint": f"0x{u.endpoint:02X}",
        "direction": u.direction,
        "usb_info": u.info,
        "usb_transfer": u.transfer,
        "usb_transfer_name": u.transfer_name,
        "usb_data_len": u.declared_data_len,
        "usb_captured_len": u.captured_data_len,
        "usb_offset": item.usb_offset,
        "spanned_urbs": item.spanned_urbs,
        "packet_len": p.length,
        "src_instance": p.source,
        "src_id": p.source_id,
        "src_name": p.source_name,
        "target_instance": p.target,
        "target_id": p.target_id,
        "target_name": p.target_name,
        "sequence": p.sequence,
        "cmd_type": f"0x{p.cmd_type:02X}",
        "cmd_type_name": p.cmd_type_name,
        "cmd_set": f"0x{p.cmd_set:02X}",
        "cmd_set_name": p.cmd_set_name,
        "cmd_id": f"0x{p.cmd_id:02X}",
        "command_name": p.command_name,
        "packet_type": p.packet_type_name,
        "ack_policy": p.ack_type_name,
        "encryption": p.encrypt_type_name,
        "semantic_summary": semantic_decode(p).summary,
        "semantic_confidence": semantic_decode(p).confidence,
        "payload_len": len(p.payload),
        "payload_hex": bytes_to_hex(p.payload),
        "crc16": f"0x{p.packet_crc16:04X}",
        "packet_hex": bytes_to_hex(p.raw),
    }


def captured_row_stream(item: CapturedDuml, *, full_hex: bool = False) -> dict:
    row = captured_row(item)
    ft = classify_filetrans_frame(item.packet)
    if not full_hex and ft.kind == "data":
        row["payload_hex"] = f"<omitted FileTrans DATA: {len(item.packet.payload)} bytes>"
        row["packet_hex"] = f"<omitted DUML frame: {len(item.packet.raw)} bytes>"
    return row



def format_captured(item: CapturedDuml, base_ts: Optional[float] = None) -> str:
    u = item.usb
    rel = ""
    if base_ts is not None:
        rel = f" | +{u.timestamp - base_ts:.6f}s"
    title = (
        f"=== DUML #{item.index} | pcap #{u.pcap_record}{rel} | "
        f"USB {u.bus}:{u.device} EP 0x{u.endpoint:02X} {u.direction} | "
        f"{u.transfer_name} | URBs {item.spanned_urbs} ==="
    )
    return title + "\n" + format_packet(item.packet)


def print_summary(items: Iterable[CapturedDuml], out: TextIO = sys.stdout) -> None:
    items = list(items)
    print("\n=== Summary ===", file=out)
    print(f"Valid DUML packets: {len(items)}", file=out)
    if not items:
        return

    in_count = sum(1 for x in items if x.usb.direction == "IN")
    out_count = len(items) - in_count
    spanning = sum(1 for x in items if x.spanned_urbs > 1)
    print(f"USB direction: IN={in_count}, OUT={out_count}", file=out)
    print(f"Frames spanning >1 URB: {spanning}", file=out)

    cmdsets = Counter(x.packet.cmd_set_name for x in items)
    print("Command sets:", file=out)
    for name, count in cmdsets.most_common():
        print(f"  {count:6d}  {name}", file=out)

    commands = Counter(
        (x.packet.cmd_set_name, x.packet.cmd_id, x.packet.command_name)
        for x in items
    )
    print("Top commands:", file=out)
    for (cmdset, cmdid, cmdname), count in commands.most_common(12):
        print(f"  {count:6d}  {cmdset:<20} 0x{cmdid:02X}  {cmdname}", file=out)

    routes = Counter(
        (x.packet.source_name, x.packet.target_name)
        for x in items
    )
    print("Top routes:", file=out)
    for (src, dst), count in routes.most_common(10):
        print(f"  {count:6d}  {src} -> {dst}", file=out)


def write_csv(path: Path, items: Iterable[CapturedDuml]) -> None:
    rows = [captured_row(x) for x in items]
    with path.open("w", newline="", encoding="utf-8") as fh:
        if not rows:
            return
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_hex(path: Path, items: Iterable[CapturedDuml]) -> None:
    with path.open("w", encoding="ascii", newline="\n") as fh:
        for item in items:
            fh.write(bytes_to_hex(item.packet.raw) + "\n")


def write_report(path: Path, items: Iterable[CapturedDuml], base_ts: Optional[float]) -> None:
    items = list(items)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for i, item in enumerate(items):
            if i:
                fh.write("\n\n")
            fh.write(format_captured(item, base_ts))
        print_summary(items, out=fh)


# ---------------------------------------------------------------------------
# Streaming PCAP pipeline (v5)
# ---------------------------------------------------------------------------

@dataclass
class StreamStats:
    total: int = 0
    in_count: int = 0
    out_count: int = 0
    spanning: int = 0
    cmdsets: Counter = None
    commands: Counter = None
    routes: Counter = None

    def __post_init__(self) -> None:
        self.cmdsets = Counter()
        self.commands = Counter()
        self.routes = Counter()

    def add(self, item: CapturedDuml) -> None:
        p = item.packet
        self.total += 1
        if item.usb.direction == "IN":
            self.in_count += 1
        else:
            self.out_count += 1
        if item.spanned_urbs > 1:
            self.spanning += 1
        self.cmdsets[p.cmd_set_name] += 1
        self.commands[(p.cmd_set_name, p.cmd_id, p.command_name)] += 1
        self.routes[(p.source_name, p.target_name)] += 1


def print_stream_summary(stats: StreamStats, out: TextIO = sys.stdout) -> None:
    print("\n=== Summary ===", file=out)
    print(f"Valid DUML packets: {stats.total}", file=out)
    if not stats.total:
        return
    print(f"USB direction: IN={stats.in_count}, OUT={stats.out_count}", file=out)
    print(f"Frames spanning >1 URB: {stats.spanning}", file=out)
    print("Command sets:", file=out)
    for name, count in stats.cmdsets.most_common():
        print(f"  {count:8d}  {name}", file=out)
    print("Top commands:", file=out)
    for (cmdset, cmdid, cmdname), count in stats.commands.most_common(12):
        print(f"  {count:8d}  {cmdset:<20} 0x{cmdid:02X}  {cmdname}", file=out)
    print("Top routes:", file=out)
    for (src_name, dst_name), count in stats.routes.most_common(10):
        print(f"  {count:8d}  {src_name} -> {dst_name}", file=out)


@dataclass
class SpoolChunk:
    offset: int
    length: int
    digest: bytes
    ordinal: int = 0


@dataclass
class SpoolTransferSession:
    index: int
    route: Tuple[int, int, int, int]
    source_name: str
    target_name: str
    filename: str
    declared_size: int
    start_time: float
    spool_path: Path
    end_time: Optional[float] = None

    # Legacy FileTrans phase=2 path.
    chunks: Dict[int, SpoolChunk] = None
    duplicate_parts: int = 0
    conflicting_parts: int = 0

    finish_digest: Optional[bytes] = None
    start_extra: bytes = b""
    finish_extra: bytes = b""
    assembled_size: int = 0
    assembled_md5: bytes = b""
    output_path: Optional[Path] = None

    # Modern/WA345T bulk path: large 0x2A frames whose payload does not start
    # with the legacy phase=2 byte.
    candidate_chunks: list = None
    candidate_payload_bytes: int = 0
    candidate_prefix_samples: list = None

    inferred_header: Optional[int] = None
    inferred_trailer: Optional[int] = None
    inferred_layout: str = ""
    inference_note: str = ""
    finalized: bool = False

    def __post_init__(self) -> None:
        if self.chunks is None:
            self.chunks = {}
        if self.candidate_chunks is None:
            self.candidate_chunks = []
        if self.candidate_prefix_samples is None:
            self.candidate_prefix_samples = []

    @property
    def sorted_parts(self) -> Tuple[int, ...]:
        return tuple(sorted(self.chunks))

    @property
    def candidate_count(self) -> int:
        return len(self.candidate_chunks)

    @property
    def missing_count(self) -> Optional[int]:
        parts = self.sorted_parts
        if not parts:
            return 0
        span = parts[-1] - parts[0] + 1
        if span > max(1_000_000, len(parts) * 16):
            return None
        return span - len(parts)

    @property
    def size_match(self) -> Optional[bool]:
        if self.declared_size < 0 or not self.finalized:
            return None
        return self.assembled_size == self.declared_size

    @property
    def md5_match(self) -> Optional[bool]:
        if self.finish_digest is None or not self.assembled_md5:
            return None
        return self.assembled_md5 == self.finish_digest


def _monotonic_u32_score(samples, byte_offset: int, endian: str = "little"):
    vals = []
    for sample in samples:
        if len(sample) < byte_offset + 4:
            continue
        vals.append(int.from_bytes(sample[byte_offset:byte_offset + 4], endian))
    if len(vals) < 3:
        return (0.0, None, None, None)

    deltas = [((b - a) & 0xFFFFFFFF) for a, b in zip(vals, vals[1:])]
    if not deltas:
        return (0.0, None, vals[0], vals[-1])

    step, count = Counter(deltas).most_common(1)[0]
    return (count / len(deltas), step, vals[0], vals[-1])


def infer_candidate_filetrans_layout(sess: SpoolTransferSession) -> dict:
    """
    Infer a constant per-frame wrapper around modern FileTrans DATA.

    Exact file size gives:
        sum(payload_len) - N*(header+trailer) == declared_size

    Prefix samples then tell us whether a u32 counter/offset is likely inside
    the header.  The final 16-byte transfer digest is used as an independent
    MD5 check when possible.
    """
    n = sess.candidate_count
    total = sess.candidate_payload_bytes
    declared = sess.declared_size

    info = {
        "candidate_count": n,
        "candidate_payload_bytes": total,
        "declared_size": declared,
        "overhead_total": None,
        "strip_per_frame": None,
        "size_candidates": [],
        "prefix_scores": [],
    }

    if n <= 0 or declared < 0:
        return info

    overhead = total - declared
    info["overhead_total"] = overhead

    if overhead >= 0 and overhead % n == 0:
        strip = overhead // n
        info["strip_per_frame"] = strip
        if 0 <= strip <= 64:
            info["size_candidates"] = [
                (header, strip - header)
                for header in range(strip + 1)
            ]

    samples = sess.candidate_prefix_samples[:256]
    for off in range(0, 13):
        for endian in ("little", "big"):
            score, step, first, last = _monotonic_u32_score(samples, off, endian)
            if score >= 0.20:
                info["prefix_scores"].append(
                    (score, off, endian, step, first, last)
                )
    info["prefix_scores"].sort(reverse=True)
    return info


def _candidate_rank(header: int, trailer: int, info: dict) -> float:
    score = 0.0

    # Common candidates.
    if header == 4 and trailer == 0:
        score += 0.60
    if header == 5 and trailer == 0:
        score += 0.30
    if trailer == 0:
        score += 0.05

    for mono_score, off, endian, step, first, last in info.get("prefix_scores", []):
        if off + 4 <= header:
            score += mono_score * 3.0
            if step in (1, 0x100, 0x200, 0x400, 1000, 1004, 1005, 1010):
                score += 0.80
            if endian == "little":
                score += 0.15
            if off == 0:
                score += 0.25
            break

    return score


def rank_candidate_layouts(sess: SpoolTransferSession):
    info = infer_candidate_filetrans_layout(sess)
    candidates = info.get("size_candidates", [])
    ranked = sorted(
        candidates,
        key=lambda ht: _candidate_rank(ht[0], ht[1], info),
        reverse=True,
    )
    return ranked, info


def assemble_candidate_layout(
    sess: SpoolTransferSession,
    header: int,
    trailer: int,
    output_path: Optional[Path] = None,
    *,
    prefix: bytes = b"",
    suffix: bytes = b"",
    keep_byte0_values: Optional[set] = None,
):
    """
    Assemble candidate bulk frames.

    Normal WA345T layout observed so far:
        byte 0      : subtype/flags
        bytes 1..4  : u32 LE chunk number
        bytes 5..   : file bytes

    `prefix`/`suffix` allow newer START/FINISH packets to carry file bytes
    outside the normal DATA phase.

    `keep_byte0_values` is a conservative fallback: for selected byte-0 values
    the leading byte is retained as file data while bytes 1..4 are still
    removed as the chunk number. This mode is accepted only if final MD5 matches.
    """
    md5 = hashlib.md5()
    total = 0
    out = output_path.open("wb") if output_path is not None else None

    def emit(data: bytes) -> None:
        nonlocal total
        if not data:
            return
        total += len(data)
        md5.update(data)
        if out is not None:
            out.write(data)

    try:
        emit(prefix)

        with sess.spool_path.open("rb") as spool:
            for chunk in sess.candidate_chunks:
                spool.seek(chunk.offset)
                payload = spool.read(chunk.length)

                if keep_byte0_values is not None:
                    # Modern wrapper variant:
                    #   [byte0][u32 part_no][data]
                    # Keep byte0 only for explicitly selected values.
                    if len(payload) < 5:
                        return 0, b""
                    if payload[0] in keep_byte0_values:
                        emit(payload[:1])
                    emit(payload[5:])
                    continue

                end = len(payload) - trailer if trailer else len(payload)
                if header > end:
                    return 0, b""
                emit(payload[header:end])

        emit(suffix)
    finally:
        if out is not None:
            out.close()

    return total, md5.digest()


def _subset_values_for_count(counts: Counter, target: int, max_values: int = 12):
    """
    Find a small subset of byte values whose occurrence counts sum to target.
    Used only as a last-resort MD5-validated inference path.
    """
    if target <= 0:
        return []

    items = [(value, count) for value, count in counts.items() if count > 0]
    items.sort(key=lambda x: x[1], reverse=True)

    # Keep the DP bounded.
    if len(items) > max_values:
        singles = [{value} for value, count in items if count == target]
        return singles[:8]

    dp = {0: frozenset()}
    for value, count in items:
        snapshot = list(dp.items())
        for subtotal, chosen in snapshot:
            new_total = subtotal + count
            if new_total > target or new_total in dp:
                continue
            dp[new_total] = chosen | {value}
        if target in dp:
            return [set(dp[target])]

    return []


def candidate_byte0_counts(sess: SpoolTransferSession) -> Counter:
    counts = Counter()
    with sess.spool_path.open("rb") as spool:
        for chunk in sess.candidate_chunks:
            spool.seek(chunk.offset)
            b = spool.read(1)
            if b:
                counts[b[0]] += 1
    return counts




class StreamingFileTransfers:
    def __init__(self, extract_dir: Optional[Path]) -> None:
        self.extract_dir = extract_dir
        if extract_dir is not None:
            extract_dir.mkdir(parents=True, exist_ok=True)

        self.tmp_dir = Path(tempfile.mkdtemp(prefix="duml_filetrans_"))
        self.sessions = []
        self.active: Dict[Tuple[int, int, int, int], SpoolTransferSession] = {}
        self.census = Counter()
        self.over_511 = 0
        self.data_bytes = 0
        self._used_names = set()

    def _find(self, route: Tuple[int, int, int, int]) -> Optional[SpoolTransferSession]:
        sess = self.active.get(route)
        if sess is not None:
            return sess

        sess = self.active.get(_reverse_route(route))
        if sess is not None:
            return sess

        unique = {id(v): v for v in self.active.values()}
        if len(unique) == 1:
            return next(iter(unique.values()))

        return None

    def _remove(self, sess: SpoolTransferSession) -> None:
        for key in [key for key, value in self.active.items() if value is sess]:
            self.active.pop(key, None)

    def _new_session(
        self,
        route,
        source_name,
        target_name,
        filename,
        declared_size,
        timestamp,
        start_extra: bytes = b"",
    ) -> SpoolTransferSession:
        idx = len(self.sessions) + 1
        spool = self.tmp_dir / f"{idx:04d}.spool"
        spool.touch()

        sess = SpoolTransferSession(
            index=idx,
            route=route,
            source_name=source_name,
            target_name=target_name,
            filename=filename,
            declared_size=declared_size,
            start_time=timestamp,
            spool_path=spool,
            start_extra=bytes(start_extra),
        )
        self.sessions.append(sess)
        self.active[route] = sess
        return sess

    def add(self, item: CapturedDuml) -> None:
        p = item.packet
        if (p.cmd_set, p.cmd_id) != (0x00, 0x2A):
            return

        ft = classify_filetrans_frame(p)
        self.census[ft.kind] += 1
        if len(p.raw) > 0x01FF:
            self.over_511 += 1

        route = (p.source_id, p.source, p.target_id, p.target)

        if ft.kind == "start":
            self._new_session(
                route,
                p.source_name,
                p.target_name,
                ft.filename,
                int(ft.total_len or 0),
                item.usb.timestamp,
                ft.extra,
            )
            return

        # WA345T observation: virtually all bulk file frames are classified as
        # "other" by the old phase-byte layout, are PC->DM368, and are large.
        # Fallback for other/newer products only. M4T DATA is classified
        # exactly above as subcommand 0x04, including short final chunks.
        candidate_bulk = (
            ft.kind == "other"
            and len(p.payload) >= 64
            and p.source_id == 10  # PC
        )

        if ft.kind not in {"data", "finish"} and not candidate_bulk:
            return

        sess = self._find(route)
        if sess is None:
            sess = self._new_session(
                route,
                p.source_name,
                p.target_name,
                f"partial_transfer_{len(self.sessions) + 1}.bin",
                -1,
                item.usb.timestamp,
            )

        if candidate_bulk:
            payload = bytes(p.payload)
            digest = hashlib.md5(payload).digest()

            with sess.spool_path.open("ab") as fh:
                offset = fh.tell()
                fh.write(payload)

            sess.candidate_chunks.append(
                SpoolChunk(
                    offset=offset,
                    length=len(payload),
                    digest=digest,
                    ordinal=sess.candidate_count,
                )
            )
            sess.candidate_payload_bytes += len(payload)

            if len(sess.candidate_prefix_samples) < 256:
                sess.candidate_prefix_samples.append(payload[:32])

            sess.end_time = item.usb.timestamp
            self.data_bytes += len(payload)
            return

        if ft.kind == "data":
            part_no = int(ft.part_no or 0)
            data = ft.data
            digest = hashlib.md5(data).digest()
            old = sess.chunks.get(part_no)

            if old is not None:
                if old.length == len(data) and old.digest == digest:
                    sess.duplicate_parts += 1
                else:
                    sess.conflicting_parts += 1
                sess.end_time = item.usb.timestamp
                return

            with sess.spool_path.open("ab") as fh:
                offset = fh.tell()
                fh.write(data)

            sess.chunks[part_no] = SpoolChunk(
                offset, len(data), digest, ordinal=len(sess.chunks)
            )
            sess.end_time = item.usb.timestamp
            self.data_bytes += len(data)
            return

        if ft.kind == "finish":
            sess.finish_digest = ft.digest
            sess.finish_extra = bytes(ft.extra)
            sess.end_time = item.usb.timestamp
            self._remove(sess)

    def _unique_output(self, sess: SpoolTransferSession) -> Optional[Path]:
        if self.extract_dir is None:
            return None

        fallback = f"transfer_{sess.index:03d}.bin"
        name = _safe_transfer_filename(sess.filename, fallback)
        candidate = name
        stem = Path(name).stem
        suffix = Path(name).suffix
        n = 2

        while (
            candidate.lower() in self._used_names
            or (self.extract_dir / candidate).exists()
        ):
            candidate = f"{stem}_{n}{suffix}"
            n += 1

        self._used_names.add(candidate.lower())
        return self.extract_dir / candidate

    def _finalize_legacy(self, sess: SpoolTransferSession) -> None:
        out_path = self._unique_output(sess)
        out_fh = out_path.open("wb") if out_path is not None else None
        md5 = hashlib.md5()
        total = 0

        try:
            with sess.spool_path.open("rb") as spool:
                for part_no in sess.sorted_parts:
                    chunk = sess.chunks[part_no]
                    spool.seek(chunk.offset)
                    data = spool.read(chunk.length)
                    md5.update(data)
                    total += len(data)
                    if out_fh is not None:
                        out_fh.write(data)
        finally:
            if out_fh is not None:
                out_fh.close()

        sess.assembled_size = total
        sess.assembled_md5 = md5.digest()
        sess.output_path = out_path
        sess.inferred_layout = "M4T exact: 0x04 + u32_le chunk_index + data"
        sess.inferred_header = 0
        sess.inferred_trailer = 0

    def _finalize_candidates(self, sess: SpoolTransferSession) -> None:
        prefix_scores = infer_candidate_filetrans_layout(sess).get("prefix_scores", [])
        prefix_note = ""
        if prefix_scores:
            score, off, endian, step, first, last = prefix_scores[0]
            prefix_note = (
                f"best_u32@{off}/{endian} score={score:.3f} "
                f"step={step} first={first} last={last}"
            )

        # Candidate placement of bytes which the legacy public dissector leaves
        # unparsed after START filename / FINISH digest.
        extra_modes = [
            ("none", b"", b""),
        ]
        if sess.start_extra:
            extra_modes.extend([
                ("START-extra prefix", sess.start_extra, b""),
                ("START-extra suffix", b"", sess.start_extra),
            ])
        if sess.finish_extra:
            extra_modes.extend([
                ("FINISH-extra prefix", sess.finish_extra, b""),
                ("FINISH-extra suffix", b"", sess.finish_extra),
            ])
        if sess.start_extra and sess.finish_extra:
            extra_modes.extend([
                (
                    "START-prefix + FINISH-suffix",
                    sess.start_extra,
                    sess.finish_extra,
                ),
                (
                    "FINISH-prefix + START-suffix",
                    sess.finish_extra,
                    sess.start_extra,
                ),
            ])

        # Deduplicate identical byte arrangements.
        seen_modes = set()
        unique_modes = []
        for label, prefix, suffix in extra_modes:
            key = (prefix, suffix)
            if key in seen_modes:
                continue
            seen_modes.add(key)
            unique_modes.append((label, prefix, suffix))
        extra_modes = unique_modes

        chosen = None

        # First, solve constant wrapper sizes for every plausible extra layout.
        for extra_label, prefix, suffix in extra_modes:
            target_candidate_data = (
                sess.declared_size - len(prefix) - len(suffix)
                if sess.declared_size >= 0
                else -1
            )
            if target_candidate_data < 0:
                continue

            overhead = sess.candidate_payload_bytes - target_candidate_data
            if overhead < 0 or sess.candidate_count <= 0:
                continue
            if overhead % sess.candidate_count != 0:
                continue

            strip = overhead // sess.candidate_count
            if not (0 <= strip <= 64):
                continue

            candidates = [(h, strip - h) for h in range(strip + 1)]
            info = {"prefix_scores": prefix_scores}
            candidates.sort(
                key=lambda ht: _candidate_rank(ht[0], ht[1], info),
                reverse=True,
            )

            # Exact MD5 is the proof. Try ranked wrappers.
            for header, trailer in candidates:
                total, digest = assemble_candidate_layout(
                    sess,
                    header,
                    trailer,
                    None,
                    prefix=prefix,
                    suffix=suffix,
                )
                if total != sess.declared_size:
                    continue
                if sess.finish_digest is not None and digest == sess.finish_digest:
                    chosen = (
                        header,
                        trailer,
                        total,
                        digest,
                        f"exact size + MD5 ({extra_label})",
                        prefix,
                        suffix,
                        None,
                    )
                    break

            if chosen is not None:
                break

        # Last-resort modern framing:
        # if u32 chunk number is at offset 1, stripping 5 bytes gives a file
        # slightly smaller than declared size. Test whether byte0 is data for a
        # subset of frames. This path is accepted ONLY by exact final MD5.
        if chosen is None and sess.candidate_count and sess.declared_size >= 0:
            base_total = sess.candidate_payload_bytes - 5 * sess.candidate_count

            for extra_label, prefix, suffix in extra_modes:
                target_from_chunks = sess.declared_size - len(prefix) - len(suffix)
                deficit = target_from_chunks - base_total
                if deficit <= 0 or deficit > sess.candidate_count:
                    continue

                counts = candidate_byte0_counts(sess)
                value_sets = _subset_values_for_count(counts, deficit)

                # Also test a direct single-value match even if DP was bounded.
                for value, count in counts.items():
                    if count == deficit:
                        value_sets.append({value})

                dedup = []
                seen_sets = set()
                for values in value_sets:
                    key = tuple(sorted(values))
                    if key in seen_sets:
                        continue
                    seen_sets.add(key)
                    dedup.append(values)

                for values in dedup[:16]:
                    total, digest = assemble_candidate_layout(
                        sess,
                        5,
                        0,
                        None,
                        prefix=prefix,
                        suffix=suffix,
                        keep_byte0_values=values,
                    )
                    if total != sess.declared_size:
                        continue
                    if sess.finish_digest is not None and digest == sess.finish_digest:
                        chosen = (
                            5,
                            0,
                            total,
                            digest,
                            (
                                "exact size + MD5 "
                                f"({extra_label}; retain byte0 for "
                                f"{','.join(f'0x{x:02X}' for x in sorted(values))})"
                            ),
                            prefix,
                            suffix,
                            values,
                        )
                        break

                if chosen is not None:
                    break

        if chosen is None:
            base_total = (
                sess.candidate_payload_bytes - 5 * sess.candidate_count
                if sess.candidate_count
                else 0
            )
            deficit = (
                sess.declared_size - base_total
                if sess.declared_size >= 0
                else None
            )
            sess.inferred_layout = "unresolved: no MD5-valid framing"
            sess.inference_note = (
                f"payload={sess.candidate_payload_bytes} "
                f"declared={sess.declared_size} "
                f"chunks={sess.candidate_count} "
                f"strip5_total={base_total} "
                f"strip5_deficit={deficit}; "
                f"start_extra={len(sess.start_extra)} "
                f"finish_extra={len(sess.finish_extra)}; "
                f"{prefix_note}"
            )
            return

        (
            header,
            trailer,
            total,
            digest,
            reason,
            prefix,
            suffix,
            keep_values,
        ) = chosen

        out_path = self._unique_output(sess)
        if out_path is not None:
            total, digest = assemble_candidate_layout(
                sess,
                header,
                trailer,
                out_path,
                prefix=prefix,
                suffix=suffix,
                keep_byte0_values=keep_values,
            )

        sess.assembled_size = total
        sess.assembled_md5 = digest
        sess.output_path = out_path
        sess.inferred_header = header
        sess.inferred_trailer = trailer
        sess.inferred_layout = reason
        sess.inference_note = (
            f"payload={sess.candidate_payload_bytes} "
            f"declared={sess.declared_size} "
            f"chunks={sess.candidate_count}; "
            f"start_extra={len(sess.start_extra)} "
            f"finish_extra={len(sess.finish_extra)}; "
            f"{prefix_note}"
        )

    def _write_meta(self, sess: SpoolTransferSession) -> None:
        if sess.output_path is None:
            return

        meta = sess.output_path.with_name(
            sess.output_path.name + ".duml.txt"
        )
        parts = sess.sorted_parts

        lines = [
            f"source={sess.source_name}",
            f"target={sess.target_name}",
            f"original_filename={sess.filename}",
            f"declared_size={sess.declared_size}",
            f"assembled_size={sess.assembled_size}",
            f"size_match={sess.size_match}",
            f"legacy_parts={len(parts)}",
            f"candidate_chunks={sess.candidate_count}",
            f"candidate_payload_bytes={sess.candidate_payload_bytes}",
            f"start_extra_len={len(sess.start_extra)}",
            f"start_extra_hex={sess.start_extra.hex()}",
            f"finish_extra_len={len(sess.finish_extra)}",
            f"finish_extra_hex={sess.finish_extra.hex()}",
            f"inferred_header={sess.inferred_header}",
            f"inferred_trailer={sess.inferred_trailer}",
            f"inferred_layout={sess.inferred_layout}",
            f"inference_note={sess.inference_note}",
            f"duplicates={sess.duplicate_parts}",
            f"conflicts={sess.conflicting_parts}",
            f"md5={sess.assembled_md5.hex()}",
            (
                "finish_digest16="
                + (sess.finish_digest.hex() if sess.finish_digest else "")
            ),
            f"md5_match={sess.md5_match}",
        ]

        meta.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def finalize(self) -> Tuple[SpoolTransferSession, ...]:
        for sess in self.sessions:
            if sess.finalized:
                continue

            if sess.chunks:
                self._finalize_legacy(sess)
            elif sess.candidate_chunks:
                self._finalize_candidates(sess)

            sess.finalized = True
            self._write_meta(sess)

            try:
                sess.spool_path.unlink()
            except OSError:
                pass

        try:
            self.tmp_dir.rmdir()
        except OSError:
            pass

        return tuple(self.sessions)

    def report(self) -> str:
        self.finalize()

        lines = ["=== FileTrans General Trans (0x00/0x2A) ==="]
        lines.append(
            "Packet census: "
            + ", ".join(
                f"{kind}={count}"
                for kind, count in self.census.most_common()
            )
            + f"; >511B={self.over_511}; "
            + f"candidate/DATA={self.data_bytes / (1024 * 1024):.1f} MiB"
        )

        if not self.sessions:
            lines.append("No file-transfer sessions found.")
            return "\n".join(lines)

        for sess in self.sessions:
            parts = sess.sorted_parts
            duration = (
                None
                if sess.end_time is None
                else sess.end_time - sess.start_time
            )

            lines.append("")
            lines.append(
                f"Transfer #{sess.index}: "
                f"{sess.source_name} -> {sess.target_name} "
                f"file={sess.filename!r}"
            )
            lines.append(
                f"  declared_size="
                f"{sess.declared_size if sess.declared_size >= 0 else 'unknown'} "
                f"assembled_size={sess.assembled_size} "
                f"size_match={sess.size_match}"
            )

            if parts:
                missing = (
                    "unknown"
                    if sess.missing_count is None
                    else str(sess.missing_count)
                )
                lines.append(
                    f"  legacy_parts={len(parts)} "
                    f"range={parts[0]}..{parts[-1]} "
                    f"missing={missing} "
                    f"duplicates={sess.duplicate_parts} "
                    f"conflicts={sess.conflicting_parts}"
                )
            else:
                lines.append("  legacy_parts=0")

            if sess.candidate_count:
                overhead = (
                    sess.candidate_payload_bytes
                    - max(sess.declared_size, 0)
                )
                per_frame = overhead / sess.candidate_count
                lines.append(
                    f"  candidate_chunks={sess.candidate_count} "
                    f"candidate_payload={sess.candidate_payload_bytes} "
                    f"overhead={overhead} "
                    f"({per_frame:.6f}/frame)"
                )
                lines.append(
                    f"  phase_extras=start:{len(sess.start_extra)}B "
                    f"finish:{len(sess.finish_extra)}B"
                )
                lines.append(
                    f"  inferred_wrapper="
                    f"header:{sess.inferred_header} "
                    f"trailer:{sess.inferred_trailer}"
                )
                lines.append(
                    f"  inference={sess.inferred_layout}"
                )
                if sess.inference_note:
                    lines.append(
                        f"  inference_note={sess.inference_note}"
                    )

            if duration is not None:
                lines.append(f"  duration={duration:.3f}s")

            lines.append(
                "  md5(assembled)="
                + (
                    sess.assembled_md5.hex()
                    if sess.assembled_md5
                    else "<unresolved>"
                )
            )

            if sess.finish_digest is not None:
                lines.append(
                    f"  finish_digest16={sess.finish_digest.hex()} "
                    f"md5_match={sess.md5_match}"
                )

            if sess.output_path is not None:
                lines.append(f"  extracted={sess.output_path}")

        return "\n".join(lines)

    def cleanup(self) -> None:
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass


def write_semantic_stream_report(
    path: Path,
    state_items: Iterable[CapturedDuml],
    inventory: Counter,
    base_timestamp: Optional[float] = None,
) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(build_upgrade_state_machine(list(state_items), base_timestamp))
        fh.write("\n\n=== Semantic command inventory ===\n")
        for (cmdset, cmdid, name), count in inventory.most_common():
            fh.write(f"{count:8d}  0x{cmdset:02X}/0x{cmdid:02X}  {name}\n")


def run_pcap_streaming(args, path: Path) -> int:
    stats = StreamStats()
    state_items = []
    semantic_inventory = Counter()
    base_ts = None

    filetrans_needed = bool(args.filetrans or args.filetrans_report or args.extract_files)
    ft_stream = StreamingFileTransfers(Path(args.extract_files) if args.extract_files else None) if filetrans_needed else None

    csv_fh = None
    csv_writer = None
    hex_fh = None
    report_fh = None

    printed = 0
    eligible_stdout = 0
    wall_start = time.monotonic()
    last_progress = wall_start
    last_progress_packets = 0

    try:
        if args.csv:
            csv_fh = Path(args.csv).open("w", newline="", encoding="utf-8")
        if args.hex_path:
            hex_fh = Path(args.hex_path).open("w", encoding="ascii", newline="\n")
        if args.report:
            report_fh = Path(args.report).open("w", encoding="utf-8", newline="\n")

        for item in extract_pcap(path):
            if base_ts is None:
                base_ts = item.usb.timestamp

            stats.add(item)
            p = item.packet
            sem = semantic_decode(p)
            semantic_inventory[(p.cmd_set, p.cmd_id, sem.name)] += 1

            # Keep only small control/status frames needed by the state-machine.
            if p.cmd_set == 0 and p.cmd_id in (0x01, 0x0C, 0x41, 0x42, 0x4F, 0x51):
                state_items.append(item)

            if ft_stream is not None:
                ft_stream.add(item)

            if csv_fh is not None:
                row = captured_row_stream(item, full_hex=args.csv_full_hex)
                if csv_writer is None:
                    csv_writer = csv.DictWriter(csv_fh, fieldnames=list(row.keys()))
                    csv_writer.writeheader()
                csv_writer.writerow(row)

            if hex_fh is not None:
                hex_fh.write(bytes_to_hex(p.raw) + "\n")

            if report_fh is not None:
                if stats.total > 1:
                    report_fh.write("\n\n")
                report_fh.write(format_captured(item, base_ts))

            if not args.summary_only:
                selected = is_interesting_packet(p) if args.interesting_only else True
                if selected:
                    eligible_stdout += 1
                    if args.limit is None or printed < max(args.limit, 0):
                        if printed:
                            print()
                        print(format_captured(item, base_ts))
                        printed += 1

            now = time.monotonic()
            if args.progress and now - last_progress >= args.progress_interval:
                elapsed = now - wall_start
                rate = (stats.total / elapsed) if elapsed > 0 else 0.0
                ft_mib = (ft_stream.data_bytes / (1024 * 1024)) if ft_stream is not None else 0.0
                delta = stats.total - last_progress_packets
                print(
                    f"[progress] valid={stats.total:,} "
                    f"pcap_record={item.usb.pcap_record:,} "
                    f"capture_t=+{item.usb.timestamp - base_ts:.1f}s "
                    f"rate={rate:,.0f} pkt/s "
                    f"filetrans_data={ft_mib:,.1f} MiB "
                    f"(+{delta:,} packets)",
                    file=sys.stderr,
                    flush=True,
                )
                last_progress = now
                last_progress_packets = stats.total

        if args.limit is not None and eligible_stdout > printed and not args.summary_only:
            print(f"\n... stdout limited to {printed} of {eligible_stdout} selected packets ...")

        if ft_stream is not None:
            ft_stream.finalize()
            extracted_count = sum(1 for s in ft_stream.sessions if s.output_path is not None)
            if args.extract_files:
                print(f"Extracted {extracted_count} non-empty transferred file(s) to {args.extract_files}")

        if args.semantic_report:
            write_semantic_stream_report(Path(args.semantic_report), state_items, semantic_inventory, base_ts)

        if args.filetrans_report and ft_stream is not None:
            Path(args.filetrans_report).write_text(ft_stream.report() + "\n", encoding="utf-8")

        if args.state_machine:
            print(build_upgrade_state_machine(state_items, base_ts))
            if not args.summary_only:
                print()

        if args.filetrans and ft_stream is not None:
            print(ft_stream.report())
            if not args.summary_only:
                print()

        if not args.no_summary:
            print_stream_summary(stats)

        return 0

    finally:
        for fh in (csv_fh, hex_fh, report_fh):
            if fh is not None:
                try:
                    fh.close()
                except Exception:
                    pass
        if ft_stream is not None:
            ft_stream.cleanup()



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Decode DJI DUML from HEX or a classic USBPcap .pcap capture"
    )
    ap.add_argument(
        "input",
        help="path to USBPcap .pcap, or one DUML packet as hexadecimal",
    )
    ap.add_argument("--csv", metavar="FILE", help="export all decoded PCAP frames to CSV")
    ap.add_argument("--hex", dest="hex_path", metavar="FILE", help="export one validated DUML frame per line")
    ap.add_argument("--report", metavar="FILE", help="write full human-readable decode to a text file")
    ap.add_argument("--summary-only", action="store_true", help="for PCAP input, suppress per-frame stdout and print only summary")
    ap.add_argument("--no-summary", action="store_true", help="for PCAP input, suppress the final summary")
    ap.add_argument("--limit", type=int, default=None, help="limit only the number of frames printed to stdout (exports still contain all frames)")
    ap.add_argument("--no-crc", action="store_true", help="HEX mode only: decode without enforcing CRC8/CRC16")
    ap.add_argument("--state-machine", action="store_true", help="print reconstructed firmware-upgrade state machine")
    ap.add_argument("--semantic-report", metavar="FILE", help="write upgrade state machine + semantic command inventory")
    ap.add_argument("--interesting-only", action="store_true", help="stdout: suppress routine telemetry/handshake frames")
    ap.add_argument("--filetrans", action="store_true", help="print reconstructed 0x2A file-transfer sessions")
    ap.add_argument("--filetrans-report", metavar="FILE", help="write reconstructed 0x2A transfer report")
    ap.add_argument("--extract-files", metavar="DIR", help="reassemble request-side 0x2A transferred files into DIR")
    ap.add_argument("--csv-full-hex", action="store_true", help="include full packet/payload hex for large FileTrans DATA rows in CSV (can create multi-GB CSVs)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="disable periodic progress lines on stderr")
    ap.add_argument("--progress-interval", type=float, default=3.0, help="seconds between progress lines (default: 3)")
    ap.set_defaults(progress=True)
    return ap


def looks_like_file(value: str) -> bool:
    return Path(value).is_file()


def main(argv: Optional[list[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if looks_like_file(args.input):
        path = Path(args.input)
        try:
            return run_pcap_streaming(args, path)
        except (OSError, PcapError, DumlError) as exc:
            ap.error(str(exc))

    if (
        args.csv or args.hex_path or args.report or args.summary_only or args.no_summary
        or args.limit is not None or args.state_machine or args.semantic_report
        or args.interesting_only or args.filetrans or args.filetrans_report
        or args.extract_files or args.csv_full_hex or not args.progress
        or args.progress_interval != 3.0
    ):
        ap.error("PCAP output options require a file input")

    try:
        pkt = parse_hex_packet(args.input, verify_crc=not args.no_crc)
    except DumlError as exc:
        ap.error(str(exc))
    print(format_packet(pkt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
