#!/usr/bin/env python3
"""
DJI DUML parser + USBPcap extractor.

Combines the core functionality of CunningLogic/dumlPrinter with a dependency-
free USBPcap reader. It can decode either a single DUML packet supplied as HEX
or all valid DUML packets found in a classic USBPcap .pcap capture.

Examples:
    python duml.py 550D04332A2835124000002AE4
    python duml.py flash_usb.pcap
    python duml.py flash_usb.pcap --summary-only
    python duml.py flash_usb.pcap --csv out.csv --hex out.hex --report out.txt

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
import os
import struct
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, Iterable, Iterator, Optional, TextIO, Tuple


MAGIC = 0x55
MIN_PACKET_LEN = 13
MAX_PACKET_LEN = 0x01FF

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
            packet = parse_duml(raw, verify_crc=True)
            self._consume(length)
            yield origin_meta, origin_offset, span_count, packet


# ---------------------------------------------------------------------------
# CRC + DUML
# ---------------------------------------------------------------------------


def crc8(data: bytes, seed: int = CRC8_SEED) -> int:
    crc = seed & 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ CRC8_POLY) if (crc & 1) else (crc >> 1)
        crc &= 0xFF
    return crc


def crc16(data: bytes, seed: int = CRC16_SEED) -> int:
    crc = seed & 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ CRC16_POLY) if (crc & 1) else (crc >> 1)
        crc &= 0xFFFF
    return crc


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

    expected_header_crc = crc8(packet[:3])
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
    calculated_crc = crc16(packet[:-2])
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


def format_packet(pkt: DumlPacket) -> str:
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
        f"cmdType:\t0x{pkt.cmd_type:02X}\t\t{pkt.cmd_type_name}",
        f"cmdSet:\t\t0x{pkt.cmd_set:02X}\t\t{pkt.cmd_set_name}",
        f"cmdID:\t\t0x{pkt.cmd_id:02X}",
    ]
    if pkt.payload:
        lines.extend([
            "",
            f"Payload:\t{bytes_to_hex(pkt.payload)}",
            f"Length:\t\t{len(pkt.payload)}",
        ])
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
        "payload_len": len(p.payload),
        "payload_hex": bytes_to_hex(p.payload),
        "crc16": f"0x{p.packet_crc16:04X}",
        "packet_hex": bytes_to_hex(p.raw),
    }


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
        (x.packet.cmd_set_name, x.packet.cmd_id, x.packet.cmd_type_name)
        for x in items
    )
    print("Top commands:", file=out)
    for (cmdset, cmdid, cmdtype), count in commands.most_common(12):
        print(f"  {count:6d}  {cmdset:<24} cmdID=0x{cmdid:02X}  {cmdtype}", file=out)

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
    return ap


def looks_like_file(value: str) -> bool:
    return Path(value).is_file()


def main(argv: Optional[list[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if looks_like_file(args.input):
        path = Path(args.input)
        try:
            items = list(extract_pcap(path))
        except (OSError, PcapError, DumlError) as exc:
            ap.error(str(exc))

        base_ts = items[0].usb.timestamp if items else None

        if args.csv:
            write_csv(Path(args.csv), items)
        if args.hex_path:
            write_hex(Path(args.hex_path), items)
        if args.report:
            write_report(Path(args.report), items, base_ts)

        if not args.summary_only:
            selected = items if args.limit is None else items[: max(args.limit, 0)]
            for i, item in enumerate(selected):
                if i:
                    print()
                print(format_captured(item, base_ts))
            if args.limit is not None and len(items) > len(selected):
                print(f"\n... stdout limited to {len(selected)} of {len(items)} packets ...")

        if not args.no_summary:
            print_summary(items)
        return 0

    if args.csv or args.hex_path or args.report or args.summary_only or args.no_summary or args.limit is not None:
        ap.error("PCAP output options require a file input")

    try:
        pkt = parse_hex_packet(args.input, verify_crc=not args.no_crc)
    except DumlError as exc:
        ap.error(str(exc))
    print(format_packet(pkt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
