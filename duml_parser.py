#!/usr/bin/env python3
"""
Python port of CunningLogic/dumlPrinter.

Original project:
    https://github.com/CunningLogic/dumlPrinter

This version keeps the same core DUML decoding behavior while fixing several
Java/signed-byte issues and field extraction bugs:

- source/target component ID: low 5 bits (& 0x1F)
- source/target instance: high 3 bits ((byte >> 5) & 0x07)
- command type: high 3 bits (& 0xE0)
- payload excludes the final CRC16
- packet checksum is correctly named CRC16
- packet length parsing is unsigned by construction
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Optional

MAGIC = 0x55
MIN_PACKET_LEN = 13
MAX_PACKET_LEN = 0x01FF

CRC8_SEED = 0x77
CRC16_SEED = 0x3692
CRC8_POLY = 0x8C
CRC16_POLY = 0x8408

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

class DumlError(ValueError):
    pass

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
        raise DumlError("Hex string must contain an even number of characters")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise DumlError(f"Invalid hexadecimal input: {exc}") from exc

def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()

def route_id(component_id: int, instance: int) -> str:
    return f"{component_id:02d}{instance:02d}"

def parse_duml(packet: bytes, *, verify_crc: bool = True) -> DumlPacket:
    if not packet:
        raise DumlError("Empty packet")

    if packet[0] != MAGIC:
        raise DumlError(f"Invalid magic: 0x{packet[0]:02X}; expected 0x55")

    if len(packet) < MIN_PACKET_LEN:
        raise DumlError(
            f"Invalid packet length: {len(packet)}; minimum is {MIN_PACKET_LEN}"
        )

    if len(packet) > MAX_PACKET_LEN:
        raise DumlError(
            f"Invalid packet length: {len(packet)}; maximum is {MAX_PACKET_LEN}"
        )

    length = packet[1] | ((packet[2] & 0x03) << 8)
    version = packet[2] >> 2
    header_crc = packet[3]

    if version != 1:
        raise DumlError(f"Unsupported DUML version: {version}")

    if length != len(packet):
        raise DumlError(
            f"Defined length does not match actual length: {length} != {len(packet)}"
        )

    expected_header_crc = crc8(packet[:3])
    if verify_crc and header_crc != expected_header_crc:
        raise DumlError(
            f"Header CRC8 mismatch: 0x{header_crc:02X} != 0x{expected_header_crc:02X}"
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
            f"Packet CRC16 mismatch: 0x{packet_crc:04X} != 0x{calculated_crc:04X}"
        )

    payload = packet[11:-2]

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
        payload=payload,
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

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="DJI DUML packet parser — Python port of dumlPrinter"
    )
    ap.add_argument(
        "packet",
        help="DUML packet as hex, e.g. 550D04332A2835124000002AE4",
    )
    ap.add_argument(
        "--no-crc",
        action="store_true",
        help="Decode packet without enforcing CRC8/CRC16 validity",
    )
    args = ap.parse_args(argv)

    try:
        packet = parse_hex_packet(args.packet, verify_crc=not args.no_crc)
    except DumlError as exc:
        ap.error(str(exc))

    print(format_packet(packet))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
