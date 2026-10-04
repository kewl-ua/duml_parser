#!/usr/bin/env python3
"""
capdump.py — dump DJI M4T/WA345T firmware files from a USBPcap capture.

Focused frontend over duml_semantic_v8.py.

Input:
    classic PCAP captured with USBPcap (linktype 249)

Output:
    <OUT>/
      files/            reconstructed transferred files
      manifest.json     machine-readable verification manifest
      filetrans.txt     human-readable transfer report

Validation:
    * DUML framing + CRC8/CRC16 are validated by the core extractor.
    * FileTrans 0x00/0x2A is reconstructed as:
        OPEN  01 | u32_le size | u8 name_len | filename\\0 | ...
        DATA  04 | u32_le chunk_index | data
        END   03 | MD5[16]
    * A transfer is "verified" only when:
        assembled_size == declared_size
        no missing parts
        no conflicting duplicate parts
        MD5(assembled) == END digest
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from duml_semantic_v8 import StreamingFileTransfers, extract_pcap


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="capdump",
        description="Dump DJI M4T/WA345T FileTrans files from a USBPcap capture.",
    )
    ap.add_argument("capture", type=Path, help="USBPcap .pcap input")
    ap.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("dump"),
        help="output directory (default: dump)",
    )
    ap.add_argument(
        "--progress-interval",
        type=float,
        default=1.0,
        help="seconds between progress lines (default: 1.0)",
    )
    ap.add_argument(
        "--no-progress",
        action="store_true",
        help="disable periodic progress output",
    )
    ap.add_argument(
        "--allow-partial",
        action="store_true",
        help="return success even if one or more transfers fail verification",
    )
    return ap


def session_verified(sess) -> bool:
    missing = sess.missing_count
    missing_ok = (missing == 0) if sess.sorted_parts else True
    return (
        sess.output_path is not None
        and sess.size_match is True
        and sess.md5_match is True
        and missing_ok
        and sess.conflicting_parts == 0
    )


def session_manifest(sess, out_root: Path) -> dict:
    output = None
    meta = None

    if sess.output_path is not None:
        try:
            output = str(sess.output_path.relative_to(out_root))
        except ValueError:
            output = str(sess.output_path)

        sidecar = sess.output_path.with_name(sess.output_path.name + ".duml.txt")
        if sidecar.exists():
            try:
                meta = str(sidecar.relative_to(out_root))
            except ValueError:
                meta = str(sidecar)

    parts = sess.sorted_parts

    return {
        "index": sess.index,
        "source": sess.source_name,
        "target": sess.target_name,
        "filename": sess.filename,
        "declared_size": sess.declared_size,
        "assembled_size": sess.assembled_size,
        "size_match": sess.size_match,
        "parts": len(parts),
        "part_first": parts[0] if parts else None,
        "part_last": parts[-1] if parts else None,
        "missing_parts": sess.missing_count,
        "duplicate_parts": sess.duplicate_parts,
        "conflicting_parts": sess.conflicting_parts,
        "md5": sess.assembled_md5.hex() if sess.assembled_md5 else None,
        "finish_digest16": (
            sess.finish_digest.hex() if sess.finish_digest is not None else None
        ),
        "md5_match": sess.md5_match,
        "verified": session_verified(sess),
        "output": output,
        "metadata": meta,
    }


def write_manifest(
    path: Path,
    capture: Path,
    out_root: Path,
    valid_duml: int,
    ft,
) -> dict:
    entries = [session_manifest(sess, out_root) for sess in ft.sessions]
    verified = sum(1 for item in entries if item["verified"])

    manifest = {
        "format": "dji-capdump-manifest-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture": str(capture),
        "valid_duml_packets": valid_duml,
        "filetrans": {
            "packet_census": dict(ft.census),
            "frames_over_511_bytes": ft.over_511,
            "data_bytes": ft.data_bytes,
            "transfers": len(entries),
            "verified_transfers": verified,
            "all_verified": bool(entries) and verified == len(entries),
        },
        "files": entries,
    }

    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def print_summary(manifest: dict, output: Path) -> None:
    ft = manifest["filetrans"]

    print()
    print("=== capdump ===")
    print(f"Valid DUML packets : {manifest['valid_duml_packets']:,}")
    print(f"FileTrans DATA     : {ft['data_bytes'] / (1024 * 1024):.1f} MiB")
    print(f"Transfers          : {ft['transfers']}")
    print(f"Verified           : {ft['verified_transfers']}/{ft['transfers']}")
    print(f"Output             : {output}")

    for item in manifest["files"]:
        mark = "OK" if item["verified"] else "FAIL"
        md5 = item["md5"] or "-"
        print(
            f"[{mark:4}] #{item['index']:02d} "
            f"{item['assembled_size']:>10} B  "
            f"{md5}  {item['filename']}"
        )


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    capture = args.capture
    if not capture.is_file():
        print(f"capdump: capture not found: {capture}", file=sys.stderr)
        return 2

    out_root = args.output
    files_dir = out_root / "files"
    out_root.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(parents=True, exist_ok=True)

    ft = StreamingFileTransfers(files_dir)

    valid_duml = 0
    last_progress = time.monotonic()
    wall_start = last_progress
    first_capture_ts = None

    try:
        for item in extract_pcap(capture):
            valid_duml += 1

            if first_capture_ts is None:
                first_capture_ts = item.usb.timestamp

            ft.add(item)

            now = time.monotonic()
            if (
                not args.no_progress
                and now - last_progress >= args.progress_interval
            ):
                elapsed = max(now - wall_start, 1e-9)
                capture_t = item.usb.timestamp - first_capture_ts
                print(
                    f"[capdump] valid={valid_duml:,} "
                    f"pcap_record={item.usb.pcap_record:,} "
                    f"capture_t=+{capture_t:.1f}s "
                    f"rate={valid_duml / elapsed:,.0f} pkt/s "
                    f"data={ft.data_bytes / (1024*1024):,.1f} MiB "
                    f"transfers={len(ft.sessions)}",
                    file=sys.stderr,
                    flush=True,
                )
                last_progress = now

        ft.finalize()

        report_path = out_root / "filetrans.txt"
        report_path.write_text(ft.report() + "\n", encoding="utf-8")

        manifest = write_manifest(
            out_root / "manifest.json",
            capture,
            out_root,
            valid_duml,
            ft,
        )
        print_summary(manifest, out_root)

        total = manifest["filetrans"]["transfers"]
        verified = manifest["filetrans"]["verified_transfers"]

        if total == 0:
            print("capdump: no FileTrans transfers found", file=sys.stderr)
            return 3

        if verified != total and not args.allow_partial:
            print(
                f"capdump: verification failed for {total - verified} "
                f"of {total} transfer(s)",
                file=sys.stderr,
            )
            return 4

        return 0

    finally:
        ft.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
