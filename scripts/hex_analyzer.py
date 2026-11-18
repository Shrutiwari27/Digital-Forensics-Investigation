#!/usr/bin/env python3
"""FAT12 root-directory inspection, signature detection, and deleted-file carving."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
OUTPUT = ROOT / "output"
DEFAULT_IMAGE = EVIDENCE / "suspect_device.dd"

SIGNATURES = [
    (b"\xFF\xD8\xFF", "JPEG image", ".jpg"),
    (b"%PDF", "PDF document", ".pdf"),
    (b"PK\x03\x04", "ZIP/Office archive", ".zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", ".png"),
    (b"GIF87a", "GIF image", ".gif"),
    (b"GIF89a", "GIF image", ".gif"),
]

def identify_signature(data):
    for signature, description, extension in SIGNATURES:
        if data.startswith(signature):
            return description, extension
    return "Unknown / text / raw data", None

def parse_fat12(path):
    disk = Path(path).read_bytes()
    if len(disk) < 512 or disk[510:512] != b"\x55\xAA":
        raise ValueError("Invalid or unsupported disk image: boot-sector signature missing.")

    bps = struct.unpack_from("<H", disk, 11)[0]
    reserved = struct.unpack_from("<H", disk, 14)[0]
    fats = disk[16]
    root_entries = struct.unpack_from("<H", disk, 17)[0]
    sectors_per_fat = struct.unpack_from("<H", disk, 22)[0]
    if bps not in (512, 1024, 2048, 4096) or not fats or not sectors_per_fat:
        raise ValueError("Unsupported FAT BPB geometry.")

    root_sectors = (root_entries * 32 + bps - 1) // bps
    root_start = (reserved + fats * sectors_per_fat) * bps
    data_start_sector = reserved + fats * sectors_per_fat + root_sectors
    artifacts = []

    for index in range(root_entries):
        offset = root_start + index * 32
        entry = disk[offset:offset+32]
        if len(entry) < 32 or entry[0] == 0x00:
            break
        if entry[11] == 0x0F:  # Long-file-name slot, not a normal short entry.
            continue
        deleted = entry[0] == 0xE5
        if entry[0] == 0x05:
            first = 0xE5
        else:
            first = entry[0]
        raw_name = bytes([first]) + entry[1:8]
        name = raw_name.decode("ascii", errors="replace").rstrip()
        ext = entry[8:11].decode("ascii", errors="replace").rstrip()
        if deleted:
            name = "_" + name[1:]
        filename = f"{name}.{ext}" if ext else name
        attr = entry[11]
        if attr & 0x08 or attr & 0x10:  # volume label or directory
            continue
        cluster = struct.unpack_from("<H", entry, 26)[0]
        size = struct.unpack_from("<I", entry, 28)[0]
        data_offset = (data_start_sector + max(cluster - 2, 0)) * bps if cluster >= 2 else 0
        payload = disk[data_offset:data_offset+size] if cluster >= 2 else b""
        kind, expected_ext = identify_signature(payload[:16])
        mismatch = bool(expected_ext and ext and ("." + ext.lower()) != expected_ext)
        artifacts.append({
            "filename": filename, "deleted": deleted, "size": size,
            "cluster": cluster, "offset": data_offset, "payload": payload,
            "kind": kind, "mismatch": mismatch,
        })
    return disk, artifacts, bps, data_start_sector

def main():
    OUTPUT.mkdir(exist_ok=True)
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_IMAGE
    if not target.is_file():
        print(f"[ERROR] Evidence image not found: {target}")
        return 2
    try:
        disk, artifacts, bps, data_start = parse_fat12(target)
    except (ValueError, struct.error) as exc:
        print(f"[ERROR] {exc}")
        return 3

    print("=" * 90)
    print(" DIGITAL FORENSICS - FAT12 ARTIFACT & FILE SIGNATURE ANALYZER")
    print("=" * 90)
    print(f"Image: {target.name} | Sector size: {bps} | Data starts at sector: {data_start}")
    print(f"{'Filename':<30} {'Status':<20} {'Size':>8}  {'Detected type':<24} Mismatch")
    print("-" * 90)
    for item in artifacts:
        status = "DELETED (carvable)" if item["deleted"] else "ACTIVE"
        mismatch = "YES - ALERT" if item["mismatch"] else "No"
        print(f"{item['filename']:<30} {status:<20} {item['size']:>8}  {item['kind']:<24} {mismatch}")

    print("\n[FILE SIGNATURE CHECK]")
    for item in artifacts:
        if item["mismatch"]:
            print(f"Suspicious file: {item['filename']}")
            print(f"Actual type: {item['kind']}")
            print("First bytes (hex):", " ".join(f"{b:02X}" for b in item["payload"][:32]))
            print("ASCII preview:", "".join(chr(b) if 32 <= b < 127 else "." for b in item["payload"][:32]))

    print("\n[DELETED FILE CARVING]")
    recovered_any = False
    for item in artifacts:
        if item["deleted"] and item["payload"]:
            out = OUTPUT / f"RECOVERED_{item['filename']}"
            out.write_bytes(item["payload"])
            recovered_any = True
            print(f"Recovered: {item['filename']}")
            print(f"Cluster: {item['cluster']} | Byte offset: 0x{item['offset']:X} | Bytes: {len(item['payload'])}")
            print(f"Saved to: {out.relative_to(ROOT)}")
            print("Content preview:")
            print(item["payload"].decode("utf-8", errors="replace").rstrip())
    if not recovered_any:
        print("No deleted root-directory file entries with recoverable cluster data were found.")
    print("=" * 90)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
