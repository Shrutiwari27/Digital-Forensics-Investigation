#!/usr/bin/env python3
"""Chunked forensic hashing, baseline verification, and safe avalanche-effect demo."""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
OUTPUT = ROOT / "output"
DEFAULT_IMAGE = EVIDENCE / "suspect_device.dd"

def calculate_hashes(path, chunk_size=65536):
    path = Path(path)
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            for digest in digests.values():
                digest.update(chunk)
    return {
        "file": path.name,
        "size": path.stat().st_size,
        **{name: digest.hexdigest() for name, digest in digests.items()},
    }

def bit_difference(hex_a, hex_b):
    return (int(hex_a, 16) ^ int(hex_b, 16)).bit_count()

def main():
    OUTPUT.mkdir(exist_ok=True)
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_IMAGE
    if not target.is_file():
        print(f"[ERROR] Evidence image not found: {target}")
        print("Run run_project.bat from the extracted project folder.")
        return 2

    results = calculate_hashes(target)
    baseline_file = EVIDENCE / "baseline_sha256.txt"
    baseline = baseline_file.read_text(encoding="utf-8").strip() if baseline_file.exists() else ""
    match = bool(baseline) and results["sha256"].lower() == baseline.lower()

    print("=" * 72)
    print(" DIGITAL FORENSICS - HASH & INTEGRITY VERIFICATION")
    print("=" * 72)
    print(f"Evidence file : {results['file']}")
    print(f"Size (bytes)  : {results['size']}")
    print(f"MD5           : {results['md5']}")
    print(f"SHA-1         : {results['sha1']}")
    print(f"SHA-256       : {results['sha256']}")
    print("-" * 72)
    print(f"Baseline SHA-256: {baseline or '[not available]'}")
    print("[VERIFICATION] INTEGRITY INTACT - baseline matches." if match
          else "[VERIFICATION] WARNING - baseline missing or hash mismatch.")
    print("-" * 72)

    # Never alter the evidence image: create a separate working copy in output/.
    tampered = OUTPUT / "suspect_device_tampered_demo.dd"
    data = bytearray(target.read_bytes())
    if len(data) <= 1024:
        print("[ERROR] Image is too small for the offset-1024 demonstration.")
        return 3
    original_hash = results["sha256"]
    data[1024] ^= 0x01
    tampered.write_bytes(data)
    changed = calculate_hashes(tampered)["sha256"]
    diff = bit_difference(original_hash, changed)
    print("[AVALANCHE EFFECT - ONE BIT FLIPPED IN A SEPARATE COPY]")
    print(f"Original SHA-256 : {original_hash}")
    print(f"Modified SHA-256 : {changed}")
    print(f"Digest bits changed: {diff}/256 ({diff / 256 * 100:.1f}%)")
    print(f"Modified copy saved: {tampered.relative_to(ROOT)}")
    print("=" * 72)
    print("NOTE: The original evidence image was not modified.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
