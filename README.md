# Digital Forensics Investigation — Complete Runnable Lab Project

This is a self-contained, reproducible **training simulation** based on the structure and learning objectives in the supplied project report and viva guide.

## One-click run (Windows)

1. Extract the ZIP file.
2. Open the extracted `Digital_Forensics_Investigation_Complete` folder in VS Code.
3. Double-click `run_project.bat` (or run it from PowerShell).
4. The two Python tools execute in sequence and their output is saved in the terminal.

No third-party Python packages are required. Python 3.10+ is recommended.

## Project structure

- `evidence/suspect_device.dd` — synthetic 1.44 MB FAT12 training disk image.
- `evidence/MEMO_DISGUISED_IMAGE.TXT` — JPEG-signature training artifact with a misleading `.TXT` extension.
- `evidence/baseline_sha256.txt` — SHA-256 baseline generated for this exact included disk image.
- `scripts/forensic_hasher.py` — MD5, SHA-1, SHA-256, baseline verification, and avalanche demonstration.
- `scripts/hex_analyzer.py` — FAT12 root-directory inspection, magic-number detection, and deleted-file recovery.
- `output/` — generated tampered copy and recovered artifacts.
- `chain_of_custody_template.csv` — editable evidence-handling log.

## Run from PowerShell

From this folder:
```powershell
python .\scripts\forensic_hasher.py
python .\scripts\hex_analyzer.py
```
Or run both:
```powershell
.\run_project.bat
```

## Important forensic notes

- This package contains **synthetic training evidence**, not a real seized USB image.
- The included `suspect_device.dd` is generated locally for repeatable demonstration. Its baseline is therefore specific to this included file; it is not the same as a hash claimed in an earlier report unless the bytes are identical.
- The hash tool never modifies `evidence/suspect_device.dd`. It flips one bit only in a separate copy under `output/`.
- The FAT12 carver demonstrates recovery from a deleted root-directory entry whose data cluster has not been overwritten. It is a teaching implementation, not a full commercial forensic suite.
- HxD is optional and external. Open `evidence/suspect_device.dd` or `evidence/MEMO_DISGUISED_IMAGE.TXT` in HxD for manual hex inspection. Do not edit/save the evidence in HxD.
- Do not present generated synthetic data as a real-world acquisition or claim that a hardware write blocker/FTK Imager was used unless that was actually done.

## Screenshots for your report/demo

1. Project folder expanded in VS Code.
2. `run_project.bat` terminal showing hash generation and baseline match.
3. Avalanche-effect output showing original and modified SHA-256.
4. Hex analyzer output showing `.TXT` extension vs JPEG signature.
5. Deleted-file carving output and `output/RECOVERED__LIENTS.CSV`.
6. HxD view of the disk image boot sector.
7. HxD view of `MEMO_DISGUISED_IMAGE.TXT` showing `FF D8 FF E0` and `JFIF`.
8. HxD view of the recovered CSV file.

## Troubleshooting

- If `python` is not recognized, install Python and enable “Add Python to PATH”, then reopen the terminal.
- Run commands from the extracted project root, not from inside `scripts` or `evidence`.
- If PowerShell blocks a batch file, run `python .\scripts\forensic_hasher.py` and `python .\scripts\hex_analyzer.py` separately.
