Set-Location $PSScriptRoot
Write-Host "`n[1/2] HASH GENERATION AND INTEGRITY VERIFICATION" -ForegroundColor Cyan
python .\scripts\forensic_hasher.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "`n[2/2] FAT12 ANALYSIS AND FILE CARVING" -ForegroundColor Cyan
python .\scripts\hex_analyzer.py
exit $LASTEXITCODE
