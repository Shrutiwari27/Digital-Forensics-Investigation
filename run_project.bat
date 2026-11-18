@echo off
setlocal
cd /d "%~dp0"
title Digital Forensics Investigation - Demo
echo ============================================================
echo   DIGITAL FORENSICS INVESTIGATION - COMPLETE DEMO
echo ============================================================
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python was not found. Install Python 3 and enable PATH.
  pause
  exit /b 1
)
echo.
echo [1/2] HASH GENERATION AND INTEGRITY VERIFICATION
python scripts\forensic_hasher.py
if errorlevel 1 (
  echo [ERROR] Hashing tool failed.
  pause
  exit /b 1
)
echo.
echo [2/2] FAT12 ANALYSIS, SIGNATURE DETECTION AND FILE CARVING
python scripts\hex_analyzer.py
if errorlevel 1 (
  echo [ERROR] Hex analyzer failed.
  pause
  exit /b 1
)
echo.
echo ============================================================
echo Demo completed. Check the output folder for generated files.
echo ============================================================
pause
