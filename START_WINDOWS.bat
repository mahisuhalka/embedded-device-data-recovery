@echo off
setlocal enabledelayedexpansion
title EDRT v5 — Data ka BHOOT

:: ── Check for admin rights ──────────────────────────────
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ── Header ──────────────────────────────────────────────
cls
echo.
echo  ================================================
echo    EDRT v5 — External Data Recovery Tool
echo    Team: Data ka BHOOT  ^|  SW-5
echo    Running as ADMINISTRATOR
echo  ================================================
echo.

:: ── Move to script directory ─────────────────────────────
cd /d "%~dp0"

:: ── Check Python ─────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% NEQ 0 (
    echo  [ERROR] Python not found!
    echo  Please install Python 3.8+ from https://python.org
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

:: ── Install dependencies ──────────────────────────────────
echo  Installing / verifying dependencies...
pip install flask psutil --quiet --disable-pip-version-check
echo  Dependencies OK.
echo.

:: ── Open browser after 2-second delay ────────────────────
echo  Starting server...
echo  Browser will open automatically at http://localhost:5000
echo.
start "" /b powershell -WindowStyle Hidden -Command "Start-Sleep 2; Start-Process 'http://localhost:5000'"

:: ── Start Flask ───────────────────────────────────────────
python -B app.py

echo.
echo  Server stopped.
pause
