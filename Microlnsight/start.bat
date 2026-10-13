@echo off
setlocal
title Microlnsight
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (
    echo Python 3.10+ is required. See README.md.
    pause
    exit /b 1
)
python -X utf8 dev.py %*
set "MICROLNSIGHT_EXIT=%ERRORLEVEL%"
if not "%MICROLNSIGHT_EXIT%"=="0" pause
exit /b %MICROLNSIGHT_EXIT%
