@echo off
title WinSecAgent

echo ========================================
echo   WinSecAgent Startup
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] Starting backend...
set "BACKEND_PYTHON=python"
if exist "backend\myenv\Scripts\python.exe" (
    backend\myenv\Scripts\python.exe -c "import fastapi, uvicorn, sqlalchemy" >nul 2>&1
    if not errorlevel 1 set "BACKEND_PYTHON=myenv\Scripts\python.exe"
)
start "WinSecAgent-Backend" cmd /k "cd backend && %BACKEND_PYTHON% run.py"

echo [Info] Waiting for backend to start (8s)...
timeout /t 8 /nobreak >nul

echo [2/2] Starting frontend...
start "WinSecAgent-Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ========================================
echo   Done!
echo   Backend:  http://127.0.0.1:8000
echo   Frontend: http://127.0.0.1:5173
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
