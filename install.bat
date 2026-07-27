@echo off
REM SecureX Installation Script for Windows

echo ============================================
echo SecureX Installation
echo ============================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not installed or not in PATH
    exit /b 1
)

echo [1/4] Creating virtual environment...
python -m venv venv
if errorlevel 1 exit /b 1

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 exit /b 1

echo [3/4] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 exit /b 1

echo [4/4] Initializing system...
python main.py --init
if errorlevel 1 exit /b 1

echo.
echo ============================================
echo Installation Complete!
echo ============================================
echo.
echo To start the system:
echo   - CLI Mode: python main.py
echo   - Web Dashboard: python -c "from src.dashboard.app import app; app.run()"
echo.
pause
