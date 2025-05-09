@echo off
REM Ransomware File Scanner - GUI Launcher
REM This script runs the GUI version of the ransomware file scanner

echo Ransomware File Scanner - GUI Version
echo ====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python is not installed or not in the PATH.
    echo Please install Python 3.6 or later from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM Check if tkinter is available
python -c "import tkinter" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Tkinter is not available in your Python installation.
    echo Please install tkinter or use the command-line version instead.
    echo.
    echo You can run the command-line version with: run_scanner.bat
    echo.
    pause
    exit /b 1
)

REM Try to create icon if not exists
if not exist scanner.ico (
    echo Creating application icon...
    python -c "import os; os.system('pip install pillow -q') if not os.system('python -c \"import PIL\"') else None" >nul 2>&1
    python create_icon.py >nul 2>&1
)

REM Run the GUI scanner
echo Starting GUI Scanner...
echo.
start pythonw gui_scanner.py

echo GUI application started!
exit /b 0 