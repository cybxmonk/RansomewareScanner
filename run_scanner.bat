@echo off
REM Ransomware File Scanner Batch Script for Windows
REM 
REM This script helps Windows users run the working_scanner.py file
REM to scan files and directories for potential ransomware.

echo Ransomware File Scanner
echo ======================
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

:menu
echo Choose an option:
echo 1. Scan a specific file
echo 2. Scan a specific folder
echo 3. Scan current folder
echo 4. Exit
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto scan_file
if "%choice%"=="2" goto scan_folder
if "%choice%"=="3" goto scan_current
if "%choice%"=="4" goto end

echo Invalid choice. Please try again.
echo.
goto menu

:scan_file
echo.
set /p file_path="Enter the full path of the file to scan: "
if not exist "%file_path%" (
    echo File not found. Please check the path and try again.
    echo.
    goto menu
)

echo.
echo Scanning file: %file_path%
python working_scanner.py "%file_path%"
echo.
pause
goto menu

:scan_folder
echo.
set /p folder_path="Enter the full path of the folder to scan: "
if not exist "%folder_path%" (
    echo Folder not found. Please check the path and try again.
    echo.
    goto menu
)

echo.
set /p recursive="Scan recursively? (y/n): "
set /p size_limit="Maximum file size to scan in MB (default 100): "

if not defined size_limit set size_limit=100

echo.
echo Scanning folder: %folder_path%
if /i "%recursive%"=="y" (
    python working_scanner.py "%folder_path%" -r -s %size_limit%
) else (
    python working_scanner.py "%folder_path%" -s %size_limit%
)
echo.
pause
goto menu

:scan_current
echo.
set /p recursive="Scan recursively? (y/n): "
set /p size_limit="Maximum file size to scan in MB (default 100): "

if not defined size_limit set size_limit=100

echo.
echo Scanning current folder
if /i "%recursive%"=="y" (
    python working_scanner.py . -r -s %size_limit%
) else (
    python working_scanner.py . -s %size_limit%
)
echo.
pause
goto menu

:end
echo Thank you for using the Ransomware File Scanner.
echo Goodbye!
exit /b 0 