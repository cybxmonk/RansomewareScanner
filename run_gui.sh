#!/usr/bin/env bash
# Ransomware File Scanner - GUI Launcher
# This script runs the GUI version of the ransomware file scanner

echo "Ransomware File Scanner - GUI Version"
echo "===================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.6 or later from your package manager or https://www.python.org/downloads/"
    echo ""
    exit 1
fi

# Check if tkinter is available
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "Error: Tkinter is not available in your Python installation."
    echo "Please install tkinter or use the command-line version instead."
    echo ""
    echo "On Ubuntu/Debian: sudo apt-get install python3-tk"
    echo "On Fedora: sudo dnf install python3-tkinter"
    echo "On macOS: brew install python-tk"
    echo ""
    echo "You can run the command-line version with: ./run_scanner.sh"
    echo ""
    exit 1
fi

# Try to create icon if not exists
if [ ! -f "scanner.ico" ] && [ ! -f "scanner.png" ]; then
    echo "Creating application icon..."
    # Try to install Pillow if not available
    python3 -c "import PIL" &> /dev/null || pip3 install pillow -q
    python3 create_icon.py &> /dev/null
fi

# Run the GUI scanner
echo "Starting GUI Scanner..."
echo ""
python3 gui_scanner.py &

# Exit
echo "GUI application started!"
exit 0 