#!/usr/bin/env bash
# Ransomware File Scanner Shell Script for Linux/Mac
# 
# This script helps Linux and macOS users run the working_scanner.py file
# to scan files and directories for potential ransomware.

echo "Ransomware File Scanner"
echo "======================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.6 or later from your package manager or https://www.python.org/downloads/"
    echo ""
    exit 1
fi

show_menu() {
    echo "Choose an option:"
    echo "1. Scan a specific file"
    echo "2. Scan a specific folder"
    echo "3. Scan current folder"
    echo "4. Exit"
    echo ""
}

scan_file() {
    echo ""
    read -p "Enter the full path of the file to scan: " file_path
    
    if [ ! -f "$file_path" ]; then
        echo "File not found. Please check the path and try again."
        echo ""
        return
    fi
    
    echo ""
    echo "Scanning file: $file_path"
    python3 working_scanner.py "$file_path"
    echo ""
    read -p "Press Enter to continue..."
}

scan_folder() {
    echo ""
    read -p "Enter the full path of the folder to scan: " folder_path
    
    if [ ! -d "$folder_path" ]; then
        echo "Folder not found. Please check the path and try again."
        echo ""
        return
    fi
    
    echo ""
    read -p "Scan recursively? (y/n): " recursive
    read -p "Maximum file size to scan in MB (default 100): " size_limit
    
    if [ -z "$size_limit" ]; then
        size_limit=100
    fi
    
    echo ""
    echo "Scanning folder: $folder_path"
    if [ "$recursive" = "y" ] || [ "$recursive" = "Y" ]; then
        python3 working_scanner.py "$folder_path" -r -s "$size_limit"
    else
        python3 working_scanner.py "$folder_path" -s "$size_limit"
    fi
    echo ""
    read -p "Press Enter to continue..."
}

scan_current() {
    echo ""
    read -p "Scan recursively? (y/n): " recursive
    read -p "Maximum file size to scan in MB (default 100): " size_limit
    
    if [ -z "$size_limit" ]; then
        size_limit=100
    fi
    
    echo ""
    echo "Scanning current folder"
    if [ "$recursive" = "y" ] || [ "$recursive" = "Y" ]; then
        python3 working_scanner.py . -r -s "$size_limit"
    else
        python3 working_scanner.py . -s "$size_limit"
    fi
    echo ""
    read -p "Press Enter to continue..."
}

# Main menu loop
while true; do
    show_menu
    read -p "Enter your choice (1-4): " choice
    
    case $choice in
        1) scan_file ;;
        2) scan_folder ;;
        3) scan_current ;;
        4) 
            echo "Thank you for using the Ransomware File Scanner."
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please try again."
            echo ""
            ;;
    esac
done 