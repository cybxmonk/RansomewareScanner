# Ransomware File Scanner

A lightweight tool for detecting potential ransomware on your system. This scanner looks for common indicators of ransomware, including suspicious file extensions, malicious content patterns, and encrypted file characteristics.
![image](https://github.com/user-attachments/assets/f2ee6ebf-6b7b-406a-82c2-618b1a361a02)

![image](https://github.com/user-attachments/assets/6a2b5d29-6565-486f-8163-97b1db76885a)

## Features

- **Simple to use**: GUI interface and command-line tools included
- **No installation required**: Runs with standard Python libraries
- **Multiple detection methods**:
  - Known ransomware file extensions
  - Suspicious text content patterns
  - Entropy analysis for encrypted files
- **Cross-platform compatibility**: Works on Windows, macOS, and Linux

## Requirements

- Python 3.6 or later
- Tkinter (included with most Python installations)
- Pillow library (optional, only for icon creation)

## Getting Started

### GUI Version

1. Run the GUI scanner:
   ```
   python gui_scanner.py
   ```

2. Select a file or directory to scan
3. Configure scan options (optional)
4. Click "Start Scan"
5. View results in the Results List tab

### Command-Line Version

Scan a specific file:
```
python working_scanner.py suspicious_file.exe
```

Scan a directory recursively:
```
python working_scanner.py /path/to/directory -r
```

Scan with custom options:
```
python working_scanner.py /path/to/scan -r -s 50 -o results.json
```

### Quick Start Scripts

For Windows users:
```
run_scanner.bat
```

For macOS/Linux users:
```
./run_scanner.sh
```

## Files Included

- `working_scanner.py` - Core scanner functionality
- `gui_scanner.py` - Graphical user interface
- `run_scanner.bat` - Windows menu script
- `run_scanner.sh` - Linux/Mac menu script
- `create_icon.py` - Creates application icon (requires Pillow)
- `test_files/` - Sample files for testing

## Detection Methods

### File Extensions

The scanner checks for known ransomware extensions such as `.locky`, `.crypted`, `.wncry` (WannaCry), and many others.

### Content Analysis

The scanner examines file content for suspicious strings like "your files have been encrypted", "bitcoin", "ransom", "payment", "decrypt", etc.

### Entropy Analysis

High entropy (randomness) in file content can indicate encryption. The scanner performs a basic entropy analysis to detect potential encrypted files.

## Understanding Results

The scanner provides a confidence score for each detection:
- 70%: Known ransomware file extension detected
- 60%: Suspicious strings found in file content
- 50%: High entropy detected, indicating possible encryption

## Limitations

- This is a detection tool only, not a removal tool
- Cannot detect sophisticated ransomware that doesn't use known patterns
- May produce false positives on legitimate encrypted or compressed files
- Not a replacement for comprehensive antivirus software

## License

This tool is provided "as is" without warranty of any kind. Use at your own risk.

## Acknowledgments

This tool was created for educational and diagnostic purposes only. It is intended to help users identify potential ransomware but is not a substitute for professional security software. 
