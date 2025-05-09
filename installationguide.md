# Installation Guide: Ransomware Detection System

This guide will help you install and set up the Ransomware Detection System.

## Prerequisites

Before installing, make sure you have the following:

- Python 3.7 or newer
- Git
- Internet connection for downloading the repository and dependencies
- Operating System: Windows, Linux, or macOS

## Installation Steps

### 1. Clone the Repository

Open a terminal or command prompt and run:

```bash
git clone https://github.com/cybxmonk/ransomeware_scanner.git
cd ransomeware_scanner
```

### 2. Set Up a Virtual Environment (Recommended)

#### Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

#### Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

For full functionality including optional features:
```bash
pip install -r requirements-full.txt
```

### 4. Configure the Application

The application should work out of the box with default settings, but you can customize it by editing the configuration files in the `data` directory.

## Running the Application

### Using the Graphical User Interface (GUI)

#### Windows:
```bash
run_gui.bat
```
Or directly:
```bash
python gui_scanner.py
```

#### Linux/macOS:
```bash
./run_gui.sh
```
Or directly:
```bash
python3 gui_scanner.py
```

### Using the Command Line Interface

#### Windows:
```bash
run_scanner.bat [file_or_directory_path]
```
Or directly:
```bash
python working_scanner.py [file_or_directory_path]
```

#### Linux/macOS:
```bash
./run_scanner.sh [file_or_directory_path]
```
Or directly:
```bash
python3 working_scanner.py [file_or_directory_path]
```

## Features

- **File Scanning**: Scan individual files for ransomware indicators
- **Directory Scanning**: Recursively scan entire directories
- **Real-time Detection**: Monitor directories for new files in real-time
- **Reporting**: Generate detailed reports of scan results
- **Custom Rules**: Add your own YARA rules for enhanced detection

## Troubleshooting

### Missing Dependencies

If you encounter errors about missing modules, try installing the full requirements:
```bash
pip install -r requirements-full.txt
```

### Permission Issues

On Linux/macOS, you might need to make the shell scripts executable:
```bash
chmod +x run_gui.sh run_scanner.sh
```

### Application Crashes

1. Check the log files in the `logs` directory for error details
2. Make sure all dependencies are correctly installed
3. Verify that the `rules` directory exists and contains YARA rules
4. Ensure your Python version is compatible (3.7+)

## Building from Source

If you want to build the application from source:

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Run the build script:
   ```bash
   python build_executable.py
   ```

3. Find the executable in the `dist` directory

## Additional Resources

- Check the `README.md` file for more detailed information
- Consult the documentation in the `docs` directory

## Support

For support, please open an issue on the GitHub repository or contact the developer.

---

Thank you for using the Ransomware Detection System. Stay secure! 