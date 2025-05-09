#!/usr/bin/env python3
"""
Ransomware File Scanner - Minimal Version
-----------------------------------------
A standalone scanner using only standard library modules to scan files and directories
for potential ransomware indicators.
"""

import os
import sys
import time
import datetime
import argparse
import json
import math
from pathlib import Path

# Program information
VERSION = "1.0.0"
PROGRAM_NAME = "Ransomware File Scanner"

# Known ransomware file extensions
RANSOMWARE_EXTENSIONS = [
    '.locky', '.cerber', '.crypto', '.cryptolocker', '.cryptowall', '.crypt', 
    '.encrypted', '.ezz', '.ecc', '.exx', '.enc', '.locked', '.vault', '.petya',
    '.crypted', '.cryp1', '.crypz', '.wncry', '.wncryt', '.wcry', '.wncrypt',
    '.zepto', '.thor', '.rokku', '.sage', '.bart', '.good', '.globe', '.aaa',
    '.abc', '.btc', '.ccc', '.combo', '.ctb', '.zzz', '.xxx', '.ttt', '.micro',
    '.krab', '.crysis', '.lock', '.dharma', '.arena', '.java', '.coverton',
    '.disappeared', '.atlas', '.vxlock', '.breaking_bad', '.evil', '.crime',
    '.write', '.id-', '.vscrypt', '.tzu', '.thanos', '.gd0', '.1txt', '.73i87A',
    '.aesir', '.alcatraz', '.amba', '.antonyn', '.armageddon', '.aurora123', '.better_call_saul',
    '.bitpaymer', '.blackout', '.blackrouter', '.bonsoir', '.borr', '.brr', '.canihelpyou',
    '.cancer', '.chernobyl', '.clop', '.cobra', '.code', '.comrade', '.cypher',
    '.czzz', '.d4nm', '.darkness', '.deadbolt', '.deuscrypt', '.donut', '.doppelpaymer',
    '.dotexe', '.edgehaha', '.emailcrypt', '.encoderpass', '.enigma', '.exotic', '.exploit',
    '.fantom', '.file0locked', '.fortune', '.freearmy', '.frtrss', '.ftcode', '.fury',
    '.gccc', '.gdcb', '.goodgame', '.gpgqwerty', '.gretas', '.gusau', '.haircut',
    '.hakunamatata', '.horriblemorning', '.hush', '.hyperion', '.idqdecrypt',
    '.isis', '.iwanthelpuuu', '.iwanttits', '.jaff', '.josef', '.keypass', '.kgpvwnr',
    '.killedxxx', '.kimcilware', '.kirk', '.kk', '.kkk', '.kokos', '.kostya',
    '.kraken', '.kratos', '.kyra', '.lcxker', '.legion', '.linda', '.lovewindows',
    '.lol!', '.loptr', '.lucifer', '.matrix', '.maze', '.medusa', '.memz', '.merry',
    '.mobef', '.moby', '.moscow', '.mransom', '.mole', '.neitrino', '.nemucode',
    '.nemucod', '.noobcrypt', '.nochance', '.nuke', '.odcodc', '.odin', '.omg!',
    '.onion', '.oops', '.osiris', '.p5tkjw', '.padcrypt', '.pandemic', '.pay2key',
    '.payday', '.pec', '.phobos', '.piasa', '.popcorn', '.purge', '.pysa', '.qinynore',
    '.qwerty', '.r16m01d05', '.radamant', '.raid', '.ransomware', '.rare1',
    '.razels', '.razy', '.rekt', '.relock', '.reyptson', '.rip', '.rnsmwr', '.rokku',
    '.ruby', '.sage', '.serpent', '.sexy', '.shino', '.shit', '.shrug', '.sifreli',
    '.space', '.sparta', '.surprise', '.syrk', '.termite', '.teslacrypt', '.truke',
    '.unlocker', '.venusf', '.venusp', '.victim', '.vindows', '.viruscrypt',
    '.visioncrypt', '.vnlocked', '.weencedufiles', '.wflx', '.windows10',
    '.windows_debug_error', '.xort', '.xrtn', '.yourransom', '.zeppelin', '.zilla',
    '.zorab', '.zorro', '.zyklon'
]

# Common ransomware strings
RANSOMWARE_STRINGS = [
    'your files have been encrypted',
    'your important files encryption produced',
    'your documents, photos, databases and other',
    'to decrypt your files, you need to buy',
    'send email with your key',
    'your files are now encrypted',
    'your files will be lost',
    'for decrypt files',
    'your files are encrypted',
    'all files on your computer has been',
    'all of your files are encrypted',
    'how to recover files',
    'your personal files are encrypted',
    'to unlock files you need',
    'ransom',
    'bitcoin',
    'btc',
    'payment',
    'decrypt',
    'decrypt files',
    'private key'
]

def format_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def analyze_file(file_path, max_file_size_mb=100):
    """
    Enhanced file analysis with multiple detection techniques.
    
    Args:
        file_path: Path to the file to analyze
        max_file_size_mb: Maximum file size to analyze in MB
        
    Returns:
        dict: Analysis results
    """
    max_size_bytes = max_file_size_mb * 1024 * 1024
    results = {
        'file_path': file_path,
        'size': 0,
        'detection_type': None,
        'confidence': 0,
        'indicators': [],
        'is_suspicious': False
    }
    
    try:
        file_size = os.path.getsize(file_path)
        results['size'] = file_size
        
        # Skip large files
        if file_size > max_size_bytes:
            results['indicators'].append(f"File too large to scan: {format_size(file_size)}")
            return results
            
        # Check file extension
        _, ext = os.path.splitext(file_path.lower())
        if ext in RANSOMWARE_EXTENSIONS:
            results['is_suspicious'] = True
            results['detection_type'] = 'Extension'
            results['confidence'] = 80
            results['indicators'].append(f"Known ransomware extension: {ext}")
            
        # Analyze file content for suspicious patterns
        suspicious_patterns = [
            b'ransom',
            b'decrypt',
            b'bitcoin',
            b'payment',
            b'encrypt',
            b'.onion',
            b'tor browser',
            b'Your files have been encrypted',
            b'pay',
            b'btc',
            b'wallet',
            b'restore files',
            b'recover files',
            b'unlock',
            b'private key',
            b'timer',
            b'deadline',
            b'victim',
            b'untrusted',
            b'demand',
            b'contact us',
            b'README.txt',
            b'DECRYPT.txt',
            b'HOW_TO_DECRYPT',
            b'YOUR_FILES',
            b'IMPORTANT_READ_ME',
            b'INSTRUCTION',
            b'RECOVERY',
            b'warning',
            b'attention',
            b'all your data',
            b'permanently deleted',
            b'money',
            b'cryptocurrency',
            b'monero',
            b'xmr',
            b'ethereum',
            b'eth',
            b'tether',
            b'usdt',
            b'telegram',
            b'email',
        ]
        
        # Check if file is binary or PE executable
        is_binary = False
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                # Check for PE header (Windows executable)
                if header.startswith(b'MZ'):
                    is_binary = True
                    results['indicators'].append("Executable file (PE format)")
        except Exception as e:
            results['indicators'].append(f"Error checking file header: {str(e)}")
        
        # Read file content for analysis
        try:
            with open(file_path, 'rb') as f:
                # For binary files, read the whole file for entropy calculation
                # but only scan headers and certain sections for text patterns
                if is_binary:
                    content = f.read(min(file_size, 5 * 1024 * 1024))  # Read up to 5MB for binary files
                    
                    # For PE files, focus on specific sections where strings might be stored
                    pattern_matches = 0
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            pattern_matches += 1
                    
                    if pattern_matches >= 3:
                        results['is_suspicious'] = True
                        results['indicators'].append(f"Found {pattern_matches} suspicious patterns in binary")
                        if results['detection_type'] is None:
                            results['detection_type'] = 'Content'
                            results['confidence'] = min(60 + (pattern_matches * 3), 95)
                else:
                    # For text files, read the whole file
                    content = f.read(min(file_size, 1 * 1024 * 1024))  # Read up to 1MB for text files
                    
                    pattern_matches = 0
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            pattern_matches += 1
                            if pattern_matches <= 5:  # Only list first 5 matches
                                results['indicators'].append(f"Found suspicious text: '{pattern.decode('utf-8', errors='ignore')}'")
                    
                    if pattern_matches >= 2:
                        results['is_suspicious'] = True
                        if results['detection_type'] is None:
                            results['detection_type'] = 'Content'
                            results['confidence'] = min(50 + (pattern_matches * 5), 95)
                
                # Calculate entropy (randomness) of file content
                # High entropy can indicate encrypted content
                if len(content) > 0:
                    entropy = calculate_entropy(content)
                    results['indicators'].append(f"File entropy: {entropy:.2f}")
                    
                    # Typical ransomware encrypted files have very high entropy
                    if entropy > 7.8:
                        results['is_suspicious'] = True
                        if results['detection_type'] is None:
                            results['detection_type'] = 'Entropy'
                            results['confidence'] = min(int((entropy - 7.0) * 60), 90)
                        results['indicators'].append("Very high entropy: likely encrypted content")
                    elif entropy > 7.0:
                        if results['detection_type'] is None:
                            results['detection_type'] = 'Entropy'
                            results['confidence'] = int((entropy - 6.5) * 40)
                        results['indicators'].append("High entropy: possibly encrypted or compressed content")
                
        except Exception as e:
            results['indicators'].append(f"Error analyzing file content: {str(e)}")
        
        # Add heuristic analysis for filenames
        filename = os.path.basename(file_path).lower()
        suspicious_filename_patterns = [
            'decrypt', 'ransom', 'how_to_decrypt', 'your_files', 'recover', 
            'readme', 'help_me', 'help_decrypt', 'how_to_recover', 'your_data',
            'important', 'warning', 'attention', 'instruction', 'read_me'
        ]
        
        for pattern in suspicious_filename_patterns:
            if pattern in filename:
                results['is_suspicious'] = True
                results['indicators'].append(f"Suspicious filename pattern: '{pattern}'")
                if results['detection_type'] is None:
                    results['detection_type'] = 'Filename'
                    results['confidence'] = 70
        
        # If file is suspicious but no indicators were found, add a generic message
        if results['is_suspicious'] and not results['indicators']:
            results['indicators'].append("File detected as suspicious (generic detection)")
            
        # If no detection was made but we have indicators, set a low confidence
        if not results['is_suspicious'] and results['indicators']:
            if len(results['indicators']) >= 3:
                results['is_suspicious'] = True
                results['detection_type'] = 'Heuristic'
                results['confidence'] = 40
                results['indicators'].append("Multiple minor indicators detected")
        
    except Exception as e:
        results['indicators'].append(f"Error analyzing file: {str(e)}")
    
    return results

# Helper function to calculate Shannon entropy
def calculate_entropy(data):
    """Calculate the Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def scan_directory(directory, recursive=True, size_limit_mb=100, excluded_dirs=None):
    """
    Scan a directory for ransomware.
    
    Args:
        directory (str): Directory to scan
        recursive (bool): Whether to scan subdirectories
        size_limit_mb (int): Maximum file size to analyze in MB
        excluded_dirs (list): List of directories to exclude
        
    Returns:
        dict: Scan results
    """
    if not os.path.exists(directory):
        print(f"[!] Error: Directory {directory} does not exist")
        return {"error": "Directory not found"}
        
    if not os.path.isdir(directory):
        print(f"[!] Error: {directory} is not a directory")
        return {"error": "Not a directory"}
    
    # Initialize variables
    excluded_dirs = excluded_dirs or []
    files_scanned = 0
    suspicious_files = []
    start_time = time.time()
    errors = []
    
    print(f"\n[*] Starting scan of {directory} (recursive: {recursive})")
    print(f"[*] Size limit: {size_limit_mb}MB, Excluded dirs: {', '.join(excluded_dirs) or 'None'}")
    
    # Walk through directory
    try:
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in excluded_dirs]
            
            # Process files
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Basic check before full analysis
                    if os.path.getsize(file_path) > size_limit_mb * 1024 * 1024:
                        print(f"[*] Skipping large file: {file_path}")
                        continue
                    
                    # Scan file
                    result = analyze_file(file_path, size_limit_mb)
                    files_scanned += 1
                    
                    # Check if suspicious
                    if result.get("is_suspicious"):
                        suspicious_files.append(result)
                except Exception as e:
                    print(f"[!] Error processing {file_path}: {str(e)}")
                    errors.append({"file": file_path, "error": str(e)})
            
            # Stop if not recursive
            if not recursive:
                break
    except Exception as e:
        print(f"[!] Error scanning directory: {str(e)}")
        errors.append({"directory": directory, "error": str(e)})
    
    # Calculate scan time
    elapsed_time = time.time() - start_time
    
    # Print summary
    print("\n" + "="*60)
    print(f"Scan Summary:")
    print(f"- Directory: {directory}")
    print(f"- Files scanned: {files_scanned}")
    print(f"- Suspicious files: {len(suspicious_files)}")
    print(f"- Elapsed time: {elapsed_time:.2f} seconds")
    print(f"- Errors encountered: {len(errors)}")
    
    if suspicious_files:
        print("\nSuspicious Files:")
        for i, file in enumerate(suspicious_files, 1):
            print(f"{i}. {file.get('file_path')}")
            print(f"   - Detection method: {file.get('detection_type', 'Unknown')}")
            print(f"   - Confidence: {file.get('confidence', 0)*100:.0f}%")
            print(f"   - Indicators: {', '.join(file.get('indicators', []))[:100]}")
    
    return {
        "directory": directory,
        "files_scanned": files_scanned,
        "suspicious_files": suspicious_files,
        "elapsed_time": elapsed_time,
        "errors": errors
    }

def main():
    """Main entry point for the program"""
    # Create argument parser
    parser = argparse.ArgumentParser(
        description=f"{PROGRAM_NAME} v{VERSION} - Scans files and directories for ransomware indicators")
    
    # Add arguments
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Scan directory recursively")
    parser.add_argument("-s", "--size-limit", type=int, default=100, help="Maximum file size to analyze in MB (default: 100)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-e", "--exclude", nargs="*", help="Directories to exclude from scanning")
    
    # Parse arguments
    args = parser.parse_args()
    
    print(f"\n{PROGRAM_NAME} v{VERSION}")
    print("-" * len(f"{PROGRAM_NAME} v{VERSION}"))
    
    # Scan file or directory
    if os.path.isfile(args.path):
        result = analyze_file(args.path, args.size_limit)
    elif os.path.isdir(args.path):
        result = scan_directory(args.path, args.recursive, args.size_limit, args.exclude)
    else:
        print(f"[!] Error: {args.path} does not exist")
        return 1
    
    # Save results to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Error saving results: {str(e)}")
    
    # Return exit code based on results
    if "error" in result:
        return 1
    if result.get("is_suspicious", False) or (
        "suspicious_files" in result and len(result["suspicious_files"]) > 0
    ):
        return 100  # Custom exit code for suspicious files
    return 0  # Everything normal

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"\n[!] Unhandled error: {str(e)}")
        traceback.print_exc()
        sys.exit(1) 