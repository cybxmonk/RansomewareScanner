#!/usr/bin/env python3
"""
Analyze the ransomware sample to extract key characteristics for detection.
"""

import os
import sys
import math
import binascii
import hashlib
import logging
import re
from collections import Counter

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    counts = Counter(data)
    for count in counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

def extract_strings(data, min_length=4):
    """Extract printable strings from binary data"""
    printable = set(bytes(range(32, 127)))
    result = []
    current = []
    
    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        elif current:
            if len(current) >= min_length:
                result.append(''.join(current))
            current = []
    
    if current and len(current) >= min_length:
        result.append(''.join(current))
    
    return result

def analyze_file(file_path):
    """Analyze the file and print detailed information"""
    try:
        file_size = os.path.getsize(file_path)
        logger.info(f"File: {file_path}")
        logger.info(f"Size: {file_size} bytes")
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Calculate hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        logger.info(f"MD5: {md5_hash}")
        logger.info(f"SHA1: {sha1_hash}")
        logger.info(f"SHA256: {sha256_hash}")
        
        # Calculate entropy
        entropy = calculate_entropy(content)
        logger.info(f"Entropy: {entropy:.4f} (0-8 scale, >7.5 suggests encryption/compression)")
        
        # Extract header information (first 1024 bytes)
        header = content[:1024]
        header_hex = binascii.hexlify(header).decode('ascii')
        logger.info(f"File header (hex): {header_hex[:100]}...")
        
        # Check if it's a PE file (Windows executable)
        is_pe = content.startswith(b'MZ')
        if is_pe:
            logger.info("File is a Windows executable (PE format)")
            # Try to extract PE header info
            pe_offset_bytes = content[0x3C:0x40]
            if len(pe_offset_bytes) == 4:
                pe_offset = int.from_bytes(pe_offset_bytes, byteorder='little')
                logger.info(f"PE header offset: 0x{pe_offset:X}")
                
                # Check for PE signature
                if len(content) > pe_offset + 4 and content[pe_offset:pe_offset+4] == b'PE\0\0':
                    logger.info("PE signature found")
        
        # Extract strings
        strings = extract_strings(content)
        interesting_strings = []
        patterns_of_interest = [
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',  # URLs
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',  # Email addresses
            r'encrypt',
            r'decrypt',
            r'ransom',
            r'bitcoin',
            r'payment',
            r'\.onion',
            r'tor',
            r'key',
            r'password',
            r'registry',
            r'dll',
            r'exe',
            r'cmd',
            r'powershell',
            r'base64',
            r'RSA',
            r'AES',
            r'crypt',
            r'(\.[a-zA-Z0-9]{3,5}$)',  # File extensions
            r'command',
            r'payload',
            r'victim',
            r'attack'
        ]
        
        pattern = '|'.join(patterns_of_interest)
        for s in strings:
            if re.search(pattern, s, re.IGNORECASE):
                interesting_strings.append(s)
        
        logger.info(f"Total extracted strings: {len(strings)}")
        logger.info(f"Interesting strings found: {len(interesting_strings)}")
        
        # Print most interesting strings (limiting to 50)
        if interesting_strings:
            logger.info("Notable strings:")
            for i, s in enumerate(interesting_strings[:50], 1):
                logger.info(f"{i}. {s}")
        
        # Analyze byte frequency
        byte_freq = Counter(content)
        most_common_bytes = byte_freq.most_common(10)
        least_common_bytes = byte_freq.most_common()[:-11:-1]
        
        logger.info("Most common bytes:")
        for byte, count in most_common_bytes:
            logger.info(f"Byte 0x{byte:02X}: {count} occurrences ({count/len(content)*100:.2f}%)")
        
        logger.info("Least common bytes:")
        for byte, count in least_common_bytes:
            logger.info(f"Byte 0x{byte:02X}: {count} occurrences ({count/len(content)*100:.2f}%)")
        
        # Check for sections of high entropy (potential encrypted/compressed data)
        section_size = min(4096, file_size // 10)  # Analyze in reasonably sized chunks
        high_entropy_sections = []
        
        for i in range(0, len(content), section_size):
            section = content[i:i+section_size]
            if len(section) > 100:  # Only analyze reasonably sized sections
                section_entropy = calculate_entropy(section)
                if section_entropy > 7.5:
                    high_entropy_sections.append((i, i+len(section), section_entropy))
        
        if high_entropy_sections:
            logger.info(f"Found {len(high_entropy_sections)} high-entropy sections (possible encrypted/compressed data):")
            for start, end, entropy in high_entropy_sections[:5]:  # Show first 5 only
                logger.info(f"Bytes {start}-{end}: entropy {entropy:.4f}")
        
        # Return a summary of findings that might be useful for detection
        return {
            "file_size": file_size,
            "entropy": entropy,
            "is_pe": is_pe,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "interesting_strings": interesting_strings,
            "high_entropy_sections": high_entropy_sections
        }
        
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Error: File not found - {file_path}")
        sys.exit(1)
    
    print(f"Analyzing file: {file_path}")
    results = analyze_file(file_path) 