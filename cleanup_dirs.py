#!/usr/bin/env python3
"""
Enhanced cleanup script to remove unnecessary files and directories from the Ransomware Scanner project.
"""

import os
import shutil
import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Essential files to keep
ESSENTIAL_FILES = [
    'working_scanner.py',
    'gui_scanner.py',
    'cleanup.py',
    'cleanup_dirs.py',
    'create_icon.py',
    'scanner.ico',
    'scanner.png',
    'run_gui.bat',
    'run_gui.sh',
    'run_scanner.bat',
    'run_scanner.sh',
    'LICENSE',
    'README.md'
]

# Essential directories to keep
ESSENTIAL_DIRECTORIES = [
    'test_files',
    'rules',
    'logs'
]

# Directories that can be cleaned up
def clean_directory(root_dir):
    """Remove unnecessary directories and files."""
    force_mode = '--force' in sys.argv
    
    logger.info(f"Starting cleanup in {root_dir}")
    
    # Check if test_files directory exists, create if not
    test_files_dir = os.path.join(root_dir, 'test_files')
    if not os.path.exists(test_files_dir):
        os.makedirs(test_files_dir)
        logger.info(f"Created directory: {test_files_dir}")
    
    # Delete unnecessary directories
    dirs_to_remove = []
    for item in os.listdir(root_dir):
        item_path = os.path.join(root_dir, item)
        if os.path.isdir(item_path) and item not in ESSENTIAL_DIRECTORIES:
            dirs_to_remove.append(item_path)
    
    if dirs_to_remove:
        logger.info(f"Found {len(dirs_to_remove)} directories to remove:")
        for dir_path in dirs_to_remove:
            logger.info(f"  - {dir_path}")
        
        if force_mode or input("Proceed with directory removal? (y/n): ").lower() == 'y':
            for dir_path in dirs_to_remove:
                try:
                    shutil.rmtree(dir_path)
                    logger.info(f"Removed directory: {dir_path}")
                except Exception as e:
                    logger.error(f"Failed to remove {dir_path}: {e}")
    
    # Delete unnecessary files
    files_to_remove = []
    for item in os.listdir(root_dir):
        item_path = os.path.join(root_dir, item)
        if os.path.isfile(item_path) and item not in ESSENTIAL_FILES:
            files_to_remove.append(item_path)
    
    if files_to_remove:
        logger.info(f"Found {len(files_to_remove)} files to remove:")
        for file_path in files_to_remove:
            logger.info(f"  - {file_path}")
        
        if force_mode or input("Proceed with file removal? (y/n): ").lower() == 'y':
            for file_path in files_to_remove:
                try:
                    os.remove(file_path)
                    logger.info(f"Removed file: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to remove {file_path}: {e}")
    
    # Create essential directories if missing
    for dir_name in ESSENTIAL_DIRECTORIES:
        dir_path = os.path.join(root_dir, dir_name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            logger.info(f"Created essential directory: {dir_path}")
    
    logger.info("Cleanup completed successfully")

if __name__ == "__main__":
    clean_directory(os.path.dirname(os.path.abspath(__file__)) or '.') 