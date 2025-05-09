#!/usr/bin/env python3
"""
Cleanup script to remove unnecessary files and keep only the essential ones
for the ransomware file scanner.
"""

import os
import shutil
import sys

# Files to keep (essential)
ESSENTIAL_FILES = [
    # Core scanner files
    "working_scanner.py",
    "gui_scanner.py",
    "run_scanner.bat",
    "run_scanner.sh",
    "run_gui.bat",
    "run_gui.sh",
    
    # Documentation
    "README.md",
    "LICENSE",
    
    # Icon creation and utility
    "create_icon.py",
    "scanner.ico",
    "scanner.png",
    
    # Test files directory
    "test_files/example.locky",
    
    # This cleanup script
    "cleanup.py"
]

# Essential directories to keep
ESSENTIAL_DIRS = [
    "test_files",
    "assets",
    "rules"
]

# File patterns to never delete, regardless of whether they're in ESSENTIAL_FILES
NEVER_DELETE_PATTERNS = [
    ".git",
    "test_files"
]

# Directories to ensure exist
ENSURE_DIRS = [
    "test_files"
]

def cleanup_files():
    """Remove unnecessary files and keep only the essential ones."""
    current_dir = os.getcwd()
    
    print("Starting cleanup process...")
    print(f"Current directory: {current_dir}")
    
    # List all directories at the root
    print("\nDirectories found in root:")
    for item in os.listdir(current_dir):
        if os.path.isdir(os.path.join(current_dir, item)):
            print(f"  - {item}")
    
    # Ensure essential directories exist
    for directory in ENSURE_DIRS:
        os.makedirs(directory, exist_ok=True)
        print(f"Ensured directory exists: {directory}")
    
    # Get all files in the current directory (recursive)
    all_files = []
    for root, dirs, files in os.walk(current_dir):
        rel_path = os.path.relpath(root, current_dir)
        if rel_path == ".":
            # Files in the root directory
            all_files.extend(files)
        else:
            # Files in subdirectories
            for file in files:
                all_files.append(os.path.join(rel_path, file))
    
    print(f"\nFound {len(all_files)} files in total")
    
    # Remove unnecessary files
    files_removed = 0
    
    for file in all_files:
        # Check if file is in the essential list or matches a never-delete pattern
        if file in ESSENTIAL_FILES:
            print(f"Keeping essential file: {file}")
            continue
            
        # Check if file matches a pattern that should never be deleted
        should_keep = False
        for pattern in NEVER_DELETE_PATTERNS:
            if pattern in file:
                should_keep = True
                print(f"Keeping pattern-matched file: {file}")
                break
                
        if should_keep:
            continue
        
        # File is not essential, remove it
        try:
            file_path = os.path.join(current_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"Removed file: {file}")
                files_removed += 1
        except Exception as e:
            print(f"Error removing file {file}: {e}")
    
    # Remove unnecessary directories
    dirs_removed = 0
    dirs_to_remove = []
    
    # First, identify directories to remove
    for root, dirs, _ in os.walk(current_dir, topdown=False):
        rel_path = os.path.relpath(root, current_dir)
        
        # Skip root directory
        if rel_path == ".":
            continue
            
        # Check if directory should be kept
        dir_name = os.path.basename(rel_path)
        parts = rel_path.split(os.sep)
        
        # Skip essential directories and their children
        should_keep = False
        for essential_dir in ESSENTIAL_DIRS:
            if parts[0] == essential_dir or any(pattern in rel_path for pattern in NEVER_DELETE_PATTERNS):
                should_keep = True
                print(f"Keeping essential directory: {rel_path}")
                break
                
        if not should_keep:
            # Only add top-level directories
            if len(parts) == 1:
                dirs_to_remove.append(rel_path)
    
    # Now remove the directories
    for dir_path in dirs_to_remove:
        try:
            full_path = os.path.join(current_dir, dir_path)
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
                print(f"Removed directory: {dir_path}")
                dirs_removed += 1
        except Exception as e:
            print(f"Error removing directory {dir_path}: {e}")
    
    print(f"\nCleanup complete. Removed {files_removed} unnecessary files and {dirs_removed} unnecessary directories.")

def confirm_cleanup():
    """Confirm with the user before proceeding with cleanup."""
    print("This script will remove all non-essential files and directories from the current directory.")
    print("Only the files and directories needed for the basic ransomware file scanner will be kept.")
    print("\nThe following files will be kept:")
    for file in sorted(ESSENTIAL_FILES):
        print(f"  - {file}")
        
    print("\nThe following directories will be kept:")
    for directory in sorted(ESSENTIAL_DIRS):
        print(f"  - {directory}")
        
    print("\nAll other files and directories will be deleted.")
    response = input("\nDo you want to continue? (yes/no): ")
    
    if response.lower() in ["yes", "y"]:
        return True
    else:
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--force":
        cleanup_files()
    elif confirm_cleanup():
        cleanup_files()
    else:
        print("Cleanup cancelled.")
        sys.exit(0) 