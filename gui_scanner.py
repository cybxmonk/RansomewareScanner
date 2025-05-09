#!/usr/bin/env python3
"""
Ransomware File Scanner - GUI Version
-------------------------------------
A graphical interface for the ransomware file scanner using tkinter.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Import the core scanner functionality
try:
    from working_scanner import (
        analyze_file, 
        scan_directory, 
        format_size, 
        VERSION, 
        PROGRAM_NAME
    )
except ImportError:
    print("Error: working_scanner.py must be in the same directory as this script")
    sys.exit(1)

class RansomwareScannerGUI:
    """GUI for the Ransomware File Scanner"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"{PROGRAM_NAME} v{VERSION} - GUI")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Set icon if available
        try:
            self.root.iconbitmap("scanner.ico")
        except:
            pass
            
        # Create style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6)
        self.style.configure("Danger.TButton", foreground="red")
        self.style.configure("Success.TButton", foreground="green")
        
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create UI elements
        self._create_input_section()
        self._create_option_section()
        self._create_button_section()
        self._create_results_section()
        self._create_status_bar()
        
        # Initialize variables
        self.scanning = False
        self.scan_thread = None
        
    def _create_input_section(self):
        """Create the input section for file/directory selection"""
        input_frame = ttk.LabelFrame(self.main_frame, text="Target Selection", padding=10)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Path input
        ttk.Label(input_frame, text="Path to scan:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.path_var = tk.StringVar(value="")
        path_entry = ttk.Entry(input_frame, textvariable=self.path_var, width=50)
        path_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Browse buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(button_frame, text="Browse File", command=self._browse_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Browse Folder", command=self._browse_folder).pack(side=tk.LEFT, padx=2)
        
        # Configure grid
        input_frame.columnconfigure(1, weight=1)
        
    def _create_option_section(self):
        """Create the options section for scan configuration"""
        options_frame = ttk.LabelFrame(self.main_frame, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Recursive option
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Scan subdirectories recursively", 
                    variable=self.recursive_var).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Size limit option
        ttk.Label(options_frame, text="Maximum file size to scan (MB):").grid(row=0, column=1, sticky=tk.W, padx=(20, 5), pady=5)
        self.size_limit_var = tk.IntVar(value=100)
        ttk.Spinbox(options_frame, from_=1, to=10000, textvariable=self.size_limit_var, width=6).grid(row=0, column=2, sticky=tk.W, pady=5)
        
        # Output file option
        self.save_results_var = tk.BooleanVar(value=False)
        save_check = ttk.Checkbutton(options_frame, text="Save results to JSON file", 
                                    variable=self.save_results_var,
                                    command=self._toggle_output_file)
        save_check.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Output file path
        self.output_frame = ttk.Frame(options_frame)
        self.output_frame.grid(row=1, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        self.output_frame.grid_remove()  # Initially hidden
        
        ttk.Label(self.output_frame, text="Output file:").pack(side=tk.LEFT, padx=(0, 5))
        self.output_var = tk.StringVar(value="scan_results.json")
        ttk.Entry(self.output_frame, textvariable=self.output_var, width=25).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(self.output_frame, text="Browse", command=self._browse_output).pack(side=tk.LEFT)
        
        # Configure grid
        options_frame.columnconfigure(2, weight=1)
        
    def _create_button_section(self):
        """Create the button section for actions"""
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan button
        self.scan_button = ttk.Button(button_frame, text="Start Scan", 
                                    command=self._start_scan, style="Success.TButton")
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Cancel button (initially disabled)
        self.cancel_button = ttk.Button(button_frame, text="Cancel Scan", 
                                    command=self._cancel_scan, state=tk.DISABLED,
                                    style="Danger.TButton")
        self.cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        ttk.Button(button_frame, text="Clear Results", 
                command=self._clear_results).pack(side=tk.LEFT, padx=5)
        
        # Help button
        ttk.Button(button_frame, text="Help", 
                command=self._show_help).pack(side=tk.RIGHT, padx=5)
        
    def _create_results_section(self):
        """Create the results section to display scan findings"""
        results_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Progress frame
        self.progress_frame = ttk.Frame(results_frame)
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(self.progress_frame, text="Progress:").pack(side=tk.LEFT, padx=(0, 5))
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, length=100, mode="indeterminate")
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_frame.pack_forget()  # Initially hidden
        
        # Summary frame
        self.summary_frame = ttk.Frame(results_frame)
        self.summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.summary_text = tk.StringVar(value="Ready to scan. Select a file or directory and click 'Start Scan'.")
        ttk.Label(self.summary_frame, textvariable=self.summary_text, wraplength=700).pack(anchor=tk.W)
        
        # Create notebook for results
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Results list tab
        self.results_frame = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(self.results_frame, text="Results List")
        
        # Create treeview for results
        columns = ("path", "size", "type", "confidence", "indicators")
        self.results_tree = ttk.Treeview(self.results_frame, columns=columns, show="headings")
        
        # Configure columns
        self.results_tree.heading("path", text="File Path")
        self.results_tree.heading("size", text="Size")
        self.results_tree.heading("type", text="Detection Type")
        self.results_tree.heading("confidence", text="Confidence")
        self.results_tree.heading("indicators", text="Indicators")
        
        self.results_tree.column("path", width=250)
        self.results_tree.column("size", width=80)
        self.results_tree.column("type", width=100)
        self.results_tree.column("confidence", width=80)
        self.results_tree.column("indicators", width=250)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=y_scrollbar.set)
        
        x_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(xscrollcommand=x_scrollbar.set)
        
        # Place tree and scrollbars
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Log tab
        self.log_frame = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(self.log_frame, text="Log")
        
        self.log_text = tk.Text(self.log_frame, wrap=tk.WORD, height=10)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        log_scrollbar = ttk.Scrollbar(self.log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for colored text
        self.log_text.tag_configure("info", foreground="black")
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("success", foreground="green")
        
        # Add initial log message
        self.log("Scanner initialized and ready", "info")
        
    def _create_status_bar(self):
        """Create status bar at the bottom of the window"""
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _browse_file(self):
        """Open file browser dialog"""
        file_path = filedialog.askopenfilename(title="Select File to Scan")
        if file_path:
            self.path_var.set(file_path)
            
    def _browse_folder(self):
        """Open folder browser dialog"""
        folder_path = filedialog.askdirectory(title="Select Folder to Scan")
        if folder_path:
            self.path_var.set(folder_path)
            
    def _browse_output(self):
        """Open save file dialog for output file"""
        output_path = filedialog.asksaveasfilename(
            title="Save Results As",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if output_path:
            self.output_var.set(output_path)
            
    def _toggle_output_file(self):
        """Show/hide output file options based on checkbox"""
        if self.save_results_var.get():
            self.output_frame.grid()
        else:
            self.output_frame.grid_remove()
            
    def _start_scan(self):
        """Start the scanning process"""
        # Get the path to scan
        path = self.path_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Please enter a file or directory path to scan")
            return
            
        # Check if path exists
        if not os.path.exists(path):
            messagebox.showerror("Error", f"The path does not exist: {path}")
            return
            
        # Clear previous results
        self._clear_results(show_message=False)
        
        # Setup UI for scanning
        self.scanning = True
        self.scan_button.configure(state=tk.DISABLED)
        self.cancel_button.configure(state=tk.NORMAL)
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))
        self.progress_bar.start(10)
        
        # Begin scanning in a separate thread
        self.scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(path,)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def _perform_scan(self, path):
        """Perform the scan in a separate thread"""
        try:
            # Get options
            recursive = self.recursive_var.get()
            size_limit = self.size_limit_var.get()
            
            # Update status
            self._update_status(f"Scanning: {path}")
            self.log(f"Starting scan of {path}", "info")
            
            # Perform scan
            if os.path.isfile(path):
                # Scanning a file
                self.log(f"Analyzing file: {path}", "info")
                result = analyze_file(path, size_limit)
                
                # Update UI with result
                self.root.after(0, lambda: self._handle_file_result(result))
                
            elif os.path.isdir(path):
                # Create custom callback for progress updates
                def progress_callback(files_scanned, suspicious_count):
                    self.root.after(0, lambda: self._update_progress(files_scanned, suspicious_count))
                
                # Scanning a directory
                self.log(f"Scanning directory: {path} (recursive: {recursive})", "info")
                result = scan_directory(path, recursive, size_limit)
                
                # Update UI with result
                self.root.after(0, lambda: self._handle_directory_result(result))
            
            # Save results if requested
            if self.save_results_var.get():
                output_file = self.output_var.get()
                self._save_results(result, output_file)
                
        except Exception as e:
            # Handle unexpected errors
            error_msg = str(e)
            self.log(f"Error during scan: {error_msg}", "error")
            self.root.after(0, lambda: messagebox.showerror("Error", f"An error occurred during scanning:\n\n{error_msg}"))
            
        finally:
            # Reset UI after scan completes
            self.root.after(0, self._reset_scanning_ui)
            
    def _handle_file_result(self, result):
        """Handle the result of a file scan"""
        if result.get("is_suspicious"):
            # File is suspicious
            confidence = result.get("confidence", 0) * 100
            method = result.get("detection_method", "Unknown")
            indicators = ", ".join(result.get("suspicious_indicators", []))
            
            self.log(f"SUSPICIOUS: {result.get('path')} (Confidence: {confidence:.0f}%)", "warning")
            self.summary_text.set(f"Suspicious file detected! Confidence: {confidence:.0f}%, Method: {method}")
            
            # Add to results tree
            self.results_tree.insert("", "end", values=(
                result.get("path"),
                format_size(result.get("size", 0)),
                method,
                f"{confidence:.0f}%",
                indicators[:100] + ("..." if len(indicators) > 100 else "")
            ))
            
            # Show alert
            messagebox.showwarning(
                "Suspicious File Detected",
                f"The file appears to be suspicious!\n\nFile: {result.get('name', os.path.basename(result.get('path', '')))}\nConfidence: {confidence:.0f}%\nMethod: {method}\n\nIndicators: {indicators}"
            )
            
        else:
            # File is clean
            self.log(f"CLEAN: {result.get('path')}", "success")
            if "error" in result:
                self.summary_text.set(f"Error scanning file: {result.get('error')}")
            else:
                self.summary_text.set("File appears to be clean. No suspicious indicators found.")
                
    def _handle_directory_result(self, result):
        """Handle the result of a directory scan"""
        # Get stats
        scanned = result.get("files_scanned", 0)
        suspicious = len(result.get("suspicious_files", []))
        elapsed = result.get("elapsed_time", 0)
        errors = len(result.get("errors", []))
        
        # Update summary
        self.summary_text.set(
            f"Scan completed. Scanned {scanned} files in {elapsed:.2f} seconds. "
            f"Found {suspicious} suspicious files. Encountered {errors} errors."
        )
        
        # Log completion
        self.log(f"Scan completed: {scanned} files, {suspicious} suspicious, {elapsed:.2f} seconds", 
                "success" if suspicious == 0 else "warning")
        
        # Add suspicious files to results
        for file_result in result.get("suspicious_files", []):
            confidence = file_result.get("confidence", 0) * 100
            method = file_result.get("detection_method", "Unknown")
            indicators = ", ".join(file_result.get("suspicious_indicators", []))
            
            self.log(f"SUSPICIOUS: {file_result.get('path')} (Confidence: {confidence:.0f}%)", "warning")
            
            # Add to results tree
            self.results_tree.insert("", "end", values=(
                file_result.get("path"),
                format_size(file_result.get("size", 0)),
                method,
                f"{confidence:.0f}%",
                indicators[:100] + ("..." if len(indicators) > 100 else "")
            ))
            
        # Show summary alert
        if suspicious > 0:
            messagebox.showwarning(
                "Suspicious Files Detected",
                f"Found {suspicious} suspicious files out of {scanned} scanned!\n\nCheck the Results List tab for details."
            )
        else:
            messagebox.showinfo(
                "Scan Complete",
                f"No suspicious files found. Scanned {scanned} files in {elapsed:.2f} seconds."
            )
            
    def _save_results(self, result, output_file):
        """Save scan results to a JSON file"""
        try:
            import json
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            self.log(f"Results saved to {output_file}", "success")
        except Exception as e:
            self.log(f"Error saving results: {e}", "error")
            
    def _update_progress(self, files_scanned, suspicious_count):
        """Update progress information"""
        self._update_status(f"Scanned {files_scanned} files, found {suspicious_count} suspicious...")
        
    def _cancel_scan(self):
        """Cancel the ongoing scan"""
        if not self.scanning:
            return
            
        # Set scanning flag to stop the thread
        self.scanning = False
        self.log("Scan cancelled by user", "warning")
        self._update_status("Scan cancelled")
        self._reset_scanning_ui()
        
    def _reset_scanning_ui(self):
        """Reset UI elements after scanning is complete"""
        self.scanning = False
        self.scan_button.configure(state=tk.NORMAL)
        self.cancel_button.configure(state=tk.DISABLED)
        self.progress_bar.stop()
        self.progress_frame.pack_forget()
        self._update_status("Ready")
        
    def _clear_results(self, show_message=True):
        """Clear all results"""
        # Clear results tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Clear log (but keep initialization message)
        self.log_text.delete(1.0, tk.END)
        self.log("Results cleared", "info")
        
        # Reset summary
        self.summary_text.set("Ready to scan. Select a file or directory and click 'Start Scan'.")
        
        if show_message:
            self._update_status("Results cleared")
            
    def _show_help(self):
        """Show help information"""
        help_text = f"""
{PROGRAM_NAME} v{VERSION} - Help

This application scans files and directories for potential ransomware indicators.

How to use:
1. Select a file or directory to scan using the browse buttons or enter a path manually
2. Configure scan options:
    - Recursive: Scan subdirectories (for directory scans)
    - Size limit: Maximum file size to scan in MB
    - Save results: Option to save detailed results to a JSON file
3. Click "Start Scan" to begin the scanning process
4. View results in the Results List tab
5. Check the Log tab for detailed scan information

Detection methods:
- Known ransomware file extensions
- Suspicious text content patterns
- File entropy analysis (randomness indicating encryption)

For more information, refer to the documentation (README.md).
"""
        messagebox.showinfo("Help", help_text)
        
    def _update_status(self, message):
        """Update status bar message"""
        self.status_var.set(message)
        self.root.update_idletasks()
        
    def log(self, message, level="info"):
        """Add a message to the log"""
        # Add timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        # Insert text with appropriate tag
        self.log_text.insert(tk.END, log_message, level)
        self.log_text.see(tk.END)  # Scroll to end
        
def main():
    """Main entry point"""
    root = tk.Tk()
    app = RansomwareScannerGUI(root)
    root.mainloop()
    
if __name__ == "__main__":
    from datetime import datetime
    main() 