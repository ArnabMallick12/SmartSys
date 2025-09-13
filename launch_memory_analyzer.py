#!/usr/bin/env python3
"""
Standalone Memory Analyzer Launcher
Opens the memory analysis GUI directly
"""

import tkinter as tk
from tkinter import ttk
import sys
import os

# Add project directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'frontend'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

try:
    from frontend.memory_analysis_gui import MemoryAnalysisGUI
    
    def main():
        """Launch the memory analyzer GUI"""
        print("Starting Memory Analyzer...")
        
        # Create main window
        root = tk.Tk()
        root.title("SmartSys Memory Analyzer")
        root.geometry("1000x700")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create memory analysis GUI
        memory_gui = MemoryAnalysisGUI(main_frame)
        
        # Start the GUI
        root.mainloop()
    
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"Error importing memory analyzer: {e}")
    print("Please ensure all dependencies are installed:")
    print("pip install -r requirements.txt")
