#!/usr/bin/env python3
"""
SmartSys: Real-Time Process and Resource Tracker
Main application entry point
"""

import sys
import os
import tkinter as tk
from tkinter import ttk
import threading
import queue
import time

# Add project directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'frontend'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'integration'))

try:
    from backend.system_monitor import SystemMonitor
    from frontend.main_gui import MainGUI
    from integration.data_bridge import DataBridge
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all required modules are properly set up.")
    sys.exit(1)


class SmartSysApp:
    """Main application class that coordinates backend and frontend"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SmartSys - Real-Time Process and Resource Tracker")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.data_queue = queue.Queue()
        self.system_monitor = SystemMonitor()
        self.data_bridge = DataBridge(self.data_queue)
        self.gui = MainGUI(self.root, self.data_queue)
        
        # Control flags
        self.running = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start the system monitoring in a separate thread"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("System monitoring started")
    
    def stop_monitoring(self):
        """Stop the system monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        print("System monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop that runs in background thread"""
        while self.running:
            try:
                # Collect system data
                system_data = self.system_monitor.get_system_data()
                
                # Send data to GUI through queue
                self.data_queue.put(system_data)
                
                # Update every 1 second
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(1)
    
    def run(self):
        """Start the application"""
        try:
            # Start monitoring
            self.start_monitoring()
            
            # Start GUI
            self.gui.start()
            
            # Handle window closing
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            
            # Start main loop
            self.root.mainloop()
            
        except KeyboardInterrupt:
            print("Application interrupted by user")
        except Exception as e:
            print(f"Application error: {e}")
        finally:
            self.stop_monitoring()
    
    def on_closing(self):
        """Handle application closing"""
        self.stop_monitoring()
        self.root.destroy()


def main():
    """Main entry point"""
    print("Starting SmartSys...")
    
    # Check if psutil is available
    try:
        import psutil
        print(f"psutil version: {psutil.__version__}")
    except ImportError:
        print("Error: psutil is required but not installed.")
        print("Please install it using: pip install psutil")
        return
    
    # Create and run application
    app = SmartSysApp()
    app.run()


if __name__ == "__main__":
    main()
