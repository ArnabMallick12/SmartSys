"""
Data Bridge Module
Responsible for integrating backend and frontend
Member 3: Integration & Testing
"""

import queue
import threading
import time
from typing import Dict, Any, Optional


class DataBridge:
    """Bridge class for data communication between backend and frontend"""
    
    def __init__(self, data_queue: queue.Queue):
        """Initialize the data bridge"""
        self.data_queue = data_queue
        self.running = False
        self.bridge_thread = None
        
    def start(self):
        """Start the data bridge"""
        if not self.running:
            self.running = True
            self.bridge_thread = threading.Thread(target=self._bridge_loop, daemon=True)
            self.bridge_thread.start()
            print("Data bridge started")
    
    def stop(self):
        """Stop the data bridge"""
        self.running = False
        if self.bridge_thread:
            self.bridge_thread.join(timeout=1)
        print("Data bridge stopped")
    
    def _bridge_loop(self):
        """Main bridge loop for data processing"""
        while self.running:
            try:
                # Process any pending data
                self._process_data()
                time.sleep(0.1)  # Small delay to prevent excessive CPU usage
                
            except Exception as e:
                print(f"Error in bridge loop: {e}")
                time.sleep(1)
    
    def _process_data(self):
        """Process data from the queue"""
        try:
            # Check for new data (non-blocking)
            if not self.data_queue.empty():
                # Data is already being processed by the GUI
                # This is where additional data processing could be added
                pass
                
        except Exception as e:
            print(f"Error processing data: {e}")
    
    def send_data(self, data: Dict[str, Any]):
        """Send data to the frontend"""
        try:
            self.data_queue.put(data)
        except Exception as e:
            print(f"Error sending data: {e}")
    
    def get_latest_data(self) -> Optional[Dict[str, Any]]:
        """Get the latest data from the queue (non-blocking)"""
        try:
            return self.data_queue.get_nowait()
        except queue.Empty:
            return None
        except Exception as e:
            print(f"Error getting data: {e}")
            return None
