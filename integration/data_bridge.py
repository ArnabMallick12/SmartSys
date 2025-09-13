"""
Data Bridge Module
Responsible for integrating backend and frontend
Member 3: Integration & Testing
"""

import queue
import threading
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime


class DataBridge:
    """Bridge class for data communication between backend and frontend"""
    
    def __init__(self, data_queue: queue.Queue):
        """Initialize the data bridge"""
        self.data_queue = data_queue
        self.running = False
        self.bridge_thread = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Performance monitoring
        self.data_count = 0
        self.error_count = 0
        self.last_error_time = None
        
        # Data validation
        self.required_fields = ['timestamp', 'cpu', 'memory', 'disk', 'processes']
        
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
                self.data_count += 1
                
        except Exception as e:
            self.error_count += 1
            self.last_error_time = datetime.now()
            self.logger.error(f"Error processing data: {e}")
    
    def validate_data(self, data: Dict[str, Any]) -> bool:
        """Validate incoming data structure"""
        try:
            if not isinstance(data, dict):
                return False
            
            # Check required fields
            for field in self.required_fields:
                if field not in data:
                    self.logger.warning(f"Missing required field: {field}")
                    return False
            
            # Validate timestamp
            if not isinstance(data['timestamp'], (int, float)):
                self.logger.warning("Invalid timestamp format")
                return False
            
            # Validate CPU data
            cpu_data = data.get('cpu', {})
            if not isinstance(cpu_data, dict):
                self.logger.warning("Invalid CPU data format")
                return False
            
            # Validate memory data
            memory_data = data.get('memory', {})
            if not isinstance(memory_data, dict):
                self.logger.warning("Invalid memory data format")
                return False
            
            # Validate processes
            processes = data.get('processes', [])
            if not isinstance(processes, list):
                self.logger.warning("Invalid processes data format")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating data: {e}")
            return False
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        return {
            'data_count': self.data_count,
            'error_count': self.error_count,
            'last_error_time': self.last_error_time.isoformat() if self.last_error_time else None,
            'error_rate': (self.error_count / max(self.data_count, 1)) * 100
        }
    
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
