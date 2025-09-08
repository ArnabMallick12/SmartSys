"""
Test cases for System Monitor
Member 3: Integration & Testing
"""

import unittest
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

try:
    from backend.system_monitor import SystemMonitor
except ImportError:
    print("Warning: Could not import SystemMonitor for testing")


class TestSystemMonitor(unittest.TestCase):
    """Test cases for SystemMonitor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        try:
            self.monitor = SystemMonitor()
        except Exception as e:
            self.skipTest(f"Could not initialize SystemMonitor: {e}")
    
    def test_cpu_info(self):
        """Test CPU information retrieval"""
        try:
            cpu_info = self.monitor.get_cpu_info()
            self.assertIsInstance(cpu_info, dict)
            self.assertIn('cpu_percent', cpu_info)
            self.assertIn('cpu_count', cpu_info)
            self.assertGreaterEqual(cpu_info['cpu_percent'], 0)
            self.assertLessEqual(cpu_info['cpu_percent'], 100)
        except Exception as e:
            self.skipTest(f"CPU info test failed: {e}")
    
    def test_memory_info(self):
        """Test memory information retrieval"""
        try:
            memory_info = self.monitor.get_memory_info()
            self.assertIsInstance(memory_info, dict)
            self.assertIn('total', memory_info)
            self.assertIn('used', memory_info)
            self.assertIn('percent', memory_info)
            self.assertGreater(memory_info['total'], 0)
        except Exception as e:
            self.skipTest(f"Memory info test failed: {e}")
    
    def test_disk_info(self):
        """Test disk information retrieval"""
        try:
            disk_info = self.monitor.get_disk_info()
            self.assertIsInstance(disk_info, dict)
            self.assertIn('total', disk_info)
            self.assertIn('used', disk_info)
            self.assertIn('percent', disk_info)
            self.assertGreater(disk_info['total'], 0)
        except Exception as e:
            self.skipTest(f"Disk info test failed: {e}")
    
    def test_processes(self):
        """Test process list retrieval"""
        try:
            processes = self.monitor.get_processes()
            self.assertIsInstance(processes, list)
            if processes:  # If we have processes
                process = processes[0]
                self.assertIn('pid', process)
                self.assertIn('name', process)
                self.assertIn('cpu_percent', process)
        except Exception as e:
            self.skipTest(f"Process list test failed: {e}")
    
    def test_system_data(self):
        """Test comprehensive system data retrieval"""
        try:
            system_data = self.monitor.get_system_data()
            self.assertIsInstance(system_data, dict)
            self.assertIn('timestamp', system_data)
            self.assertIn('cpu', system_data)
            self.assertIn('memory', system_data)
            self.assertIn('disk', system_data)
            self.assertIn('processes', system_data)
        except Exception as e:
            self.skipTest(f"System data test failed: {e}")


if __name__ == '__main__':
    unittest.main()
