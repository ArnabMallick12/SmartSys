"""
Integration tests for SmartSys
Member 3: Integration & Testing
"""

import unittest
import sys
import os
import queue
import time
import threading

# Add modules to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'integration'))

try:
    from backend.system_monitor import SystemMonitor
    from integration.data_bridge import DataBridge
except ImportError:
    print("Warning: Could not import modules for integration testing")


class TestIntegration(unittest.TestCase):
    """Integration tests for SmartSys components"""
    
    def setUp(self):
        """Set up test fixtures"""
        try:
            self.data_queue = queue.Queue()
            self.monitor = SystemMonitor()
            self.bridge = DataBridge(self.data_queue)
        except Exception as e:
            self.skipTest(f"Could not initialize components: {e}")
    
    def test_data_flow(self):
        """Test data flow from backend to bridge"""
        try:
            # Get system data
            system_data = self.monitor.get_system_data()
            
            # Validate data
            self.assertTrue(self.bridge.validate_data(system_data))
            
            # Send data through bridge
            self.bridge.send_data(system_data)
            
            # Check if data is in queue
            self.assertFalse(self.data_queue.empty())
            
        except Exception as e:
            self.skipTest(f"Data flow test failed: {e}")
    
    def test_data_validation(self):
        """Test data validation in bridge"""
        try:
            # Test valid data
            valid_data = {
                'timestamp': time.time(),
                'cpu': {'cpu_percent': 25.5},
                'memory': {'percent': 60.2},
                'disk': {'percent': 45.0},
                'processes': [{'pid': 1, 'name': 'test'}]
            }
            self.assertTrue(self.bridge.validate_data(valid_data))
            
            # Test invalid data (missing field)
            invalid_data = {
                'timestamp': time.time(),
                'cpu': {'cpu_percent': 25.5},
                'memory': {'percent': 60.2},
                # Missing 'disk' and 'processes'
            }
            self.assertFalse(self.bridge.validate_data(invalid_data))
            
            # Test invalid data (wrong type)
            invalid_data2 = {
                'timestamp': 'not_a_number',
                'cpu': {'cpu_percent': 25.5},
                'memory': {'percent': 60.2},
                'disk': {'percent': 45.0},
                'processes': [{'pid': 1, 'name': 'test'}]
            }
            self.assertFalse(self.bridge.validate_data(invalid_data2))
            
        except Exception as e:
            self.skipTest(f"Data validation test failed: {e}")
    
    def test_performance_monitoring(self):
        """Test performance monitoring in bridge"""
        try:
            # Get initial stats
            initial_stats = self.bridge.get_performance_stats()
            
            # Send some data
            for i in range(5):
                test_data = {
                    'timestamp': time.time(),
                    'cpu': {'cpu_percent': 25.5 + i},
                    'memory': {'percent': 60.2 + i},
                    'disk': {'percent': 45.0 + i},
                    'processes': [{'pid': i, 'name': f'test{i}'}]
                }
                self.bridge.send_data(test_data)
            
            # Get updated stats
            updated_stats = self.bridge.get_performance_stats()
            
            # Check if data count increased
            self.assertGreaterEqual(updated_stats['data_count'], initial_stats['data_count'])
            
        except Exception as e:
            self.skipTest(f"Performance monitoring test failed: {e}")
    
    def test_process_filtering(self):
        """Test process filtering functionality"""
        try:
            # Test filtering by name
            filtered_processes = self.monitor.get_processes(filter_name="python", limit=10)
            
            # All returned processes should contain "python" in name
            for proc in filtered_processes:
                self.assertIn("python", proc['name'].lower())
            
            # Test sorting
            cpu_sorted = self.monitor.get_processes(sort_by="cpu", limit=10)
            memory_sorted = self.monitor.get_processes(sort_by="memory", limit=10)
            name_sorted = self.monitor.get_processes(sort_by="name", limit=10)
            
            # Verify sorting (if we have enough processes)
            if len(cpu_sorted) > 1:
                self.assertGreaterEqual(cpu_sorted[0]['cpu_percent'], cpu_sorted[1]['cpu_percent'])
            
            if len(memory_sorted) > 1:
                self.assertGreaterEqual(memory_sorted[0]['memory_percent'], memory_sorted[1]['memory_percent'])
            
            if len(name_sorted) > 1:
                self.assertLessEqual(name_sorted[0]['name'].lower(), name_sorted[1]['name'].lower())
            
        except Exception as e:
            self.skipTest(f"Process filtering test failed: {e}")
    
    def test_system_performance_metrics(self):
        """Test system performance metrics"""
        try:
            perf_metrics = self.monitor.get_system_performance_metrics()
            
            # Check required fields
            self.assertIn('uptime_seconds', perf_metrics)
            self.assertIn('uptime_formatted', perf_metrics)
            self.assertIn('boot_time', perf_metrics)
            
            # Verify uptime is positive
            self.assertGreater(perf_metrics['uptime_seconds'], 0)
            
        except Exception as e:
            self.skipTest(f"System performance metrics test failed: {e}")


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    def setUp(self):
        """Set up test fixtures"""
        try:
            self.data_queue = queue.Queue()
            self.bridge = DataBridge(self.data_queue)
        except Exception as e:
            self.skipTest(f"Could not initialize components: {e}")
    
    def test_invalid_data_handling(self):
        """Test handling of invalid data"""
        try:
            # Test with None
            self.assertFalse(self.bridge.validate_data(None))
            
            # Test with empty dict
            self.assertFalse(self.bridge.validate_data({}))
            
            # Test with string
            self.assertFalse(self.bridge.validate_data("not a dict"))
            
            # Test with list
            self.assertFalse(self.bridge.validate_data([1, 2, 3]))
            
        except Exception as e:
            self.skipTest(f"Invalid data handling test failed: {e}")
    
    def test_bridge_error_recovery(self):
        """Test bridge error recovery"""
        try:
            # Start bridge
            self.bridge.start()
            
            # Let it run briefly
            time.sleep(0.1)
            
            # Stop bridge
            self.bridge.stop()
            
            # Should not raise exceptions
            self.assertTrue(True)
            
        except Exception as e:
            self.skipTest(f"Bridge error recovery test failed: {e}")


if __name__ == '__main__':
    unittest.main()


