"""
System Monitor Module
Responsible for collecting system data using psutil
Member 1: Backend Development
"""

import psutil
import time
import json
from typing import Dict, List, Any


class SystemMonitor:
    """Main class for monitoring system resources and processes"""
    
    def __init__(self):
        """Initialize the system monitor"""
        self.cpu_count = psutil.cpu_count()
        self.boot_time = psutil.boot_time()
        
    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information and usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            cpu_freq = psutil.cpu_freq()
            
            return {
                'cpu_percent': cpu_percent,
                'cpu_per_core': cpu_per_core,
                'cpu_count': self.cpu_count,
                'cpu_freq': {
                    'current': cpu_freq.current if cpu_freq else 0,
                    'min': cpu_freq.min if cpu_freq else 0,
                    'max': cpu_freq.max if cpu_freq else 0
                }
            }
        except Exception as e:
            print(f"Error getting CPU info: {e}")
            return {'cpu_percent': 0, 'cpu_per_core': [], 'cpu_count': 0, 'cpu_freq': {}}
    
    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information"""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'free': memory.free,
                'percent': memory.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_free': swap.free,
                'swap_percent': swap.percent
            }
        except Exception as e:
            print(f"Error getting memory info: {e}")
            return {}
    
    def get_disk_info(self) -> Dict[str, Any]:
        """Get disk information"""
        try:
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            return {
                'total': disk_usage.total,
                'used': disk_usage.used,
                'free': disk_usage.free,
                'percent': (disk_usage.used / disk_usage.total) * 100,
                'read_bytes': disk_io.read_bytes if disk_io else 0,
                'write_bytes': disk_io.write_bytes if disk_io else 0
            }
        except Exception as e:
            print(f"Error getting disk info: {e}")
            return {}
    
    def get_processes(self) -> List[Dict[str, Any]]:
        """Get list of running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent'],
                        'status': proc_info['status'],
                        'create_time': proc_info['create_time']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort by CPU usage (descending)
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return processes[:50]  # Return top 50 processes
            
        except Exception as e:
            print(f"Error getting processes: {e}")
            return []
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get network information"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except Exception as e:
            print(f"Error getting network info: {e}")
            return {}
    
    def get_system_data(self) -> Dict[str, Any]:
        """Get comprehensive system data"""
        return {
            'timestamp': time.time(),
            'cpu': self.get_cpu_info(),
            'memory': self.get_memory_info(),
            'disk': self.get_disk_info(),
            'processes': self.get_processes(),
            'network': self.get_network_info()
        }
    
    def terminate_process(self, pid: int) -> bool:
        """Terminate a process by PID"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error terminating process {pid}: {e}")
            return False
    
    def kill_process(self, pid: int) -> bool:
        """Force kill a process by PID"""
        try:
            process = psutil.Process(pid)
            process.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error killing process {pid}: {e}")
            return False
