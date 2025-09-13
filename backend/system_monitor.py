"""
System Monitor Module
Responsible for collecting system data using psutil
Member 1: Backend Development
"""

import psutil
import time
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta


class SystemMonitor:
    """Main class for monitoring system resources and processes"""
    
    def __init__(self):
        """Initialize the system monitor"""
        self.cpu_count = psutil.cpu_count()
        self.boot_time = psutil.boot_time()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        self.last_update_time = time.time()
        self.update_interval = 1.0  # seconds
        
        # Data caching for performance
        self.cached_data = {}
        self.cache_duration = 0.5  # seconds
        
    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information and usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=2.0)
            cpu_per_core = psutil.cpu_percent(interval=2.0, percpu=True)
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
    
    def get_processes(self, filter_name: str = "", sort_by: str = "cpu", limit: int = 50) -> List[Dict[str, Any]]:
        """Get list of running processes with filtering and sorting options"""
        try:
            processes = []
            proc_fields = [
                'pid', 'name', 'cpu_percent', 'memory_percent', 'status', 
                'create_time', 'memory_info', 'cmdline', 'username', 'ppid'
            ]
            
            for proc in psutil.process_iter(proc_fields):
                try:
                    proc_info = proc.info
                    
                    # Apply name filter
                    if filter_name and filter_name.lower() not in proc_info['name'].lower():
                        continue
                    
                    # Get memory info
                    memory_info = proc_info.get('memory_info')
                    memory_rss = memory_info.rss if memory_info else 0
                    memory_vms = memory_info.vms if memory_info else 0
                    
                    # Get CPU usage (use existing value to avoid delays)
                    cpu_percent = proc_info['cpu_percent'] or 0
                    
                    process_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cpu_percent': cpu_percent,
                        'memory_percent': proc_info['memory_percent'] or 0,
                        'memory_rss': memory_rss,
                        'memory_vms': memory_vms,
                        'status': proc_info['status'],
                        'create_time': proc_info['create_time'],
                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        'username': proc_info.get('username', 'Unknown'),
                        'ppid': proc_info.get('ppid', 0)
                    }
                    
                    processes.append(process_data)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort processes
            if sort_by == "cpu":
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            elif sort_by == "memory":
                processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            elif sort_by == "name":
                processes.sort(key=lambda x: x['name'].lower())
            elif sort_by == "pid":
                processes.sort(key=lambda x: x['pid'])
            
            return processes[:limit]
            
        except Exception as e:
            self.logger.error(f"Error getting processes: {e}")
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
    
    def get_system_data(self, filter_name: str = "", sort_by: str = "cpu", limit: int = 50) -> Dict[str, Any]:
        """Get comprehensive system data with filtering and sorting options"""
        current_time = time.time()
        
        # Check if we can use cached data
        if (current_time - self.last_update_time) < self.cache_duration and self.cached_data:
            # Return cached data with updated processes if filtering/sorting changed
            cached_data = self.cached_data.copy()
            if filter_name or sort_by != "cpu" or limit != 50:
                cached_data['processes'] = self.get_processes(filter_name, sort_by, limit)
            cached_data['timestamp'] = current_time
            return cached_data
        
        # Collect fresh data
        system_data = {
            'timestamp': current_time,
            'cpu': self.get_cpu_info(),
            'memory': self.get_memory_info(),
            'disk': self.get_disk_info(),
            'processes': self.get_processes(filter_name, sort_by, limit),
            'network': self.get_network_info(),
            'performance': self.get_system_performance_metrics()
        }
        
        # Cache the data
        self.cached_data = system_data.copy()
        self.last_update_time = current_time
        
        return system_data
    
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
            self.logger.info(f"Process {pid} killed successfully")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def suspend_process(self, pid: int) -> bool:
        """Suspend a process by PID"""
        try:
            process = psutil.Process(pid)
            process.suspend()
            self.logger.info(f"Process {pid} suspended successfully")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error suspending process {pid}: {e}")
            return False
    
    def resume_process(self, pid: int) -> bool:
        """Resume a suspended process by PID"""
        try:
            process = psutil.Process(pid)
            process.resume()
            self.logger.info(f"Process {pid} resumed successfully")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error resuming process {pid}: {e}")
            return False
    
    def set_process_priority(self, pid: int, priority: str) -> bool:
        """Set process priority (low, normal, high, realtime)"""
        try:
            process = psutil.Process(pid)
            
            priority_map = {
                'low': psutil.BELOW_NORMAL_PRIORITY_CLASS,
                'normal': psutil.NORMAL_PRIORITY_CLASS,
                'high': psutil.HIGH_PRIORITY_CLASS,
                'realtime': psutil.REALTIME_PRIORITY_CLASS
            }
            
            if priority.lower() in priority_map:
                process.nice(priority_map[priority.lower()])
                self.logger.info(f"Process {pid} priority set to {priority}")
                return True
            else:
                self.logger.error(f"Invalid priority: {priority}")
                return False
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error setting priority for process {pid}: {e}")
            return False
    
    def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific process"""
        try:
            process = psutil.Process(pid)
            
            # Get process info
            proc_info = process.as_dict([
                'pid', 'name', 'cpu_percent', 'memory_percent', 'status',
                'create_time', 'memory_info', 'cmdline', 'username', 'ppid',
                'num_threads', 'connections', 'open_files'
            ])
            
            # Add additional details
            details = {
                'pid': proc_info['pid'],
                'name': proc_info['name'],
                'cpu_percent': proc_info['cpu_percent'],
                'memory_percent': proc_info['memory_percent'],
                'memory_rss': proc_info['memory_info'].rss if proc_info['memory_info'] else 0,
                'memory_vms': proc_info['memory_info'].vms if proc_info['memory_info'] else 0,
                'status': proc_info['status'],
                'create_time': proc_info['create_time'],
                'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                'username': proc_info.get('username', 'Unknown'),
                'ppid': proc_info.get('ppid', 0),
                'num_threads': proc_info.get('num_threads', 0),
                'num_connections': len(proc_info.get('connections', [])),
                'num_open_files': len(proc_info.get('open_files', []))
            }
            
            return details
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error getting process details for {pid}: {e}")
            return None
    
    def get_system_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system performance metrics"""
        try:
            # Get load averages (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()
                load_avg_data = {
                    'load_1min': load_avg[0],
                    'load_5min': load_avg[1],
                    'load_15min': load_avg[2]
                }
            except AttributeError:
                load_avg_data = {'load_1min': 0, 'load_5min': 0, 'load_15min': 0}
            
            # Get boot time and uptime
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            
            # Get system-wide performance data
            perf_data = {
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime))),
                'boot_time': datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S'),
                'load_averages': load_avg_data,
                'context_switches': psutil.cpu_stats().ctx_switches if hasattr(psutil, 'cpu_stats') else 0,
                'interrupts': psutil.cpu_stats().interrupts if hasattr(psutil, 'cpu_stats') else 0
            }
            
            return perf_data
            
        except Exception as e:
            self.logger.error(f"Error getting performance metrics: {e}")
            return {}
    
    def get_detailed_cpu_usage(self, pid: int) -> float:
        """Get detailed CPU usage for a specific process (with longer measurement)"""
        try:
            process = psutil.Process(pid)
            
            # First call (returns 0)
            cpu_percent = process.cpu_percent()
            time.sleep(2.0)  # Wait 2 seconds for accurate measurement
            cpu_percent = process.cpu_percent()  # Second call (returns actual percentage)
            
            # If still 0, try with interval method
            if cpu_percent == 0:
                try:
                    cpu_percent = process.cpu_percent(interval=2.0)
                except:
                    cpu_percent = 0
            
            return cpu_percent
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0
        except Exception as e:
            print(f"Error getting detailed CPU usage for PID {pid}: {e}")
            return 0.0
