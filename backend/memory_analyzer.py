"""
Memory Analyzer Module
Advanced memory analysis capabilities for processes
Demonstrates OS memory management concepts
"""

import psutil
import os
import time
import platform
from typing import Dict, List, Any, Optional
from datetime import datetime


class MemoryAnalyzer:
    """Advanced memory analysis for processes"""
    
    def __init__(self):
        """Initialize the memory analyzer"""
        self.analysis_cache = {}
        self.cache_duration = 5.0  # Cache for 5 seconds
        
    def get_detailed_memory_info(self, pid: int) -> Dict[str, Any]:
        """Get detailed memory information for a process"""
        try:
            process = psutil.Process(pid)
            
            # Basic memory info
            memory_info = process.memory_info()
            
            # Memory maps (if available)
            memory_maps = []
            try:
                memory_maps = process.memory_maps()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # System memory info
            system_memory = psutil.virtual_memory()
            
            # Process memory percentage
            memory_percent = process.memory_percent()
            
            # Handle different psutil versions and platforms
            memory_data = {
                'rss': memory_info.rss,                    # Resident Set Size
                'vms': memory_info.vms,                    # Virtual Memory Size
            }
            
            # Add platform-specific fields if available
            if hasattr(memory_info, 'shared'):
                memory_data['shared'] = memory_info.shared
            else:
                memory_data['shared'] = 0
                
            if hasattr(memory_info, 'text'):
                memory_data['text'] = memory_info.text
            else:
                memory_data['text'] = 0
                
            if hasattr(memory_info, 'data'):
                memory_data['data'] = memory_info.data
            else:
                memory_data['data'] = 0
                
            if hasattr(memory_info, 'lib'):
                memory_data['lib'] = memory_info.lib
            else:
                memory_data['lib'] = 0
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'memory_info': memory_data,
                'memory_maps': memory_maps,
                'memory_percent': memory_percent,
                'system_memory': {
                    'total': system_memory.total,
                    'available': system_memory.available,
                    'used': system_memory.used,
                    'free': system_memory.free,
                    'percent': system_memory.percent
                }
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def analyze_memory_regions(self, pid: int) -> Dict[str, Any]:
        """Analyze memory regions for a process"""
        try:
            process = psutil.Process(pid)
            memory_maps = process.memory_maps()
            
            regions = {
                'text': [],      # Code segments
                'data': [],      # Data segments
                'heap': [],      # Heap segments
                'stack': [],     # Stack segments
                'libs': [],      # Library segments
                'anonymous': [], # Anonymous memory
                'other': []      # Other segments
            }
            
            total_size = 0
            region_count = 0
            
            for mmap in memory_maps:
                region_count += 1
                
                # Handle different memory map object types
                if hasattr(mmap, 'size'):
                    size = mmap.size
                elif hasattr(mmap, 'length'):
                    size = mmap.length
                elif hasattr(mmap, 'rss'):
                    size = mmap.rss  # Use RSS if available
                else:
                    size = 0
                
                # On Windows, if size is 0, try to estimate from RSS
                if size == 0 and hasattr(mmap, 'rss') and mmap.rss > 0:
                    size = mmap.rss
                
                total_size += size
                
                path = getattr(mmap, 'path', '') or ''
                path_lower = path.lower()
                perms = getattr(mmap, 'perms', '')
                
                # Categorize memory regions
                if 'text' in path_lower or 'code' in path_lower or (perms and 'x' in perms):
                    regions['text'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
                elif 'data' in path_lower or (perms and 'w' in perms and 'x' not in perms):
                    regions['data'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
                elif 'heap' in path_lower:
                    regions['heap'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
                elif 'stack' in path_lower:
                    regions['stack'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
                elif '.so' in path_lower or 'lib' in path_lower or 'dll' in path_lower:
                    regions['libs'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
                elif not path or path == '[anon]':
                    regions['anonymous'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
                else:
                    regions['other'].append({
                        'path': path,
                        'size': size,
                        'permissions': perms,
                        'address': getattr(mmap, 'addr', 'N/A')
                    })
            
            # Windows fallback: If we have very little region data, estimate from process memory
            if total_size == 0 and region_count > 0:
                # Get process memory info to estimate regions
                try:
                    process = psutil.Process(pid)
                    memory_info = process.memory_info()
                    
                    # Estimate regions based on total memory
                    estimated_total = memory_info.rss
                    if estimated_total > 0:
                        # Distribute memory across regions (rough estimates)
                        estimated_regions = {
                            'text': estimated_total * 0.15,      # 15% for code
                            'data': estimated_total * 0.25,      # 25% for data
                            'heap': estimated_total * 0.30,      # 30% for heap
                            'stack': estimated_total * 0.05,     # 5% for stack
                            'libs': estimated_total * 0.20,      # 20% for libraries
                            'anonymous': estimated_total * 0.05   # 5% for anonymous
                        }
                        
                        # Update regions with estimated data
                        for region_type, estimated_size in estimated_regions.items():
                            if regions[region_type]:  # If we have region entries
                                # Update the size of the first region
                                if regions[region_type]:
                                    regions[region_type][0]['size'] = int(estimated_size)
                        
                        total_size = estimated_total
                except Exception:
                    pass
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'total_regions': region_count,
                'total_size': total_size,
                'regions': regions,
                'summary': self._summarize_regions(regions),
                'platform_note': 'Windows - Some memory region sizes estimated due to platform limitations'
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def _summarize_regions(self, regions: Dict[str, List]) -> Dict[str, Any]:
        """Summarize memory regions"""
        summary = {}
        
        for region_type, region_list in regions.items():
            if region_list:
                total_size = sum(region['size'] for region in region_list)
                summary[region_type] = {
                    'count': len(region_list),
                    'total_size': total_size,
                    'average_size': total_size / len(region_list) if region_list else 0
                }
            else:
                summary[region_type] = {
                    'count': 0,
                    'total_size': 0,
                    'average_size': 0
                }
        
        return summary
    
    def analyze_cpu_behavior(self, pid: int) -> Dict[str, Any]:
        """Analyze CPU behavior for a process"""
        try:
            process = psutil.Process(pid)
            
            # Get CPU times
            cpu_times = process.cpu_times()
            
            # Get CPU affinity
            cpu_affinity = process.cpu_affinity()
            
            # Get thread information
            threads = process.threads()
            
            # Get CPU usage with longer measurement period for accuracy
            cpu_percent = process.cpu_percent()  # First call (returns 0)
            time.sleep(2.0)  # Wait 2 seconds for accurate measurement
            cpu_percent = process.cpu_percent()  # Second call (returns actual percentage)
            
            # If still 0, try with longer interval method
            if cpu_percent == 0:
                try:
                    cpu_percent = process.cpu_percent(interval=2.0)  # 2-second measurement
                except:
                    cpu_percent = 0
            
            # Get process status
            status = process.status()
            
            # Handle different CPU times attributes
            cpu_times_data = {}
            if hasattr(cpu_times, 'user'):
                cpu_times_data['user_time'] = cpu_times.user
            else:
                cpu_times_data['user_time'] = 0.0
                
            if hasattr(cpu_times, 'system'):
                cpu_times_data['system_time'] = cpu_times.system
            else:
                cpu_times_data['system_time'] = 0.0
                
            if hasattr(cpu_times, 'children_user'):
                cpu_times_data['children_user'] = cpu_times.children_user
            else:
                cpu_times_data['children_user'] = 0.0
                
            if hasattr(cpu_times, 'children_system'):
                cpu_times_data['children_system'] = cpu_times.children_system
            else:
                cpu_times_data['children_system'] = 0.0
            
            # Handle thread information
            thread_data = []
            for thread in threads:
                thread_info = {'id': thread.id}
                if hasattr(thread, 'user_time'):
                    thread_info['user_time'] = thread.user_time
                else:
                    thread_info['user_time'] = 0.0
                    
                if hasattr(thread, 'system_time'):
                    thread_info['system_time'] = thread.system_time
                else:
                    thread_info['system_time'] = 0.0
                    
                thread_data.append(thread_info)
            
            # Handle nice and ionice
            nice_value = 0
            ionice_value = None
            try:
                nice_value = process.nice()
            except (psutil.AccessDenied, AttributeError):
                pass
                
            try:
                ionice_value = getattr(process, 'ionice', lambda: None)()
            except (psutil.AccessDenied, AttributeError):
                pass
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'cpu_times': cpu_times_data,
                'cpu_affinity': cpu_affinity,
                'num_threads': len(threads),
                'threads': thread_data,
                'cpu_percent': cpu_percent,
                'status': status,
                'nice': nice_value,
                'ionice': ionice_value
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def get_memory_layout_analysis(self, pid: int) -> Dict[str, Any]:
        """Get memory layout analysis (simplified page table simulation)"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            
            # Get memory maps for detailed analysis
            memory_maps = []
            try:
                memory_maps = process.memory_maps()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Simulate page table analysis
            page_analysis = {
                'virtual_pages': 0,
                'resident_pages': 0,
                'shared_pages': 0,
                'private_pages': 0,
                'readable_pages': 0,
                'writable_pages': 0,
                'executable_pages': 0
            }
            
            total_virtual_size = 0
            total_resident_size = 0
            
            # First, try to analyze memory maps if available
            if memory_maps:
                for mmap in memory_maps:
                    # Handle different memory map object types
                    if hasattr(mmap, 'size'):
                        size = mmap.size
                    elif hasattr(mmap, 'length'):
                        size = mmap.length
                    elif hasattr(mmap, 'rss'):
                        size = mmap.rss
                    else:
                        size = 0
                    
                    # Skip if size is 0
                    if size == 0:
                        continue
                    
                    total_virtual_size += size
                    
                    # Estimate pages (assuming 4KB pages)
                    estimated_pages = max(1, size // 4096)  # At least 1 page
                    page_analysis['virtual_pages'] += estimated_pages
                    
                    # Analyze permissions
                    perms = getattr(mmap, 'perms', '')
                    if perms:
                        if 'r' in perms:
                            page_analysis['readable_pages'] += estimated_pages
                        if 'w' in perms:
                            page_analysis['writable_pages'] += estimated_pages
                        if 'x' in perms:
                            page_analysis['executable_pages'] += estimated_pages
                    
                    # Estimate resident pages based on path and type
                    path = getattr(mmap, 'path', '') or ''
                    if path and path != '[anon]':
                        # Executable files and libraries are more likely to be resident
                        if any(x in path.lower() for x in ['.exe', '.dll', '.so', 'lib']):
                            page_analysis['resident_pages'] += estimated_pages * 3 // 4  # 75% resident
                        else:
                            page_analysis['resident_pages'] += estimated_pages // 2  # 50% resident
                    else:
                        # Anonymous memory is typically resident
                        page_analysis['resident_pages'] += estimated_pages * 2 // 3  # 67% resident
                    
                    # Estimate shared pages
                    if any(x in path.lower() for x in ['shared', 'lib', 'dll', 'so']):
                        page_analysis['shared_pages'] += estimated_pages
                    else:
                        # Estimate some pages as shared based on typical patterns
                        page_analysis['shared_pages'] += estimated_pages // 4  # 25% shared
            
            # If memory maps didn't provide good data, use process memory info as fallback
            if total_virtual_size == 0 or page_analysis['virtual_pages'] == 0:
                # Use VMS (Virtual Memory Size) for virtual pages
                total_virtual_size = memory_info.vms
                virtual_pages = max(1, total_virtual_size // 4096)
                page_analysis['virtual_pages'] = virtual_pages
                
                # Use RSS (Resident Set Size) for resident pages
                total_resident_size = memory_info.rss
                resident_pages = max(1, total_resident_size // 4096)
                page_analysis['resident_pages'] = resident_pages
                
                # Estimate other page types based on typical process patterns
                page_analysis['readable_pages'] = virtual_pages * 4 // 5  # 80% readable
                page_analysis['writable_pages'] = virtual_pages * 3 // 5  # 60% writable
                page_analysis['executable_pages'] = virtual_pages // 4    # 25% executable
                page_analysis['shared_pages'] = virtual_pages // 3        # 33% shared
                page_analysis['private_pages'] = virtual_pages * 2 // 3   # 67% private
            
            # Ensure private pages calculation is correct
            page_analysis['private_pages'] = max(0, page_analysis['virtual_pages'] - page_analysis['shared_pages'])
            
            # Ensure we have reasonable values (at least 1 page for each type if virtual_pages > 0)
            if page_analysis['virtual_pages'] > 0:
                page_analysis['resident_pages'] = max(1, page_analysis['resident_pages'])
                page_analysis['readable_pages'] = max(1, page_analysis['readable_pages'])
                page_analysis['writable_pages'] = max(1, page_analysis['writable_pages'])
                page_analysis['private_pages'] = max(1, page_analysis['private_pages'])
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'page_analysis': page_analysis,
                'memory_maps_count': len(memory_maps),
                'total_virtual_size': total_virtual_size,
                'total_resident_size': total_resident_size,
                'note': f'Page table simulation based on process memory info. Real page tables are kernel-internal. Platform: {platform.system()}'
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def get_system_memory_context(self) -> Dict[str, Any]:
        """Get system-wide memory context"""
        try:
            # System memory
            system_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            # Memory statistics
            memory_stats = {}
            try:
                # Try to get memory statistics (Linux)
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            memory_stats[key.strip()] = value.strip()
            except FileNotFoundError:
                # Windows or other systems
                memory_stats = {'note': 'Detailed memory stats not available on this system'}
            
            return {
                'timestamp': time.time(),
                'system_memory': {
                    'total': system_memory.total,
                    'available': system_memory.available,
                    'used': system_memory.used,
                    'free': system_memory.free,
                    'percent': system_memory.percent,
                    'buffers': getattr(system_memory, 'buffers', 0),
                    'cached': getattr(system_memory, 'cached', 0)
                },
                'swap_memory': {
                    'total': swap_memory.total,
                    'used': swap_memory.used,
                    'free': swap_memory.free,
                    'percent': swap_memory.percent
                },
                'memory_stats': memory_stats
            }
            
        except Exception as e:
            return {'error': f"Error getting system memory context: {e}"}
    
    def get_comprehensive_analysis(self, pid: int) -> Dict[str, Any]:
        """Get comprehensive memory analysis for a process"""
        # Check cache first
        cache_key = f"analysis_{pid}"
        if cache_key in self.analysis_cache:
            cached_data, cache_time = self.analysis_cache[cache_key]
            if time.time() - cache_time < self.cache_duration:
                return cached_data
        
        # Perform comprehensive analysis
        analysis = {
            'pid': pid,
            'timestamp': time.time(),
            'detailed_memory': self.get_detailed_memory_info(pid),
            'memory_regions': self.analyze_memory_regions(pid),
            'cpu_behavior': self.analyze_cpu_behavior(pid),
            'memory_layout': self.get_memory_layout_analysis(pid),
            'system_context': self.get_system_memory_context(),
            'educational_notes': {
                'page_tables': 'Page tables are kernel-internal structures not accessible from user space',
                'tlb': 'TLB (Translation Lookaside Buffer) is hardware-specific and not user-accessible',
                'segmentation': 'Memory segmentation details require kernel-level access',
                'limitations': 'This analysis shows what is possible with user-space tools like psutil'
            }
        }
        
        # Cache the result
        self.analysis_cache[cache_key] = (analysis, time.time())
        
        return analysis
    
    def format_memory_size(self, size_bytes: int) -> str:
        """Format memory size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def get_process_memory_summary(self, pid: int) -> str:
        """Get a formatted summary of process memory usage"""
        try:
            analysis = self.get_comprehensive_analysis(pid)
            
            if 'error' in analysis:
                return f"Error: {analysis['error']}"
            
            memory_info = analysis['detailed_memory']['memory_info']
            regions = analysis['memory_regions']['summary']
            layout = analysis['memory_layout']
            
            # Check if we have platform notes
            platform_note = analysis['memory_regions'].get('platform_note', '')
            
            summary = f"""
Process Memory Analysis for PID {pid}
{'='*50}

Memory Usage:
- RSS (Resident Set Size): {self.format_memory_size(memory_info['rss'])}
- VMS (Virtual Memory Size): {self.format_memory_size(memory_info['vms'])}
- Shared Memory: {self.format_memory_size(memory_info['shared'])}
- Text Segment: {self.format_memory_size(memory_info['text'])}
- Data Segment: {self.format_memory_size(memory_info['data'])}

Memory Regions:
- Text Segments: {regions['text']['count']} regions ({self.format_memory_size(regions['text']['total_size'])})
- Data Segments: {regions['data']['count']} regions ({self.format_memory_size(regions['data']['total_size'])})
- Heap Segments: {regions['heap']['count']} regions ({self.format_memory_size(regions['heap']['total_size'])})
- Stack Segments: {regions['stack']['count']} regions ({self.format_memory_size(regions['stack']['total_size'])})
- Library Segments: {regions['libs']['count']} regions ({self.format_memory_size(regions['libs']['total_size'])})
- Anonymous Memory: {regions['anonymous']['count']} regions ({self.format_memory_size(regions['anonymous']['total_size'])})

CPU Behavior:
- CPU Usage: {analysis['cpu_behavior']['cpu_percent']:.2f}%
- Number of Threads: {analysis['cpu_behavior']['num_threads']}
- Process Status: {analysis['cpu_behavior']['status']}
- User Time: {analysis['cpu_behavior']['cpu_times']['user_time']:.2f}s
- System Time: {analysis['cpu_behavior']['cpu_times']['system_time']:.2f}s

Page Table Simulation:
- Virtual Pages: {layout['page_analysis']['virtual_pages']:,}
- Resident Pages: {layout['page_analysis']['resident_pages']:,}
- Shared Pages: {layout['page_analysis']['shared_pages']:,}
- Private Pages: {layout['page_analysis']['private_pages']:,}

Notes:
- This analysis shows user-space accessible memory information
- Real page tables, TLB, and segmentation details require kernel-level access
- Platform: {platform.system()} - Some features may be limited on Windows
- {platform_note if platform_note else 'Memory region data available'}
"""
            
            return summary
            
        except Exception as e:
            return f"Error generating summary: {e}"


# Example usage and testing
if __name__ == "__main__":
    analyzer = MemoryAnalyzer()
    
    # Test with current process
    current_pid = os.getpid()
    print(f"Analyzing current process (PID: {current_pid})")
    
    # Get comprehensive analysis
    analysis = analyzer.get_comprehensive_analysis(current_pid)
    
    # Print summary
    print(analyzer.get_process_memory_summary(current_pid))
    
    # Print detailed analysis
    print("\nDetailed Analysis:")
    print(f"Memory Regions: {analysis['memory_regions']['total_regions']} regions")
    print(f"Total Size: {analyzer.format_memory_size(analysis['memory_regions']['total_size'])}")
    
    # Print educational notes
    print("\nEducational Notes:")
    for key, note in analysis['educational_notes'].items():
        print(f"- {key.replace('_', ' ').title()}: {note}")
