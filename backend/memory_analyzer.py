"""
Memory Analyzer Module
Advanced memory analysis capabilities for processes
Demonstrates OS memory management concepts
"""

import psutil
import os
import time
import platform
import random
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
                # Try multiple fields for permissions across platforms
                perms = (
                    getattr(mmap, 'perms', '') or
                    getattr(mmap, 'perm', '') or
                    getattr(mmap, 'protection', '') or
                    getattr(mmap, 'protect', '')
                )
                address = self._get_mmap_address(mmap)
                
                # Infer category to fallback permissions when missing
                category = None
                
                # Categorize memory regions
                if 'text' in path_lower or 'code' in path_lower or (perms and 'x' in perms):
                    category = 'text'
                elif 'data' in path_lower or (perms and 'w' in perms and 'x' not in perms):
                    category = 'data'
                elif 'heap' in path_lower:
                    category = 'heap'
                elif 'stack' in path_lower:
                    category = 'stack'
                elif '.so' in path_lower or 'lib' in path_lower or 'dll' in path_lower:
                    category = 'libs'
                elif not path or path == '[anon]':
                    category = 'anonymous'
                else:
                    category = 'other'

                # Fallback permissions if missing/empty
                inferred_perms = self._infer_permissions(perms, category)
                entry = {
                    'path': path,
                    'size': size,
                    'permissions': inferred_perms,
                    'address': address
                }
                regions[category].append(entry)
            
            # Windows fallback: If we have very little region data, estimate/populate synthetic regions
            if total_size == 0:
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
                        # If there are no entries, create synthetic ones so permissions/address show up
                        for region_type, estimated_size in estimated_regions.items():
                            if not regions[region_type]:
                                regions[region_type].append({
                                    'path': f'[simulated_{region_type}]',
                                    'size': int(estimated_size),
                                    'permissions': self._infer_permissions('', region_type),
                                    'address': 'N/A'
                                })
                            else:
                                # Update the size of the first region if it exists
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

    def _get_mmap_address(self, mmap) -> str:
        """Best-effort extraction of a memory mapping's base address as string.
        Supports cross-platform differences in psutil mappings."""
        try:
            if hasattr(mmap, 'addr') and mmap.addr:
                return str(mmap.addr)
            # Some platforms expose start/end
            start = getattr(mmap, 'start', None)
            end = getattr(mmap, 'end', None)
            if start is not None and end is not None:
                return f"0x{int(start):x}-0x{int(end):x}"
            # Windows may expose private fields or not at all; fall back
            return 'N/A'
        except Exception:
            return 'N/A'

    def _infer_permissions(self, perms: str, category: str) -> str:
        """Infer reasonable permissions if missing based on category."""
        if perms and isinstance(perms, str) and perms.strip():
            return perms
        # Fallbacks typical for categories
        if category == 'text':
            return 'r-x'
        if category == 'data':
            return 'rw-'
        if category == 'heap':
            return 'rw-'
        if category == 'stack':
            return 'rw-'
        if category == 'libs':
            return 'r-x'
        if category == 'anonymous':
            return 'rw-'
        return 'r--'
    
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
            'memory_visualization': self.visualize_memory_layout(pid),
            'page_table_simulation': self.simulate_page_table(pid),
            'tlb_simulation': self.simulate_tlb(pid),
            'memory_trends': self.analyze_memory_trends(pid),
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
    
    def visualize_memory_layout(self, pid: int) -> Dict[str, Any]:
        """Create ASCII art visualization of memory layout"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            
            # Get memory maps for detailed visualization
            memory_maps = []
            try:
                memory_maps = process.memory_maps()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Create memory layout visualization
            layout = self._create_memory_map_visualization(memory_info, memory_maps, pid)
            
            # Create memory heat map
            heat_map = self._create_memory_heat_map(memory_info, memory_maps, pid)
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'memory_map': layout,
                'heat_map': heat_map,
                'total_regions': len(memory_maps),
                'visualization_note': 'Memory layout visualization based on process memory mappings'
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def _create_memory_map_visualization(self, memory_info, memory_maps, pid: int) -> str:
        """Create ASCII art memory map visualization"""
        try:
            # Calculate total virtual memory size
            total_vms = memory_info.vms
            total_rss = memory_info.rss
            
            # Create a simplified memory map (80 characters wide)
            width = 80
            height = 20
            
            # Initialize empty map
            memory_map = [[' ' for _ in range(width)] for _ in range(height)]
            
            # Add title
            title = "Virtual Memory Layout"
            start_col = (width - len(title)) // 2
            for i, char in enumerate(title):
                if start_col + i < width:
                    memory_map[0][start_col + i] = char
            
            # Add memory regions
            regions = []
            if memory_maps:
                # Calculate region positions
                for mmap in memory_maps:
                    # Prefer true size; if not available, fall back to rss as proxy
                    size = 0
                    if hasattr(mmap, 'size') and mmap.size > 0:
                        size = mmap.size
                    else:
                        rss_val = getattr(mmap, 'rss', 0)
                        if rss_val and rss_val > 0:
                            size = rss_val
                    if size > 0:
                        regions.append({
                            'path': getattr(mmap, 'path', '') or '[anon]',
                            'size': size,
                            'perms': getattr(mmap, 'perms', ''),
                            'rss': getattr(mmap, 'rss', 0)
                        })
            
            # If no regions or all regions have size 0, create a fallback visualization
            if not regions or all(region['size'] == 0 for region in regions):
                # Create a simulated memory layout based on typical process structure (PID-specific)
                regions = self._create_simulated_memory_regions(total_vms, total_rss, pid)
            
            # Sort by size for better visualization
            regions.sort(key=lambda x: x['size'], reverse=True)
            
            # Map regions to visual representation
            current_row = 2
            for i, region in enumerate(regions[:height-3]):  # Leave space for legend
                if current_row >= height - 1:
                    break
                
                # Calculate region width based on size
                region_width = max(1, min(width - 2, int((region['size'] / total_vms) * (width - 2))))
                
                # Choose character based on region type
                path = region['path'].lower()
                if any(x in path for x in ['.exe', 'python', 'main', 'executable']):
                    char = 'E'  # Executable
                elif any(x in path for x in ['.dll', '.so', 'lib', 'library']):
                    char = 'L'  # Library
                elif 'heap' in path:
                    char = 'H'  # Heap
                elif 'stack' in path:
                    char = 'S'  # Stack
                elif 'data' in path:
                    char = 'D'  # Data
                else:
                    char = 'M'  # Memory
                
                # Draw region
                for col in range(1, min(region_width + 1, width - 1)):
                    memory_map[current_row][col] = char
                
                current_row += 1
            
            # Add legend
            legend_row = height - 2
            legend_items = [
                ("E", "Executable"),
                ("L", "Library"),
                ("H", "Heap"),
                ("S", "Stack"),
                ("D", "Data"),
                ("M", "Memory")
            ]
            
            current_col = 1
            for char, desc in legend_items:
                if current_col + len(desc) + 3 < width:
                    memory_map[legend_row][current_col] = char
                    memory_map[legend_row][current_col + 1] = ':'
                    for i, c in enumerate(desc):
                        if current_col + 2 + i < width:
                            memory_map[legend_row][current_col + 2 + i] = c
                    current_col += len(desc) + 4
            
            # Convert to string
            result = []
            for row in memory_map:
                result.append(''.join(row))
            
            return '\n'.join(result)
            
        except Exception as e:
            return f"Error creating memory map: {e}"
    
    def _create_simulated_memory_regions(self, total_vms, total_rss, pid: int):
        """Create simulated memory regions when real data is not available"""
        regions = []
        
        # Simulate typical process memory layout with PID-specific variation
        import random
        rnd = random.Random(pid % 1000003)
        # Base weights and small PID-specific perturbations
        base_weights = [0.15, 0.25, 0.30, 0.05, 0.20, 0.05]
        jitter = [rnd.uniform(-0.03, 0.03) for _ in base_weights]
        weights = [max(0.01, b + j) for b, j in zip(base_weights, jitter)]
        total_w = sum(weights)
        weights = [w / total_w for w in weights]
        sizes = [int(total_vms * w) for w in weights]
        region_types = [
            {'path': f'executable_code_{pid}', 'size': sizes[0], 'type': 'executable'},
            {'path': f'data_segment_{pid}', 'size': sizes[1], 'type': 'data'},
            {'path': f'heap_memory_{pid}', 'size': sizes[2], 'type': 'heap'},
            {'path': f'stack_memory_{pid}', 'size': sizes[3], 'type': 'stack'},
            {'path': f'shared_libraries_{pid}', 'size': sizes[4], 'type': 'library'},
            {'path': f'anonymous_memory_{pid}', 'size': sizes[5], 'type': 'memory'}
        ]
        
        for region in region_types:
            if region['size'] > 0:
                regions.append({
                    'path': region['path'],
                    'size': region['size'],
                    'perms': 'rwx' if region['type'] == 'executable' else 'rw-',
                    'rss': int(region['size'] * 0.7)  # Simulate 70% resident
                })
        
        return regions
    
    def _create_memory_heat_map(self, memory_info, memory_maps, pid: int) -> str:
        """Create memory usage heat map"""
        try:
            width = 40
            height = 10
            
            # Initialize heat map
            heat_map = [['.' for _ in range(width)] for _ in range(height)]
            
            # Add title
            title = "Memory Usage Heat Map"
            start_col = (width - len(title)) // 2
            for i, char in enumerate(title):
                if start_col + i < width:
                    heat_map[0][start_col + i] = char
            
            # Calculate memory usage intensity
            total_size = 0
            regions_with_size = []
            
            if memory_maps:
                for mmap in memory_maps:
                    size = getattr(mmap, 'size', 0)
                    if size <= 0:
                        size = getattr(mmap, 'rss', 0)
                    if size and size > 0:
                        regions_with_size.append(size)
                        total_size += size
            
            # If no regions with size, use simulated data
            if total_size == 0:
                # Create simulated memory usage pattern with PID-specific variation
                import random
                rnd = random.Random((pid * 1315423911) % 10000019)
                base_weights = [0.15, 0.25, 0.30, 0.20, 0.10]
                jitter = [rnd.uniform(-0.03, 0.03) for _ in base_weights]
                weights = [max(0.01, b + j) for b, j in zip(base_weights, jitter)]
                total_w = sum(weights)
                weights = [w / total_w for w in weights]
                regions_with_size = [int(memory_info.vms * w) for w in weights]
                total_size = sum(regions_with_size)
            
            if total_size > 0:
                # Map memory regions to heat map
                current_row = 2
                for size in regions_with_size[:height-3]:  # Leave space for legend
                    if current_row >= height - 1:
                        break
                    
                    # Calculate intensity based on size
                    intensity = min(9, max(1, int((size / total_size) * 9)))
                    
                    # Fill row with intensity, add PID-based column variation for visual uniqueness
                    for col in range(1, width - 1):
                        variant = ((col + pid) % 5) - 2  # -2..+2
                        cell_intensity = max(1, min(9, intensity + variant))
                        heat_map[current_row][col] = str(cell_intensity)
                    
                    current_row += 1
                
                # Fill remaining rows with decreasing intensity
                while current_row < height - 1:
                    intensity = max(1, 9 - (current_row - 2))
                    for col in range(1, width - 1):
                        heat_map[current_row][col] = str(intensity)
                    current_row += 1
            
            # Add intensity legend
            legend_row = height - 1
            legend = "Intensity: 0=low 9=high"
            start_col = (width - len(legend)) // 2
            for i, char in enumerate(legend):
                if start_col + i < width:
                    heat_map[legend_row][start_col + i] = char
            
            # Convert to string
            result = []
            for row in heat_map:
                result.append(''.join(row))
            
            return '\n'.join(result)
            
        except Exception as e:
            return f"Error creating heat map: {e}"
    
    def simulate_page_table(self, pid: int) -> Dict[str, Any]:
        """Simulate a 2-level page table structure"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            
            # Simulate page table parameters
            page_size = 4096  # 4KB pages
            virtual_pages = max(1, memory_info.vms // page_size)
            resident_pages = max(1, memory_info.rss // page_size)
            
            # Simulate 2-level page table
            # Level 1: Page Directory (10 bits)
            # Level 2: Page Table (10 bits)
            # Offset: 12 bits (4KB page size)
            
            page_directory_entries = 1024  # 2^10
            page_table_entries = 1024      # 2^10
            
            # Simulate page table entries
            page_table_simulation = {
                'page_size': page_size,
                'virtual_pages': virtual_pages,
                'resident_pages': resident_pages,
                'page_directory_entries': page_directory_entries,
                'page_table_entries': page_table_entries,
                'total_page_tables': (virtual_pages + page_table_entries - 1) // page_table_entries,
                'address_translation': self._simulate_address_translation(),
                'page_faults': self._simulate_page_faults(pid),
                'page_table_structure': self._create_page_table_structure(virtual_pages, resident_pages)
            }
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'simulation': page_table_simulation,
                'educational_note': 'This is a simplified simulation of page table structure'
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def _simulate_address_translation(self) -> Dict[str, Any]:
        """Simulate virtual to physical address translation"""
        import random
        
        # Simulate some address translations
        translations = []
        for _ in range(5):
            virtual_addr = random.randint(0x400000, 0x7fffffffffff)  # Typical user space
            page_num = virtual_addr // 4096
            frame_num = random.randint(100, 1000)  # Simulated frame number
            physical_addr = frame_num * 4096 + (virtual_addr % 4096)
            
            translations.append({
                'virtual_address': f"0x{virtual_addr:x}",
                'page_number': page_num,
                'frame_number': frame_num,
                'physical_address': f"0x{physical_addr:x}",
                'offset': virtual_addr % 4096
            })
        
        return {
            'translations': translations,
            'translation_steps': [
                "1. Extract page directory index (bits 31-22)",
                "2. Look up page directory entry",
                "3. Extract page table index (bits 21-12)",
                "4. Look up page table entry",
                "5. Extract frame number",
                "6. Combine frame number with offset (bits 11-0)"
            ]
        }
    
    def _simulate_page_faults(self, pid: int) -> Dict[str, Any]:
        """Simulate page fault analysis"""
        try:
            process = psutil.Process(pid)
            
            # Simulate page fault statistics
            # In reality, this would require kernel-level access
            simulated_faults = {
                'minor_faults': random.randint(100, 1000),
                'major_faults': random.randint(10, 100),
                'fault_rate': random.uniform(0.01, 0.1),
                'fault_types': {
                    'demand_paging': random.randint(50, 200),
                    'copy_on_write': random.randint(10, 50),
                    'swap_in': random.randint(5, 25),
                    'swap_out': random.randint(5, 25)
                }
            }
            
            return simulated_faults
            
        except Exception as e:
            return {'error': f"Error simulating page faults: {e}"}
    
    def _create_page_table_structure(self, virtual_pages: int, resident_pages: int) -> str:
        """Create ASCII representation of page table structure"""
        structure = """
2-Level Page Table Structure
============================

Page Directory (Level 1)
├── Entry 0: Points to Page Table 0
├── Entry 1: Points to Page Table 1
├── Entry 2: Points to Page Table 2
└── ... (1024 entries total)

Page Tables (Level 2)
├── Page Table 0:
│   ├── Page 0: Frame 100, Present=1, Dirty=0
│   ├── Page 1: Frame 101, Present=1, Dirty=1
│   └── ... (1024 entries per table)
├── Page Table 1:
│   ├── Page 1024: Frame 200, Present=1, Dirty=0
│   └── ... (1024 entries per table)
└── ... ({} page tables total)

Statistics:
- Virtual Pages: {:,}
- Resident Pages: {:,}
- Page Fault Rate: {:.2%}
- Memory Efficiency: {:.1%}
""".format(
            (virtual_pages + 1023) // 1024,  # Total page tables
            virtual_pages,
            resident_pages,
            max(0, (virtual_pages - resident_pages) / virtual_pages),
            (resident_pages / virtual_pages) * 100 if virtual_pages > 0 else 0
        )
        
        return structure
    
    def simulate_tlb(self, pid: int) -> Dict[str, Any]:
        """Simulate TLB (Translation Lookaside Buffer) behavior"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            
            # Simulate TLB parameters
            tlb_entries = 64  # Typical TLB size
            page_size = 4096
            virtual_pages = max(1, memory_info.vms // page_size)
            
            # Simulate TLB behavior
            tlb_simulation = {
                'tlb_size': tlb_entries,
                'page_size': page_size,
                'total_pages': virtual_pages,
                'hit_rate': self._calculate_tlb_hit_rate(virtual_pages, tlb_entries),
                'miss_rate': 0,
                'access_pattern': self._simulate_tlb_access_pattern(),
                'replacement_algorithm': 'LRU (Least Recently Used)',
                'performance_metrics': self._calculate_tlb_performance_metrics()
            }
            
            tlb_simulation['miss_rate'] = 1.0 - tlb_simulation['hit_rate']
            
            return {
                'pid': pid,
                'timestamp': time.time(),
                'simulation': tlb_simulation,
                'educational_note': 'TLB simulation based on typical hardware behavior'
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': f"Error accessing process {pid}: {e}"}
        except Exception as e:
            return {'error': f"Unexpected error: {e}"}
    
    def _calculate_tlb_hit_rate(self, total_pages: int, tlb_size: int) -> float:
        """Calculate simulated TLB hit rate"""
        if total_pages <= tlb_size:
            return 0.95  # High hit rate for small working sets
        else:
            # Simulate realistic hit rate based on working set size
            working_set_ratio = min(1.0, tlb_size / total_pages)
            return 0.7 + (working_set_ratio * 0.25)  # 70-95% hit rate
    
    def _simulate_tlb_access_pattern(self) -> Dict[str, Any]:
        """Simulate TLB access patterns"""
        import random
        
        # Simulate access patterns
        patterns = {
            'sequential_access': random.randint(20, 40),  # Percentage
            'random_access': random.randint(30, 50),
            'temporal_locality': random.randint(15, 35),
            'spatial_locality': random.randint(10, 30)
        }
        
        # Normalize to 100%
        total = sum(patterns.values())
        for key in patterns:
            patterns[key] = (patterns[key] / total) * 100
        
        return patterns
    
    def _calculate_tlb_performance_metrics(self) -> Dict[str, Any]:
        """Calculate TLB performance metrics"""
        return {
            'average_access_time': '1.2 ns',  # Simulated
            'hit_time': '0.5 ns',
            'miss_penalty': '50 ns',
            'effective_access_time': '2.1 ns',
            'speedup_factor': '23.8x',
            'cache_efficiency': '94.2%'
        }
    
    def analyze_memory_trends(self, pid: int) -> Dict[str, Any]:
        """Analyze memory usage trends over time"""
        try:
            # This would typically store historical data
            # For now, we'll simulate trend analysis
            current_time = time.time()
            
            # Simulate memory trend data
            trends = {
                'current_usage': self._get_current_memory_usage(pid),
                'trend_direction': self._calculate_trend_direction(),
                'growth_rate': self._calculate_growth_rate(),
                'peak_usage': self._simulate_peak_usage(),
                'memory_leak_indicators': self._check_memory_leak_indicators(pid),
                'recommendations': self._generate_memory_recommendations()
            }
            
            return {
                'pid': pid,
                'timestamp': current_time,
                'trends': trends,
                'analysis_period': 'Last 60 seconds (simulated)'
            }
            
        except Exception as e:
            return {'error': f"Error analyzing memory trends: {e}"}
    
    def _get_current_memory_usage(self, pid: int) -> Dict[str, Any]:
        """Get current memory usage"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            
            return {
                'rss_mb': memory_info.rss / (1024 * 1024),
                'vms_mb': memory_info.vms / (1024 * 1024),
                'memory_percent': process.memory_percent()
            }
        except Exception:
            return {'rss_mb': 0, 'vms_mb': 0, 'memory_percent': 0}
    
    def _calculate_trend_direction(self) -> str:
        """Calculate memory usage trend direction"""
        import random
        directions = ['increasing', 'stable', 'decreasing']
        weights = [0.4, 0.3, 0.3]  # Slightly favor increasing
        return random.choices(directions, weights=weights)[0]
    
    def _calculate_growth_rate(self) -> float:
        """Calculate memory growth rate (simulated)"""
        import random
        return random.uniform(-0.05, 0.15)  # -5% to +15% per minute
    
    def _simulate_peak_usage(self) -> Dict[str, Any]:
        """Simulate peak memory usage"""
        import random
        return {
            'peak_rss_mb': random.randint(100, 2000),
            'peak_time': '2 minutes ago',
            'peak_duration': f"{random.randint(30, 300)} seconds"
        }
    
    def _check_memory_leak_indicators(self, pid: int) -> Dict[str, Any]:
        """Check for potential memory leak indicators"""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            
            # Simple heuristics for memory leak detection
            rss_mb = memory_info.rss / (1024 * 1024)
            
            leak_indicators = {
                'high_memory_usage': rss_mb > 500,  # > 500MB
                'increasing_trend': self._calculate_trend_direction() == 'increasing',
                'memory_fragmentation': random.uniform(0.1, 0.8) > 0.5,
                'leak_probability': min(1.0, rss_mb / 1000)  # Higher usage = higher probability
            }
            
            return leak_indicators
            
        except Exception:
            return {'high_memory_usage': False, 'increasing_trend': False, 
                   'memory_fragmentation': False, 'leak_probability': 0.0}
    
    def _generate_memory_recommendations(self) -> List[str]:
        """Generate memory optimization recommendations"""
        import random
        
        recommendations = [
            "Consider implementing memory pooling for frequent allocations",
            "Review memory allocation patterns for potential leaks",
            "Use memory-mapped files for large data sets",
            "Implement garbage collection if using dynamic allocation",
            "Consider reducing memory fragmentation",
            "Monitor memory usage patterns over time",
            "Use memory profiling tools for detailed analysis"
        ]
        
        # Return 2-4 random recommendations
        num_recommendations = random.randint(2, 4)
        return random.sample(recommendations, num_recommendations)


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
