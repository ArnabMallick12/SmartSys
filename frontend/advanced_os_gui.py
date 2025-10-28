"""
Advanced OS Features GUI Component
Phase 3: File System, IPC, Deadlock Detection, Memory Management, Real-Time Systems
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from typing import Dict, Any, Optional

# Add backend to path
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

try:
    from backend.advanced_os_features import AdvancedOSFeatures
except ImportError as e:
    print(f"Warning: Could not import AdvancedOSFeatures: {e}")


class AdvancedOSGUI:
    """GUI component for advanced OS features"""
    
    def __init__(self, parent_frame):
        """Initialize the advanced OS features GUI"""
        self.parent_frame = parent_frame
        self.advanced_features = AdvancedOSFeatures()
        self.current_pid = None
        self.analysis_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the advanced OS features UI"""
        # Main container
        main_frame = ttk.Frame(self.parent_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced OS Features", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Control panel
        self.setup_control_panel(main_frame)
        
        # Analysis results
        self.setup_results_panel(main_frame)
    
    def setup_control_panel(self, parent):
        """Set up the control panel"""
        control_frame = ttk.LabelFrame(parent, text="Analysis Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # PID input
        pid_frame = ttk.Frame(control_frame)
        pid_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pid_frame, text="Process ID:").pack(side=tk.LEFT)
        self.pid_entry = ttk.Entry(pid_frame, width=10)
        self.pid_entry.pack(side=tk.LEFT, padx=(5, 10))
        self.pid_entry.insert(0, str(os.getpid()))  # Default to current process
        
        # Analysis buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        # Row 1 buttons
        row1_frame = ttk.Frame(button_frame)
        row1_frame.pack(fill=tk.X, pady=2)
        
        ttk.Button(row1_frame, text="File System Analysis", 
                  command=self.analyze_file_system).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row1_frame, text="IPC Analysis", 
                  command=self.analyze_ipc).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row1_frame, text="Deadlock Detection", 
                  command=self.detect_deadlock).pack(side=tk.LEFT, padx=(0, 5))
        
        # Row 2 buttons
        row2_frame = ttk.Frame(button_frame)
        row2_frame.pack(fill=tk.X, pady=2)
        
        ttk.Button(row2_frame, text="Memory Management", 
                  command=self.analyze_memory_management).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row2_frame, text="Real-Time Analysis", 
                  command=self.analyze_real_time).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row2_frame, text="Comprehensive Analysis", 
                  command=self.comprehensive_analysis).pack(side=tk.LEFT, padx=(0, 5))
        
        # Row 3 buttons
        row3_frame = ttk.Frame(button_frame)
        row3_frame.pack(fill=tk.X, pady=2)
        
        ttk.Button(row3_frame, text="Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row3_frame, text="Browse Processes", 
                  command=self.browse_processes).pack(side=tk.LEFT, padx=(0, 5))
    
    def setup_results_panel(self, parent):
        """Set up the results display panel"""
        results_frame = ttk.LabelFrame(parent, text="Analysis Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for different analysis types
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # File System tab
        self.filesystem_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.filesystem_frame, text="File System")
        
        self.filesystem_text = scrolledtext.ScrolledText(self.filesystem_frame, wrap=tk.WORD, 
                                                        height=15, width=80, font=('Courier', 9))
        self.filesystem_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # IPC Analysis tab
        self.ipc_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.ipc_frame, text="IPC Analysis")
        
        self.ipc_text = scrolledtext.ScrolledText(self.ipc_frame, wrap=tk.WORD, 
                                                 height=15, width=80)
        self.ipc_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Deadlock Detection tab
        self.deadlock_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.deadlock_frame, text="Deadlock Detection")
        
        self.deadlock_text = scrolledtext.ScrolledText(self.deadlock_frame, wrap=tk.WORD, 
                                                      height=15, width=80, font=('Courier', 9))
        self.deadlock_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Memory Management tab
        self.memory_mgmt_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.memory_mgmt_frame, text="Memory Management")
        
        self.memory_mgmt_text = scrolledtext.ScrolledText(self.memory_mgmt_frame, wrap=tk.WORD, 
                                                         height=15, width=80)
        self.memory_mgmt_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Real-Time Systems tab
        self.realtime_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.realtime_frame, text="Real-Time Systems")
        
        self.realtime_text = scrolledtext.ScrolledText(self.realtime_frame, wrap=tk.WORD, 
                                                      height=15, width=80)
        self.realtime_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Educational Content tab
        self.education_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.education_frame, text="OS Concepts")
        
        self.education_text = scrolledtext.ScrolledText(self.education_frame, wrap=tk.WORD, 
                                                       height=15, width=80)
        self.education_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add educational content
        self.add_educational_content()
    
    def add_educational_content(self):
        """Add educational content about advanced OS concepts"""
        content = """
Advanced Operating System Concepts
==================================

1. File System Management
   - Directory structure and inode management
   - Disk allocation strategies (contiguous, linked, indexed)
   - File access methods and permissions
   - Fragmentation and optimization techniques

2. Inter-Process Communication (IPC)
   - Shared memory segments
   - Message queues and pipes
   - Semaphores and mutexes
   - Socket communication
   - Synchronization mechanisms

3. Deadlock Detection and Prevention
   - Resource allocation graphs
   - Deadlock detection algorithms
   - Prevention strategies (resource ordering, preemption)
   - Recovery mechanisms
   - Banker's algorithm

4. Memory Management Algorithms
   - Dynamic allocation (malloc/free)
   - Garbage collection strategies
   - Memory fragmentation analysis
   - Heap management techniques
   - Memory pooling

5. Real-Time Systems
   - Priority inversion problems
   - Rate Monotonic Scheduling (RMS)
   - Earliest Deadline First (EDF)
   - Real-time constraints and deadlines
   - Priority inheritance protocols

6. Process Synchronization
   - Critical section problem
   - Mutual exclusion algorithms
   - Semaphores and monitors
   - Readers-writers problem
   - Producer-consumer problem

7. Security and Protection
   - Access control matrices
   - Capability-based security
   - Memory protection mechanisms
   - Process isolation
   - Sandboxing techniques

Educational Value:
=================
These simulations demonstrate complex OS concepts in an interactive way,
helping students understand:
- How operating systems manage resources
- Common problems and their solutions
- Trade-offs between different algorithms
- Real-world system behavior patterns

Note: These are educational simulations and may not reflect
exact real-world system behavior due to platform limitations.
"""
        
        self.education_text.insert(1.0, content)
        self.education_text.config(state=tk.DISABLED)
    
    def get_current_pid(self) -> Optional[int]:
        """Get the current PID from the entry field"""
        try:
            pid_str = self.pid_entry.get().strip()
            if pid_str:
                return int(pid_str)
        except ValueError:
            messagebox.showerror("Invalid PID", "Please enter a valid process ID")
        return None
    
    def analyze_file_system(self):
        """Analyze file system structure and disk allocation"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.filesystem_text.delete(1.0, tk.END)
        self.filesystem_text.insert(1.0, f"Analyzing file system structure for PID {pid}...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._analyze_file_system_thread, daemon=True)
        self.analysis_thread.start()
    
    def _analyze_file_system_thread(self):
        """File system analysis thread"""
        try:
            # Get file system structure
            fs_structure = self.advanced_features.file_system.visualize_file_system(self.current_pid)
            
            # Get disk allocation simulation
            disk_allocation = self.advanced_features.file_system.simulate_disk_allocation(self.current_pid)
            
            # Format results
            results = self._format_filesystem_results(fs_structure, disk_allocation)
            
            # Update GUI in main thread
            self.filesystem_text.after(0, self._update_filesystem, results)
            
        except Exception as e:
            error_msg = f"Error analyzing file system: {e}"
            self.filesystem_text.after(0, self._update_filesystem, error_msg)
    
    def analyze_ipc(self):
        """Analyze inter-process communication"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.ipc_text.delete(1.0, tk.END)
        self.ipc_text.insert(1.0, f"Analyzing IPC usage for PID {pid}...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._analyze_ipc_thread, daemon=True)
        self.analysis_thread.start()
    
    def _analyze_ipc_thread(self):
        """IPC analysis thread"""
        try:
            ipc_result = self.advanced_features.ipc_analyzer.analyze_ipc_usage(self.current_pid)
            
            # Format results
            results = self._format_ipc_results(ipc_result)
            
            # Update GUI in main thread
            self.ipc_text.after(0, self._update_ipc, results)
            
        except Exception as e:
            error_msg = f"Error analyzing IPC: {e}"
            self.ipc_text.after(0, self._update_ipc, error_msg)
    
    def detect_deadlock(self):
        """Detect deadlocks and analyze resource allocation"""
        self.deadlock_text.delete(1.0, tk.END)
        self.deadlock_text.insert(1.0, "Analyzing deadlock scenarios...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._detect_deadlock_thread, daemon=True)
        self.analysis_thread.start()
    
    def _detect_deadlock_thread(self):
        """Deadlock detection thread"""
        try:
            deadlock_result = self.advanced_features.deadlock_detector.simulate_deadlock_scenario()
            
            # Format results
            results = self._format_deadlock_results(deadlock_result)
            
            # Update GUI in main thread
            self.deadlock_text.after(0, self._update_deadlock, results)
            
        except Exception as e:
            error_msg = f"Error detecting deadlock: {e}"
            self.deadlock_text.after(0, self._update_deadlock, error_msg)
    
    def analyze_memory_management(self):
        """Analyze memory management algorithms"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.memory_mgmt_text.delete(1.0, tk.END)
        self.memory_mgmt_text.insert(1.0, f"Analyzing memory management algorithms for PID {pid}...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._analyze_memory_management_thread, daemon=True)
        self.analysis_thread.start()
    
    def _analyze_memory_management_thread(self):
        """Memory management analysis thread"""
        try:
            # Simulate malloc/free operations
            malloc_result = self.advanced_features.memory_manager.simulate_malloc_free(15, self.current_pid)
            
            # Simulate garbage collection
            gc_result = self.advanced_features.memory_manager.simulate_garbage_collection()
            
            # Format results
            results = self._format_memory_management_results(malloc_result, gc_result)
            
            # Update GUI in main thread
            self.memory_mgmt_text.after(0, self._update_memory_mgmt, results)
            
        except Exception as e:
            error_msg = f"Error analyzing memory management: {e}"
            self.memory_mgmt_text.after(0, self._update_memory_mgmt, error_msg)
    
    def analyze_real_time(self):
        """Analyze real-time system concepts"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.realtime_text.delete(1.0, tk.END)
        self.realtime_text.insert(1.0, f"Analyzing real-time concepts for PID {pid}...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._analyze_real_time_thread, daemon=True)
        self.analysis_thread.start()
    
    def _analyze_real_time_thread(self):
        """Real-time analysis thread"""
        try:
            # Analyze priority inversion
            priority_result = self.advanced_features.real_time_analyzer.analyze_priority_inversion(self.current_pid)
            
            # Simulate rate monotonic scheduling
            rms_result = self.advanced_features.real_time_analyzer.simulate_rate_monotonic_scheduling(self.current_pid)
            
            # Format results
            results = self._format_realtime_results(priority_result, rms_result)
            
            # Update GUI in main thread
            self.realtime_text.after(0, self._update_realtime, results)
            
        except Exception as e:
            error_msg = f"Error analyzing real-time concepts: {e}"
            self.realtime_text.after(0, self._update_realtime, error_msg)
    
    def comprehensive_analysis(self):
        """Run comprehensive analysis of all advanced features"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        
        # Clear all text areas
        self.clear_results()
        
        # Show progress
        self.filesystem_text.insert(1.0, "Running comprehensive analysis...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._comprehensive_analysis_thread, daemon=True)
        self.analysis_thread.start()
    
    def _comprehensive_analysis_thread(self):
        """Comprehensive analysis thread"""
        try:
            analysis = self.advanced_features.get_comprehensive_analysis(self.current_pid)
            
            if 'error' in analysis:
                error_msg = f"Error in comprehensive analysis: {analysis['error']}"
                self.filesystem_text.after(0, self._update_filesystem, error_msg)
                return
            
            # Update each tab with results
            fs_results = self._format_filesystem_results(
                analysis['file_system']['structure'],
                analysis['file_system']['disk_allocation']
            )
            self.filesystem_text.after(0, self._update_filesystem, fs_results)
            
            ipc_results = self._format_ipc_results(analysis['ipc_analysis'])
            self.ipc_text.after(0, self._update_ipc, ipc_results)
            
            deadlock_results = self._format_deadlock_results(analysis['deadlock_analysis'])
            self.deadlock_text.after(0, self._update_deadlock, deadlock_results)
            
            memory_results = self._format_memory_management_results(
                analysis['memory_management']['malloc_free'],
                analysis['memory_management']['garbage_collection']
            )
            self.memory_mgmt_text.after(0, self._update_memory_mgmt, memory_results)
            
            realtime_results = self._format_realtime_results(
                analysis['real_time_analysis']['priority_inversion'],
                analysis['real_time_analysis']['rate_monotonic']
            )
            self.realtime_text.after(0, self._update_realtime, realtime_results)
            
        except Exception as e:
            error_msg = f"Error in comprehensive analysis: {e}"
            self.filesystem_text.after(0, self._update_filesystem, error_msg)
    
    def browse_processes(self):
        """Browse and select from running processes"""
        # Create process selection dialog
        dialog = ProcessSelectionDialog(self.parent_frame)
        if dialog.result:
            self.pid_entry.delete(0, tk.END)
            self.pid_entry.insert(0, str(dialog.result))
    
    def clear_results(self):
        """Clear all analysis results"""
        self.filesystem_text.delete(1.0, tk.END)
        self.ipc_text.delete(1.0, tk.END)
        self.deadlock_text.delete(1.0, tk.END)
        self.memory_mgmt_text.delete(1.0, tk.END)
        self.realtime_text.delete(1.0, tk.END)
    
    # Update methods for each tab
    def _update_filesystem(self, text):
        """Update file system text"""
        self.filesystem_text.delete(1.0, tk.END)
        self.filesystem_text.insert(1.0, text)
        self.results_notebook.select(0)  # Switch to file system tab
    
    def _update_ipc(self, text):
        """Update IPC text"""
        self.ipc_text.delete(1.0, tk.END)
        self.ipc_text.insert(1.0, text)
        self.results_notebook.select(1)  # Switch to IPC tab
    
    def _update_deadlock(self, text):
        """Update deadlock text"""
        self.deadlock_text.delete(1.0, tk.END)
        self.deadlock_text.insert(1.0, text)
        self.results_notebook.select(2)  # Switch to deadlock tab
    
    def _update_memory_mgmt(self, text):
        """Update memory management text"""
        self.memory_mgmt_text.delete(1.0, tk.END)
        self.memory_mgmt_text.insert(1.0, text)
        self.results_notebook.select(3)  # Switch to memory management tab
    
    def _update_realtime(self, text):
        """Update real-time text"""
        self.realtime_text.delete(1.0, tk.END)
        self.realtime_text.insert(1.0, text)
        self.results_notebook.select(4)  # Switch to real-time tab
    
    # Formatting methods
    def _format_filesystem_results(self, structure, allocation):
        """Format file system analysis results"""
        if 'error' in allocation:
            return f"Error: {allocation['error']}"
        
        results = f"""
File System Analysis
{'='*50}

File System Structure:
{structure}

Disk Allocation Analysis:
- Total Blocks: {allocation['total_blocks']:,}
- Used Blocks: {allocation['used_blocks']:,}
- Free Blocks: {allocation['free_blocks']:,}
- Block Size: {allocation['block_size']:,} bytes

Fragmentation Analysis:
- Internal Fragmentation: {allocation['fragmentation']['internal_fragmentation']:.1f}%
- External Fragmentation: {allocation['fragmentation']['external_fragmentation']:.1f}%
- Fragmentation Level: {allocation['fragmentation']['fragmentation_level']}

File Allocation Details:
"""
        
        for filename, file_info in allocation['allocation_map'].items():
            results += f"""
File: {filename}
- Inode: {file_info['inode']}
- Size: {file_info['size']:,} bytes
- Blocks Needed: {file_info['blocks_needed']}
- Allocation Type: {file_info['allocation_type']}
- Allocated Blocks: {file_info['allocated_blocks']}
"""
        
        return results
    
    def _format_ipc_results(self, ipc_result):
        """Format IPC analysis results"""
        if 'error' in ipc_result:
            return f"Error: {ipc_result['error']}"
        
        results = f"""
IPC Analysis for PID {ipc_result['pid']}
{'='*40}

Shared Memory:
- Segments: {ipc_result['shared_memory']['segments']}
- Total Size: {ipc_result['shared_memory']['total_size']:,} bytes
- Attached Processes: {ipc_result['shared_memory']['attached_processes']}
- Status: {ipc_result['shared_memory']['status']}

Message Queues:
- Queues: {ipc_result['message_queues']['queues']}
- Messages Sent: {ipc_result['message_queues']['messages_sent']:,}
- Messages Received: {ipc_result['message_queues']['messages_received']:,}
- Queue Size: {ipc_result['message_queues']['queue_size']}
- Status: {ipc_result['message_queues']['status']}

Semaphores:
- Semaphores: {ipc_result['semaphores']['semaphores']}
- Operations: {ipc_result['semaphores']['operations']:,}
- Wait Operations: {ipc_result['semaphores']['wait_operations']:,}
- Signal Operations: {ipc_result['semaphores']['signal_operations']:,}
- Status: {ipc_result['semaphores']['status']}

Pipes:
- Pipes: {ipc_result['pipes']['pipes']}
- Read Pipes: {ipc_result['pipes']['read_pipes']}
- Write Pipes: {ipc_result['pipes']['write_pipes']}
- Status: {ipc_result['pipes']['status']}

Sockets:
- Sockets: {ipc_result['sockets']['sockets']}
- TCP Connections: {ipc_result['sockets']['tcp_connections']}
- UDP Connections: {ipc_result['sockets']['udp_connections']}
- Listening Ports: {ipc_result['sockets']['listening_ports']}
- Established Connections: {ipc_result['sockets']['established_connections']}
- Status: {ipc_result['sockets']['status']}

IPC Summary:
- Total IPC Objects: {ipc_result['ipc_summary']['total_ipc_objects']}
- Active IPC Objects: {ipc_result['ipc_summary']['active_ipc_objects']}
- IPC Utilization: {ipc_result['ipc_summary']['ipc_utilization']:.1f}%
- Communication Intensity: {ipc_result['ipc_summary']['communication_intensity']}
"""
        return results
    
    def _format_deadlock_results(self, deadlock_result):
        """Format deadlock detection results"""
        if 'error' in deadlock_result:
            return f"Error: {deadlock_result['error']}"
        
        results = f"""
Deadlock Detection Analysis
{'='*40}

Deadlock Status: {'DETECTED' if deadlock_result['deadlock_detected'] else 'NOT DETECTED'}

Process Information:
"""
        
        for pid, proc in deadlock_result['processes'].items():
            results += f"""
{pid}:
- Allocated Resources: {', '.join(proc['allocated'])}
- Requested Resources: {', '.join(proc['requested'])}
"""
        
        results += f"""
Resource Information:
"""
        
        for rid, resource in deadlock_result['resources'].items():
            results += f"""
{rid}:
- Total: {resource['total']}
- Available: {resource['available']}
- Allocated To: {', '.join(resource['allocated_to'])}
"""
        
        if deadlock_result['deadlock_detected']:
            results += f"""
Deadlock Cycle: {' -> '.join(deadlock_result['deadlock_cycle'])} -> {deadlock_result['deadlock_cycle'][0]}

Resource Allocation Graph:
{deadlock_result['allocation_graph']}

Prevention Suggestions:
"""
            for i, suggestion in enumerate(deadlock_result['prevention_suggestions'], 1):
                results += f"{i}. {suggestion}\n"
            
            results += "\nRecovery Strategies:\n"
            for i, strategy in enumerate(deadlock_result['recovery_strategies'], 1):
                results += f"{i}. {strategy}\n"
        else:
            results += "\nSystem is deadlock-free!\n"
        
        return results
    
    def _format_memory_management_results(self, malloc_result, gc_result):
        """Format memory management analysis results"""
        if 'error' in malloc_result:
            return f"Error: {malloc_result['error']}"
        
        if 'error' in gc_result:
            return f"Error in garbage collection: {gc_result['error']}"
        
        # Calculate averages safely
        avg_fragmentation = 0
        avg_efficiency = 0
        avg_heap_usage = 0
        
        if malloc_result.get('memory_fragmentation'):
            avg_fragmentation = sum(malloc_result['memory_fragmentation']) / len(malloc_result['memory_fragmentation'])
        
        if malloc_result.get('allocation_efficiency'):
            avg_efficiency = sum(malloc_result['allocation_efficiency']) / len(malloc_result['allocation_efficiency'])
        
        if malloc_result.get('heap_usage'):
            avg_heap_usage = sum(malloc_result['heap_usage']) / len(malloc_result['heap_usage'])
        
        results = f"""
Memory Management Analysis
{'='*40}

Malloc/Free Operations:
- Total Operations: {len(malloc_result.get('operations', []))}
- Average Fragmentation: {avg_fragmentation:.2f}%
- Average Allocation Efficiency: {avg_efficiency:.2f}%
- Average Heap Usage: {avg_heap_usage:.2f}%

Recent Operations:
"""
        
        operations = malloc_result.get('operations', [])
        for i, op in enumerate(operations[-5:], 1):  # Show last 5 operations
            if op.get('type') == 'malloc':
                if 'status' in op:
                    results += f"{i}. {op['type'].upper()}: {op['size']} bytes - {op['status']}\n"
                else:
                    results += f"{i}. {op['type'].upper()}: {op['size']} bytes, {op['blocks']} blocks\n"
            else:
                results += f"{i}. {op['type'].upper()}: {op['size']} bytes freed\n"
        
        results += f"""
Garbage Collection Analysis:
"""
        
        for algorithm, gc_data in gc_result.items():
            if algorithm != 'comparison' and isinstance(gc_data, dict):
                results += f"""
{gc_data.get('algorithm', algorithm)}:
- Overhead: {gc_data.get('overhead', 'N/A')}
- Pause Time: {gc_data.get('pause_time', 'N/A')}
- Memory Efficiency: {gc_data.get('memory_efficiency', 0):.1f}%
- CPU Overhead: {gc_data.get('cpu_overhead', 0):.1f}%
- Cycles Collected: {gc_data.get('cycles_collected', 0)}
- Objects Freed: {gc_data.get('objects_freed', 0)}
"""
        
        comparison = gc_result.get('comparison', {})
        results += f"""
GC Algorithm Comparison:
- Best Memory Efficiency: {comparison.get('best_memory_efficiency', 0):.1f}%
- Lowest CPU Overhead: {comparison.get('lowest_cpu_overhead', 0):.1f}%
- Recommendation: {comparison.get('recommendation', 'N/A')}
"""
        
        return results
    
    def _format_realtime_results(self, priority_result, rms_result):
        """Format real-time analysis results"""
        if 'error' in priority_result:
            return f"Error: {priority_result['error']}"
        
        results = f"""
Real-Time System Analysis
{'='*40}

Priority Inversion Analysis:
- Priority Inversion Detected: {'YES' if priority_result['analysis']['priority_inversion_detected'] else 'NO'}
- Severity: {priority_result['analysis']['severity']}
- Affected Tasks: {', '.join(priority_result['analysis']['affected_tasks'])}
- Blocking Tasks: {', '.join(priority_result['analysis']['blocking_tasks'])}
- Response Time Impact: {priority_result['analysis']['response_time_impact']:.1f}%
- Deadline Miss Probability: {priority_result['analysis']['deadline_miss_probability']:.1%}

Solutions:
"""
        for i, solution in enumerate(priority_result['solutions'], 1):
            results += f"{i}. {solution}\n"
        
        results += f"""
Rate Monotonic Scheduling Analysis:
- Schedulable: {'YES' if rms_result['feasibility']['schedulable'] else 'NO'}
- Feasible: {'YES' if rms_result['feasibility']['feasible'] else 'NO'}
- Utilization Bound: {rms_result['feasibility']['utilization_bound']:.3f}
- Actual Utilization: {rms_result['feasibility']['actual_utilization']:.3f}
- Utilization Percentage: {rms_result['feasibility']['utilization_percentage']:.1f}%

Task Schedule (first 10 events):
"""
        
        for i, event in enumerate(rms_result['schedule'][:10], 1):
            results += f"{i}. Time {event['time']}: {event['task']} (exec: {event['execution_time']}, deadline: {event['deadline']})\n"
        
        results += f"""
Recommendations:
"""
        for i, rec in enumerate(rms_result['recommendations'], 1):
            results += f"{i}. {rec}\n"
        
        return results


class ProcessSelectionDialog:
    """Dialog for selecting a process"""
    
    def __init__(self, parent):
        """Initialize the process selection dialog"""
        self.result = None
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Select Process")
        self.dialog.geometry("600x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self.setup_ui()
        
        # Wait for dialog to close
        self.dialog.wait_window()
    
    def setup_ui(self):
        """Set up the dialog UI"""
        # Title
        title_label = ttk.Label(self.dialog, text="Select a Process", 
                               font=('Arial', 12, 'bold'))
        title_label.pack(pady=10)
        
        # Process list
        columns = ('PID', 'Name', 'CPU%', 'Memory%')
        self.tree = ttk.Treeview(self.dialog, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('PID', text='PID')
        self.tree.heading('Name', text='Process Name')
        self.tree.heading('CPU%', text='CPU %')
        self.tree.heading('Memory%', text='Memory %')
        
        self.tree.column('PID', width=80)
        self.tree.column('Name', width=200)
        self.tree.column('CPU%', width=80)
        self.tree.column('Memory%', width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.dialog, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Select", command=self.select_process).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.refresh_processes).pack(side=tk.LEFT, padx=5)
        
        # Load processes
        self.refresh_processes()
    
    def refresh_processes(self):
        """Refresh the process list"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add processes
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    self.tree.insert('', 'end', values=(
                        proc_info['pid'],
                        proc_info['name'],
                        f"{proc_info['cpu_percent'] or 0:.1f}",
                        f"{proc_info['memory_percent'] or 0:.1f}"
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"Error refreshing processes: {e}")
    
    def select_process(self):
        """Select the highlighted process"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            pid = int(item['values'][0])
            self.result = pid
            self.dialog.destroy()
        else:
            messagebox.showwarning("No Selection", "Please select a process")
    
    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()
