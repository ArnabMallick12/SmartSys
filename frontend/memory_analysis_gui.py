"""
Memory Analysis GUI Component
Advanced memory analysis interface for SmartSys
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
    from backend.memory_analyzer import MemoryAnalyzer
except ImportError as e:
    print(f"Warning: Could not import MemoryAnalyzer: {e}")


class MemoryAnalysisGUI:
    """GUI component for memory analysis"""
    
    def __init__(self, parent_frame):
        """Initialize the memory analysis GUI"""
        self.parent_frame = parent_frame
        self.analyzer = MemoryAnalyzer()
        self.current_pid = None
        self.analysis_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the memory analysis UI"""
        # Main container
        main_frame = ttk.Frame(self.parent_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Memory Analysis", 
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
        
        ttk.Button(button_frame, text="Quick Analysis", 
                  command=self.quick_analysis).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Comprehensive Analysis", 
                  command=self.comprehensive_analysis).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Memory Regions", 
                  command=self.analyze_memory_regions).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="CPU Behavior", 
                  command=self.analyze_cpu_behavior).pack(side=tk.LEFT, padx=(0, 5))
        
        # Phase 1 new buttons
        button_frame2 = ttk.Frame(control_frame)
        button_frame2.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame2, text="Memory Visualization", 
                  command=self.visualize_memory_layout).pack(side=tk.LEFT, padx=(0, 5))
        # Removed Page Table and TLB simulations (per project requirement)
        ttk.Button(button_frame2, text="Memory Trends", 
                  command=self.analyze_memory_trends).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame2, text="Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT, padx=(0, 5))
        
        # Process selection
        selection_frame = ttk.Frame(control_frame)
        selection_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(selection_frame, text="Or select from running processes:").pack(side=tk.LEFT)
        ttk.Button(selection_frame, text="Browse Processes", 
                  command=self.browse_processes).pack(side=tk.LEFT, padx=(10, 0))
    
    def setup_results_panel(self, parent):
        """Set up the results display panel"""
        results_frame = ttk.LabelFrame(parent, text="Analysis Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for different analysis types
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_frame, text="Summary")
        
        self.summary_text = scrolledtext.ScrolledText(self.summary_frame, wrap=tk.WORD, 
                                                     height=15, width=80)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Memory Regions tab
        self.regions_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.regions_frame, text="Memory Regions")
        
        self.regions_text = scrolledtext.ScrolledText(self.regions_frame, wrap=tk.WORD, 
                                                     height=15, width=80)
        self.regions_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # CPU Behavior tab
        self.cpu_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.cpu_frame, text="CPU Behavior")
        
        self.cpu_text = scrolledtext.ScrolledText(self.cpu_frame, wrap=tk.WORD, 
                                                 height=15, width=80)
        self.cpu_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Educational Notes tab
        self.education_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.education_frame, text="OS Concepts")
        
        self.education_text = scrolledtext.ScrolledText(self.education_frame, wrap=tk.WORD, 
                                                       height=15, width=80)
        self.education_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Phase 1 new tabs
        # Memory Visualization tab
        self.visualization_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.visualization_frame, text="Memory Visualization")
        
        self.visualization_text = scrolledtext.ScrolledText(self.visualization_frame, wrap=tk.WORD, 
                                                           height=15, width=80, font=('Courier', 9))
        self.visualization_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Removed Page Table and TLB tabs
        
        # Memory Trends tab
        self.trends_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.trends_frame, text="Memory Trends")
        
        self.trends_text = scrolledtext.ScrolledText(self.trends_frame, wrap=tk.WORD, 
                                                    height=15, width=80)
        self.trends_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add educational content
        self.add_educational_content()
    
    def add_educational_content(self):
        """Add educational content about OS memory management"""
        content = """
OS Memory Management Concepts
=============================

1. Virtual Memory
   - Each process has its own virtual address space
   - Virtual addresses are translated to physical addresses
   - Allows processes to use more memory than physically available

2. Page Tables
   - Data structure that maps virtual pages to physical pages
   - Each process has its own page table
   - Page table entries contain page frame numbers and access permissions

3. TLB (Translation Lookaside Buffer)
   - Hardware cache for page table entries
   - Speeds up virtual-to-physical address translation
   - Contains recently used page table entries

4. Memory Segmentation
   - Divides memory into logical segments (text, data, heap, stack)
   - Each segment has different permissions and purposes
   - Segments can grow and shrink dynamically

5. Memory Regions
   - Text: Executable code
   - Data: Global and static variables
   - Heap: Dynamically allocated memory
   - Stack: Function calls and local variables
   - Libraries: Shared libraries and DLLs

6. Page Faults
   - Occur when accessing a page not in physical memory
   - Trigger page loading from disk (swap)
   - Handled by the operating system

7. Memory Protection
   - Read, Write, Execute permissions for memory pages
   - Prevents unauthorized access to memory
   - Enforced by hardware and operating system

Limitations of User-Space Analysis:
===================================
- Cannot access kernel-internal page tables
- Cannot see TLB contents (hardware-specific)
- Cannot access segmentation tables directly
- Limited to memory mappings visible to user space

What We Can Analyze:
===================
- Virtual memory layout and regions
- Memory usage statistics
- Process memory mappings
- CPU behavior and scheduling
- System memory context
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
    
    def quick_analysis(self):
        """Perform quick memory analysis"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, "Performing quick analysis...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._quick_analysis_thread, daemon=True)
        self.analysis_thread.start()
    
    def _quick_analysis_thread(self):
        """Quick analysis thread"""
        try:
            summary = self.analyzer.get_process_memory_summary(self.current_pid)
            
            # Update GUI in main thread
            self.summary_text.after(0, self._update_summary, summary)
            
        except Exception as e:
            error_msg = f"Error during analysis: {e}"
            self.summary_text.after(0, self._update_summary, error_msg)
    
    def comprehensive_analysis(self):
        """Perform comprehensive memory analysis"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, "Performing comprehensive analysis...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._comprehensive_analysis_thread, daemon=True)
        self.analysis_thread.start()
    
    def _comprehensive_analysis_thread(self):
        """Comprehensive analysis thread"""
        try:
            analysis = self.analyzer.get_comprehensive_analysis(self.current_pid)
            
            # Format results
            results = self._format_comprehensive_results(analysis)
            
            # Update GUI in main thread
            self.summary_text.after(0, self._update_summary, results)
            
        except Exception as e:
            error_msg = f"Error during comprehensive analysis: {e}"
            self.summary_text.after(0, self._update_summary, error_msg)
    
    def analyze_memory_regions(self):
        """Analyze memory regions"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.regions_text.delete(1.0, tk.END)
        self.regions_text.insert(1.0, "Analyzing memory regions...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._memory_regions_thread, daemon=True)
        self.analysis_thread.start()
    
    def _memory_regions_thread(self):
        """Memory regions analysis thread"""
        try:
            regions = self.analyzer.analyze_memory_regions(self.current_pid)
            
            # Format results
            results = self._format_memory_regions_results(regions)
            
            # Update GUI in main thread
            self.regions_text.after(0, self._update_regions, results)
            
        except Exception as e:
            error_msg = f"Error analyzing memory regions: {e}"
            self.regions_text.after(0, self._update_regions, error_msg)
    
    def analyze_cpu_behavior(self):
        """Analyze CPU behavior"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.cpu_text.delete(1.0, tk.END)
        self.cpu_text.insert(1.0, "Analyzing CPU behavior...\n(This will take about 4-6 seconds for accurate measurement)\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._cpu_behavior_thread, daemon=True)
        self.analysis_thread.start()
    
    def _cpu_behavior_thread(self):
        """CPU behavior analysis thread"""
        try:
            cpu_behavior = self.analyzer.analyze_cpu_behavior(self.current_pid)
            
            # Format results
            results = self._format_cpu_behavior_results(cpu_behavior)
            
            # Update GUI in main thread
            self.cpu_text.after(0, self._update_cpu, results)
            
        except Exception as e:
            error_msg = f"Error analyzing CPU behavior: {e}"
            self.cpu_text.after(0, self._update_cpu, error_msg)
    
    def browse_processes(self):
        """Browse and select from running processes"""
        # Create process selection dialog
        dialog = ProcessSelectionDialog(self.parent_frame)
        if dialog.result:
            self.pid_entry.delete(0, tk.END)
            self.pid_entry.insert(0, str(dialog.result))
    
    def clear_results(self):
        """Clear all analysis results"""
        self.summary_text.delete(1.0, tk.END)
        self.regions_text.delete(1.0, tk.END)
        self.cpu_text.delete(1.0, tk.END)
        self.visualization_text.delete(1.0, tk.END)
        self.page_table_text.delete(1.0, tk.END)
        self.tlb_text.delete(1.0, tk.END)
        self.trends_text.delete(1.0, tk.END)
    
    def visualize_memory_layout(self):
        """Visualize memory layout"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.visualization_text.delete(1.0, tk.END)
        self.visualization_text.insert(1.0, "Creating memory layout visualization...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._visualize_memory_layout_thread, daemon=True)
        self.analysis_thread.start()
    
    def _visualize_memory_layout_thread(self):
        """Memory layout visualization thread"""
        try:
            visualization = self.analyzer.visualize_memory_layout(self.current_pid)
            
            # Format results
            results = self._format_memory_visualization_results(visualization)
            
            # Update GUI in main thread
            self.visualization_text.after(0, self._update_visualization, results)
            
        except Exception as e:
            error_msg = f"Error creating memory visualization: {e}"
            self.visualization_text.after(0, self._update_visualization, error_msg)
    
    # Removed Page Table and TLB simulation actions
    
    def analyze_memory_trends(self):
        """Analyze memory trends"""
        pid = self.get_current_pid()
        if pid is None:
            return
        
        self.current_pid = pid
        self.trends_text.delete(1.0, tk.END)
        self.trends_text.insert(1.0, "Analyzing memory trends...\n")
        
        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._analyze_memory_trends_thread, daemon=True)
        self.analysis_thread.start()
    
    def _analyze_memory_trends_thread(self):
        """Memory trends analysis thread"""
        try:
            trends = self.analyzer.analyze_memory_trends(self.current_pid)
            
            # Format results
            results = self._format_memory_trends_results(trends)
            
            # Update GUI in main thread
            self.trends_text.after(0, self._update_trends, results)
            
        except Exception as e:
            error_msg = f"Error analyzing memory trends: {e}"
            self.trends_text.after(0, self._update_trends, error_msg)
    
    def _update_summary(self, text):
        """Update summary text"""
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, text)
        self.results_notebook.select(self.summary_frame)
    
    def _update_regions(self, text):
        """Update regions text"""
        self.regions_text.delete(1.0, tk.END)
        self.regions_text.insert(1.0, text)
        self.results_notebook.select(self.regions_frame)
    
    def _update_cpu(self, text):
        """Update CPU text"""
        self.cpu_text.delete(1.0, tk.END)
        self.cpu_text.insert(1.0, text)
        self.results_notebook.select(self.cpu_frame)
    
    def _update_visualization(self, text):
        """Update visualization text"""
        self.visualization_text.delete(1.0, tk.END)
        self.visualization_text.insert(1.0, text)
        self.results_notebook.select(self.visualization_frame)
    
    # Removed page table updater
    
    # Removed TLB updater
    
    def _update_trends(self, text):
        """Update trends text"""
        self.trends_text.delete(1.0, tk.END)
        self.trends_text.insert(1.0, text)
        self.results_notebook.select(self.trends_frame)
    
    def _format_comprehensive_results(self, analysis):
        """Format comprehensive analysis results"""
        if 'error' in analysis:
            return f"Error: {analysis['error']}"
        
        results = f"""
Comprehensive Memory Analysis for PID {analysis['pid']}
{'='*60}

Memory Information:
- RSS: {self.analyzer.format_memory_size(analysis['detailed_memory']['memory_info']['rss'])}
- VMS: {self.analyzer.format_memory_size(analysis['detailed_memory']['memory_info']['vms'])}
- Shared: {self.analyzer.format_memory_size(analysis['detailed_memory']['memory_info']['shared'])}

Memory Regions Summary:
- Total Regions: {analysis['memory_regions']['total_regions']}
- Total Size: {self.analyzer.format_memory_size(analysis['memory_regions']['total_size'])}

CPU Behavior:
- CPU Usage: {analysis['cpu_behavior']['cpu_percent']:.2f}%
- Threads: {analysis['cpu_behavior']['num_threads']}
- Status: {analysis['cpu_behavior']['status']}
- User Time: {analysis['cpu_behavior']['cpu_times']['user_time']:.2f}s
- System Time: {analysis['cpu_behavior']['cpu_times']['system_time']:.2f}s

Page Table Simulation:
- Virtual Pages: {analysis['memory_layout']['page_analysis']['virtual_pages']:,}
- Resident Pages: {analysis['memory_layout']['page_analysis']['resident_pages']:,}
- Shared Pages: {analysis['memory_layout']['page_analysis']['shared_pages']:,}

System Context:
- System Memory: {self.analyzer.format_memory_size(analysis['system_context']['system_memory']['total'])}
- Available: {self.analyzer.format_memory_size(analysis['system_context']['system_memory']['available'])}
- Used: {analysis['system_context']['system_memory']['percent']:.1f}%

Educational Notes:
{analysis['educational_notes']['page_tables']}
{analysis['educational_notes']['tlb']}
{analysis['educational_notes']['segmentation']}
{analysis['educational_notes']['limitations']}
"""
        return results
    
    def _format_memory_regions_results(self, regions):
        """Format memory regions results"""
        if 'error' in regions:
            return f"Error: {regions['error']}"
        
        results = f"""
Memory Regions Analysis for PID {regions['pid']}
{'='*50}

Total Regions: {regions['total_regions']}
Total Size: {self.analyzer.format_memory_size(regions['total_size'])}

Region Details:
"""
        
        for region_type, region_list in regions['regions'].items():
            if region_list:
                results += f"\n{region_type.upper()} REGIONS ({len(region_list)} regions):\n"
                results += "-" * 40 + "\n"
                
                for i, region in enumerate(region_list[:10]):  # Show first 10
                    results += f"{i+1}. {region['path']}\n"
                    results += f"   Size: {self.analyzer.format_memory_size(region['size'])}\n"
                    results += f"   Permissions: {region['permissions']}\n"
                    results += f"   Address: {region['address']}\n\n"
                
                if len(region_list) > 10:
                    results += f"... and {len(region_list) - 10} more regions\n\n"
        
        return results
    
    def _format_cpu_behavior_results(self, cpu_behavior):
        """Format CPU behavior results"""
        if 'error' in cpu_behavior:
            return f"Error: {cpu_behavior['error']}"
        
        results = f"""
CPU Behavior Analysis for PID {cpu_behavior['pid']}
{'='*45}

Process Information:
- CPU Usage: {cpu_behavior['cpu_percent']:.2f}%
- Status: {cpu_behavior['status']}
- Number of Threads: {cpu_behavior['num_threads']}

CPU Times:
- User Time: {cpu_behavior['cpu_times']['user_time']:.2f} seconds
- System Time: {cpu_behavior['cpu_times']['system_time']:.2f} seconds
- Children User Time: {cpu_behavior['cpu_times']['children_user']:.2f} seconds
- Children System Time: {cpu_behavior['cpu_times']['children_system']:.2f} seconds

CPU Affinity: {cpu_behavior['cpu_affinity']}

Thread Details:
"""
        
        for i, thread in enumerate(cpu_behavior['threads'][:10]):  # Show first 10 threads
            results += f"Thread {i+1} (ID: {thread['id']}):\n"
            results += f"  User Time: {thread['user_time']:.2f}s\n"
            results += f"  System Time: {thread['system_time']:.2f}s\n"
        
        if len(cpu_behavior['threads']) > 10:
            results += f"\n... and {len(cpu_behavior['threads']) - 10} more threads\n"
        
        return results
    
    def _format_memory_visualization_results(self, visualization):
        """Format memory visualization results"""
        if 'error' in visualization:
            return f"Error: {visualization['error']}"
        
        results = f"""
Memory Layout Visualization for PID {visualization['pid']}
{'='*60}

Memory Map:
{visualization['memory_map']}

Memory Heat Map:
{visualization['heat_map']}

Statistics:
- Total Memory Regions: {visualization['total_regions']}
- Visualization Note: {visualization['visualization_note']}

Legend:
- E: Executable code
- L: Library/DLL files
- H: Heap memory
- S: Stack memory
- D: Data segments
- M: Other memory regions

Heat Map Intensity:
- 0-2: Low memory usage
- 3-5: Medium memory usage
- 6-9: High memory usage
"""
        return results
    
    # Removed page table formatter
    
    # Removed TLB formatter
    
    def _format_memory_trends_results(self, trends):
        """Format memory trends analysis results"""
        if 'error' in trends:
            return f"Error: {trends['error']}"
        
        trend_data = trends['trends']
        
        results = f"""
Memory Trends Analysis for PID {trends['pid']}
{'='*50}

Current Memory Usage:
- RSS: {trend_data['current_usage']['rss_mb']:.1f} MB
- VMS: {trend_data['current_usage']['vms_mb']:.1f} MB
- Memory Percent: {trend_data['current_usage']['memory_percent']:.1f}%

Trend Analysis:
- Direction: {trend_data['trend_direction'].title()}
- Growth Rate: {trend_data['growth_rate']:.2%} per minute
- Analysis Period: {trends['analysis_period']}

Peak Usage:
- Peak RSS: {trend_data['peak_usage']['peak_rss_mb']:,} MB
- Peak Time: {trend_data['peak_usage']['peak_time']}
- Peak Duration: {trend_data['peak_usage']['peak_duration']}

Memory Leak Indicators:
- High Memory Usage: {'Yes' if trend_data['memory_leak_indicators']['high_memory_usage'] else 'No'}
- Increasing Trend: {'Yes' if trend_data['memory_leak_indicators']['increasing_trend'] else 'No'}
- Memory Fragmentation: {'Yes' if trend_data['memory_leak_indicators']['memory_fragmentation'] else 'No'}
- Leak Probability: {trend_data['memory_leak_indicators']['leak_probability']:.1%}

Recommendations:
"""
        for i, rec in enumerate(trend_data['recommendations'], 1):
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
