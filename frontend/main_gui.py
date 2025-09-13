"""
Main GUI Module
Responsible for displaying system data using Tkinter
Member 2: Frontend Development
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import queue
import threading
import time
from typing import Dict, Any, Optional
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np


class MainGUI:
    """Main GUI class for SmartSys application"""
    
    def __init__(self, root: tk.Tk, data_queue: queue.Queue, request_queue: queue.Queue = None):
        """Initialize the GUI"""
        self.root = root
        self.data_queue = data_queue
        self.request_queue = request_queue  # Queue for sending requests to backend
        self.current_data = {}
        
        # Chart data storage
        self.chart_data = {
            'cpu_history': [],
            'memory_history': [],
            'timestamps': [],
            'max_history': 60  # Keep 60 data points (1 minute at 1Hz)
        }
        
        # Filter and sort options
        self.filter_name = tk.StringVar(value="")
        self.sort_by = tk.StringVar(value="cpu")
        self.process_limit = tk.IntVar(value=50)
        
        # Track if we need to request new data
        self.filter_changed = False
        self.sort_changed = False
        
        # Create main frames
        self.setup_ui()
        
        # Start data update thread
        self.update_thread = threading.Thread(target=self._update_data_loop, daemon=True)
        self.update_running = True
        self.update_thread.start()
    
    def setup_ui(self):
        """Set up the user interface"""
        # Configure main window
        self.root.configure(bg='#f0f0f0')
        
        # Create main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="SmartSys - Real-Time Process and Resource Tracker", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create tabs
        self.setup_processes_tab()
        self.setup_system_info_tab()
        self.setup_charts_tab()
    
    def setup_processes_tab(self):
        """Set up the processes tab"""
        # Create processes tab
        processes_tab = ttk.Frame(self.notebook)
        self.notebook.add(processes_tab, text="Processes")
        
        # Configure grid
        processes_tab.columnconfigure(0, weight=1)
        processes_tab.rowconfigure(0, weight=1)
        
        # Process list
        self.setup_process_list(processes_tab)
    
    def setup_system_info_tab(self):
        """Set up the system information tab"""
        # Create system info tab
        system_tab = ttk.Frame(self.notebook)
        self.notebook.add(system_tab, text="System Info")
        
        # Configure grid
        system_tab.columnconfigure(0, weight=1)
        system_tab.columnconfigure(1, weight=1)
        system_tab.rowconfigure(0, weight=1)
        
        # System metrics
        self.setup_system_metrics(system_tab)
        
        # Performance metrics
        self.setup_performance_metrics(system_tab)
    
    def setup_charts_tab(self):
        """Set up the charts tab"""
        # Create charts tab
        charts_tab = ttk.Frame(self.notebook)
        self.notebook.add(charts_tab, text="Charts")
        
        # Configure grid
        charts_tab.columnconfigure(0, weight=1)
        charts_tab.rowconfigure(0, weight=1)
        
        # Charts panel
        self.setup_charts_panel(charts_tab)
    
    def setup_system_metrics(self, parent):
        """Set up system metrics display"""
        metrics_frame = ttk.LabelFrame(parent, text="System Metrics", padding="10")
        metrics_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        metrics_frame.columnconfigure(0, weight=1)
        
        # CPU metrics
        cpu_frame = ttk.Frame(metrics_frame)
        cpu_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(cpu_frame, text="CPU Usage:").grid(row=0, column=0, sticky=tk.W)
        self.cpu_label = ttk.Label(cpu_frame, text="0%", font=('Arial', 12, 'bold'))
        self.cpu_label.grid(row=0, column=1, sticky=tk.E)
        
        self.cpu_progress = ttk.Progressbar(cpu_frame, length=200, mode='determinate')
        self.cpu_progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Memory metrics
        memory_frame = ttk.Frame(metrics_frame)
        memory_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(memory_frame, text="Memory Usage:").grid(row=0, column=0, sticky=tk.W)
        self.memory_label = ttk.Label(memory_frame, text="0%", font=('Arial', 12, 'bold'))
        self.memory_label.grid(row=0, column=1, sticky=tk.E)
        
        self.memory_progress = ttk.Progressbar(memory_frame, length=200, mode='determinate')
        self.memory_progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Disk metrics
        disk_frame = ttk.Frame(metrics_frame)
        disk_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(disk_frame, text="Disk Usage:").grid(row=0, column=0, sticky=tk.W)
        self.disk_label = ttk.Label(disk_frame, text="0%", font=('Arial', 12, 'bold'))
        self.disk_label.grid(row=0, column=1, sticky=tk.E)
        
        self.disk_progress = ttk.Progressbar(disk_frame, length=200, mode='determinate')
        self.disk_progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # System info
        info_frame = ttk.LabelFrame(metrics_frame, text="System Information", padding="5")
        info_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=10)
        info_frame.columnconfigure(0, weight=1)
        info_frame.rowconfigure(0, weight=1)
        
        self.info_text = tk.Text(info_frame, height=8, width=30, wrap=tk.WORD)
        self.info_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for info text
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        info_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
    
    def setup_performance_metrics(self, parent):
        """Set up performance metrics display"""
        perf_frame = ttk.LabelFrame(parent, text="Performance Metrics", padding="10")
        perf_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        perf_frame.columnconfigure(0, weight=1)
        
        # Uptime
        uptime_frame = ttk.Frame(perf_frame)
        uptime_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(uptime_frame, text="System Uptime:").grid(row=0, column=0, sticky=tk.W)
        self.uptime_label = ttk.Label(uptime_frame, text="0:00:00", font=('Arial', 12, 'bold'))
        self.uptime_label.grid(row=0, column=1, sticky=tk.E)
        
        # Boot time
        boot_frame = ttk.Frame(perf_frame)
        boot_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(boot_frame, text="Boot Time:").grid(row=0, column=0, sticky=tk.W)
        self.boot_time_label = ttk.Label(boot_frame, text="Unknown", font=('Arial', 10))
        self.boot_time_label.grid(row=0, column=1, sticky=tk.E)
        
        # Load averages
        load_frame = ttk.LabelFrame(perf_frame, text="Load Averages", padding="5")
        load_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(load_frame, text="1 min:").grid(row=0, column=0, sticky=tk.W)
        self.load_1min_label = ttk.Label(load_frame, text="0.00", font=('Arial', 10))
        self.load_1min_label.grid(row=0, column=1, sticky=tk.E)
        
        ttk.Label(load_frame, text="5 min:").grid(row=1, column=0, sticky=tk.W)
        self.load_5min_label = ttk.Label(load_frame, text="0.00", font=('Arial', 10))
        self.load_5min_label.grid(row=1, column=1, sticky=tk.E)
        
        ttk.Label(load_frame, text="15 min:").grid(row=2, column=0, sticky=tk.W)
        self.load_15min_label = ttk.Label(load_frame, text="0.00", font=('Arial', 10))
        self.load_15min_label.grid(row=2, column=1, sticky=tk.E)
        
        # System statistics
        stats_frame = ttk.LabelFrame(perf_frame, text="System Statistics", padding="5")
        stats_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(stats_frame, text="Context Switches:").grid(row=0, column=0, sticky=tk.W)
        self.context_switches_label = ttk.Label(stats_frame, text="0", font=('Arial', 10))
        self.context_switches_label.grid(row=0, column=1, sticky=tk.E)
        
        ttk.Label(stats_frame, text="Interrupts:").grid(row=1, column=0, sticky=tk.W)
        self.interrupts_label = ttk.Label(stats_frame, text="0", font=('Arial', 10))
        self.interrupts_label.grid(row=1, column=1, sticky=tk.E)
    
    def setup_process_list(self, parent):
        """Set up process list display"""
        process_frame = ttk.LabelFrame(parent, text="Running Processes", padding="10")
        process_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        process_frame.columnconfigure(0, weight=1)
        process_frame.rowconfigure(0, weight=1)
        
        # Create treeview for processes
        columns = ('PID', 'Name', 'CPU%', 'Memory%', 'Status')
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Process Name')
        self.process_tree.heading('CPU%', text='CPU %')
        self.process_tree.heading('Memory%', text='Memory %')
        self.process_tree.heading('Status', text='Status')
        
        self.process_tree.column('PID', width=80)
        self.process_tree.column('Name', width=200)
        self.process_tree.column('CPU%', width=80)
        self.process_tree.column('Memory%', width=80)
        self.process_tree.column('Status', width=100)
        
        # Scrollbars for process tree
        process_v_scrollbar = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        process_h_scrollbar = ttk.Scrollbar(process_frame, orient=tk.HORIZONTAL, command=self.process_tree.xview)
        
        self.process_tree.configure(yscrollcommand=process_v_scrollbar.set, xscrollcommand=process_h_scrollbar.set)
        
        # Grid layout
        self.process_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        process_v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        process_h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Filter and sort controls
        control_frame = ttk.Frame(process_frame)
        control_frame.grid(row=2, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
        
        # Filter controls
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_name, width=15)
        filter_entry.grid(row=0, column=1, padx=(0, 10))
        filter_entry.bind('<KeyRelease>', self.on_filter_change)
        
        # Sort controls
        ttk.Label(control_frame, text="Sort by:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        sort_combo = ttk.Combobox(control_frame, textvariable=self.sort_by, width=10, 
                                 values=["cpu", "memory", "name", "pid"], state="readonly")
        sort_combo.grid(row=0, column=3, padx=(0, 10))
        sort_combo.bind('<<ComboboxSelected>>', self.on_sort_change)
        
        # Process control buttons
        button_frame = ttk.Frame(process_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_processes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Terminate", command=self.terminate_selected_process).pack(side=tk.LEFT, padx=5)
        # ttk.Button(button_frame, text="Suspend", command=self.suspend_selected_process).pack(side=tk.LEFT, padx=5)
        # ttk.Button(button_frame, text="Details", command=self.show_process_details).pack(side=tk.LEFT, padx=5)
        
        # Bind double-click to show details
        self.process_tree.bind('<Double-1>', self.on_process_double_click)
    
    def setup_charts_panel(self, parent):
        """Set up charts panel for real-time metrics visualization"""
        charts_frame = ttk.LabelFrame(parent, text="Real-Time Performance Charts", padding="10")
        charts_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        charts_frame.columnconfigure(0, weight=1)
        charts_frame.rowconfigure(0, weight=1)
        
        # Create matplotlib figure with subplots
        self.fig = Figure(figsize=(14, 8), dpi=100)
        
        # CPU chart
        self.cpu_ax = self.fig.add_subplot(221)
        self.cpu_ax.set_title('CPU Usage %', fontsize=12, fontweight='bold')
        self.cpu_ax.set_ylabel('CPU %')
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_ax.grid(True, alpha=0.3)
        
        # Memory chart
        self.memory_ax = self.fig.add_subplot(222)
        self.memory_ax.set_title('Memory Usage %', fontsize=12, fontweight='bold')
        self.memory_ax.set_ylabel('Memory %')
        self.memory_ax.set_ylim(0, 100)
        self.memory_ax.grid(True, alpha=0.3)
        
        # Disk chart
        self.disk_ax = self.fig.add_subplot(223)
        self.disk_ax.set_title('Disk Usage %', fontsize=12, fontweight='bold')
        self.disk_ax.set_ylabel('Disk %')
        self.disk_ax.set_ylim(0, 100)
        self.disk_ax.grid(True, alpha=0.3)
        
        # Network chart (placeholder for future enhancement)
        self.network_ax = self.fig.add_subplot(224)
        self.network_ax.set_title('Network Activity', fontsize=12, fontweight='bold')
        self.network_ax.set_ylabel('Bytes/sec')
        self.network_ax.grid(True, alpha=0.3)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, charts_frame)
        self.canvas.get_tk_widget().grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure figure layout
        self.fig.tight_layout()
        
        # Initialize chart data for disk and network
        self.chart_data['disk_history'] = []
        self.chart_data['network_history'] = []
    
    def update_system_metrics(self, data: Dict[str, Any]):
        """Update system metrics display"""
        try:
            # Update CPU
            cpu_percent = data.get('cpu', {}).get('cpu_percent', 0)
            self.cpu_label.config(text=f"{cpu_percent:.1f}%")
            self.cpu_progress['value'] = cpu_percent
            
            # Update Memory
            memory_percent = data.get('memory', {}).get('percent', 0)
            self.memory_label.config(text=f"{memory_percent:.1f}%")
            self.memory_progress['value'] = memory_percent
            
            # Update Disk
            disk_percent = data.get('disk', {}).get('percent', 0)
            self.disk_label.config(text=f"{disk_percent:.1f}%")
            self.disk_progress['value'] = disk_percent
            
            # Update system info
            self.update_system_info(data)
            
        except Exception as e:
            print(f"Error updating system metrics: {e}")
    
    def update_system_info(self, data: Dict[str, Any]):
        """Update system information text"""
        try:
            self.info_text.delete(1.0, tk.END)
            
            cpu_info = data.get('cpu', {})
            memory_info = data.get('memory', {})
            disk_info = data.get('disk', {})
            
            info_text = f"""CPU Cores: {cpu_info.get('cpu_count', 'N/A')}
CPU Frequency: {cpu_info.get('cpu_freq', {}).get('current', 'N/A'):.0f} MHz

Memory Total: {memory_info.get('total', 0) / (1024**3):.1f} GB
Memory Available: {memory_info.get('available', 0) / (1024**3):.1f} GB
Memory Used: {memory_info.get('used', 0) / (1024**3):.1f} GB

Disk Total: {disk_info.get('total', 0) / (1024**3):.1f} GB
Disk Used: {disk_info.get('used', 0) / (1024**3):.1f} GB
Disk Free: {disk_info.get('free', 0) / (1024**3):.1f} GB"""
            
            self.info_text.insert(1.0, info_text)
            
        except Exception as e:
            print(f"Error updating system info: {e}")
    
    def update_performance_metrics(self, data: Dict[str, Any]):
        """Update performance metrics display"""
        try:
            perf_data = data.get('performance', {})
            
            # Update uptime
            uptime_formatted = perf_data.get('uptime_formatted', 'Unknown')
            self.uptime_label.config(text=uptime_formatted)
            
            # Update boot time
            boot_time = perf_data.get('boot_time', 'Unknown')
            self.boot_time_label.config(text=boot_time)
            
            # Update load averages
            load_avg = perf_data.get('load_averages', {})
            self.load_1min_label.config(text=f"{load_avg.get('load_1min', 0):.2f}")
            self.load_5min_label.config(text=f"{load_avg.get('load_5min', 0):.2f}")
            self.load_15min_label.config(text=f"{load_avg.get('load_15min', 0):.2f}")
            
            # Update system statistics
            self.context_switches_label.config(text=str(perf_data.get('context_switches', 0)))
            self.interrupts_label.config(text=str(perf_data.get('interrupts', 0)))
            
        except Exception as e:
            print(f"Error updating performance metrics: {e}")
    
    def update_process_list(self, data: Dict[str, Any]):
        """Update process list display"""
        try:
            # Clear existing items
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            
            # Add new processes
            processes = data.get('processes', [])
            for proc in processes:
                self.process_tree.insert('', 'end', values=(
                    proc.get('pid', ''),
                    proc.get('name', ''),
                    f"{proc.get('cpu_percent', 0):.1f}",
                    f"{proc.get('memory_percent', 0):.1f}",
                    proc.get('status', '')
                ))
                
        except Exception as e:
            print(f"Error updating process list: {e}")
    
    def refresh_processes(self):
        """Manually refresh process list with current filter and sort settings"""
        self.request_new_process_data()
    
    def terminate_selected_process(self):
        """Terminate the selected process"""
        try:
            selection = self.process_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a process to terminate.")
                return
            
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            process_name = item['values'][1]
            
            result = messagebox.askyesno("Confirm Termination", 
                                       f"Are you sure you want to terminate process '{process_name}' (PID: {pid})?")
            if result:
                # This would need to be implemented with backend integration
                print(f"Terminating process {pid}")
                messagebox.showinfo("Process Terminated", f"Process {process_name} (PID: {pid}) has been terminated.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error terminating process: {e}")
    
    def on_process_double_click(self, event):
        """Handle double-click on process"""
        self.show_process_details()
    
    def on_filter_change(self, event):
        """Handle filter change"""
        self.filter_changed = True
        self.request_new_process_data()
    
    def on_sort_change(self, event):
        """Handle sort change"""
        self.sort_changed = True
        self.request_new_process_data()
    
    def request_new_process_data(self):
        """Request new process data with current filter and sort settings"""
        if self.request_queue:
            request = {
                'type': 'process_data',
                'filter_name': self.filter_name.get(),
                'sort_by': self.sort_by.get(),
                'limit': self.process_limit.get()
            }
            try:
                self.request_queue.put(request)
            except Exception as e:
                print(f"Error sending request: {e}")
    
    def update_charts(self, data: Dict[str, Any]):
        """Update real-time charts"""
        try:
            cpu_percent = data.get('cpu', {}).get('cpu_percent', 0)
            memory_percent = data.get('memory', {}).get('percent', 0)
            disk_percent = data.get('disk', {}).get('percent', 0)
            
            # Calculate network activity (simplified)
            network_data = data.get('network', {})
            network_activity = 0  # Placeholder for network activity calculation
            
            # Add new data points
            self.chart_data['cpu_history'].append(cpu_percent)
            self.chart_data['memory_history'].append(memory_percent)
            self.chart_data['disk_history'].append(disk_percent)
            self.chart_data['network_history'].append(network_activity)
            self.chart_data['timestamps'].append(time.time())
            
            # Limit history length
            max_len = self.chart_data['max_history']
            if len(self.chart_data['cpu_history']) > max_len:
                self.chart_data['cpu_history'] = self.chart_data['cpu_history'][-max_len:]
                self.chart_data['memory_history'] = self.chart_data['memory_history'][-max_len:]
                self.chart_data['disk_history'] = self.chart_data['disk_history'][-max_len:]
                self.chart_data['network_history'] = self.chart_data['network_history'][-max_len:]
                self.chart_data['timestamps'] = self.chart_data['timestamps'][-max_len:]
            
            # Update charts
            if len(self.chart_data['cpu_history']) > 1:
                # Clear previous plots
                self.cpu_ax.clear()
                self.memory_ax.clear()
                self.disk_ax.clear()
                self.network_ax.clear()
                
                # Plot CPU chart
                self.cpu_ax.plot(self.chart_data['cpu_history'], 'b-', linewidth=2, label='CPU %')
                self.cpu_ax.set_title('CPU Usage %', fontsize=12, fontweight='bold')
                self.cpu_ax.set_ylabel('CPU %')
                self.cpu_ax.set_ylim(0, 100)
                self.cpu_ax.grid(True, alpha=0.3)
                self.cpu_ax.legend()
                
                # Plot Memory chart
                self.memory_ax.plot(self.chart_data['memory_history'], 'r-', linewidth=2, label='Memory %')
                self.memory_ax.set_title('Memory Usage %', fontsize=12, fontweight='bold')
                self.memory_ax.set_ylabel('Memory %')
                self.memory_ax.set_ylim(0, 100)
                self.memory_ax.grid(True, alpha=0.3)
                self.memory_ax.legend()
                
                # Plot Disk chart
                self.disk_ax.plot(self.chart_data['disk_history'], 'g-', linewidth=2, label='Disk %')
                self.disk_ax.set_title('Disk Usage %', fontsize=12, fontweight='bold')
                self.disk_ax.set_ylabel('Disk %')
                self.disk_ax.set_ylim(0, 100)
                self.disk_ax.grid(True, alpha=0.3)
                self.disk_ax.legend()
                
                # Plot Network chart (placeholder)
                self.network_ax.plot(self.chart_data['network_history'], 'm-', linewidth=2, label='Network')
                self.network_ax.set_title('Network Activity', fontsize=12, fontweight='bold')
                self.network_ax.set_ylabel('Activity')
                self.network_ax.set_ylim(0, 100)
                self.network_ax.grid(True, alpha=0.3)
                self.network_ax.legend()
                
                # Refresh canvas
                self.fig.tight_layout()
                self.canvas.draw()
                
        except Exception as e:
            print(f"Error updating charts: {e}")
    
    def suspend_selected_process(self):
        """Suspend the selected process"""
        try:
            selection = self.process_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a process to suspend.")
                return
            
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            process_name = item['values'][1]
            
            result = messagebox.askyesno("Confirm Suspension", 
                                       f"Are you sure you want to suspend process '{process_name}' (PID: {pid})?")
            if result:
                # This would need to be implemented with backend integration
                print(f"Suspending process {pid}")
                messagebox.showinfo("Process Suspended", f"Process {process_name} (PID: {pid}) has been suspended.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error suspending process: {e}")
    
    def show_process_details(self):
        """Show detailed information about the selected process"""
        try:
            selection = self.process_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a process to view details.")
                return
            
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            
            # Create details window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Process Details - PID {pid}")
            details_window.geometry("600x400")
            
            # Create text widget for details
            text_widget = tk.Text(details_window, wrap=tk.WORD, padx=10, pady=10)
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # Get process details (this would need backend integration)
            details_text = f"""Process Details for PID {pid}

Name: {item['values'][1]}
CPU Usage: {item['values'][2]}%
Memory Usage: {item['values'][3]}%
Status: {item['values'][4]}

Additional details would be fetched from the backend system monitor.
This includes:
- Command line arguments
- Parent process ID
- Number of threads
- Memory usage details
- File handles
- Network connections

[This is a placeholder - actual implementation would fetch real data]"""
            
            text_widget.insert(1.0, details_text)
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error showing process details: {e}")
    
    def _update_data_loop(self):
        """Background thread to update GUI with new data"""
        while self.update_running:
            try:
                # Get data from queue (non-blocking)
                try:
                    data = self.data_queue.get_nowait()
                    self.current_data = data
                    
                    # Update GUI in main thread
                    self.root.after(0, self.update_system_metrics, data)
                    self.root.after(0, self.update_performance_metrics, data)
                    self.root.after(0, self.update_process_list, data)
                    self.root.after(0, self.update_charts, data)
                    
                except queue.Empty:
                    pass
                
                time.sleep(0.5)  # Update every 500ms
                
            except Exception as e:
                print(f"Error in update loop: {e}")
                time.sleep(1)
    
    def start(self):
        """Start the GUI"""
        print("GUI started")
    
    def stop(self):
        """Stop the GUI update thread"""
        self.update_running = False
        if self.update_thread:
            self.update_thread.join(timeout=1)
