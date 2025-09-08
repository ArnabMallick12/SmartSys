"""
Main GUI Module
Responsible for displaying system data using Tkinter
Member 2: Frontend Development
"""

import tkinter as tk
from tkinter import ttk, messagebox
import queue
import threading
import time
from typing import Dict, Any


class MainGUI:
    """Main GUI class for SmartSys application"""
    
    def __init__(self, root: tk.Tk, data_queue: queue.Queue):
        """Initialize the GUI"""
        self.root = root
        self.data_queue = data_queue
        self.current_data = {}
        
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
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="SmartSys - Real-Time Process and Resource Tracker", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Left panel - System metrics
        self.setup_system_metrics(main_frame)
        
        # Right panel - Process list
        self.setup_process_list(main_frame)
    
    def setup_system_metrics(self, parent):
        """Set up system metrics display"""
        metrics_frame = ttk.LabelFrame(parent, text="System Metrics", padding="10")
        metrics_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
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
        
        self.info_text = tk.Text(info_frame, height=8, width=30, wrap=tk.WORD)
        self.info_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for info text
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        info_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
    
    def setup_process_list(self, parent):
        """Set up process list display"""
        process_frame = ttk.LabelFrame(parent, text="Running Processes", padding="10")
        process_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
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
        
        # Process control buttons
        button_frame = ttk.Frame(process_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_processes).pack(side=tk.LEFT, padx=5)
        # ttk.Button(button_frame, text="Terminate Process", command=self.terminate_selected_process).pack(side=tk.LEFT, padx=5)
        
        # Bind double-click to terminate
        self.process_tree.bind('<Double-1>', self.on_process_double_click)
    
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
        """Manually refresh process list"""
        # This will be handled by the data update loop
        pass
    
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
        self.terminate_selected_process()
    
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
                    self.root.after(0, self.update_process_list, data)
                    
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
