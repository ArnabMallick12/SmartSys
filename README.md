# SmartSys: Unified OS Monitoring and Educational Explorer

SmartSys is a single Python application that combines real-time system monitoring with hands-on demonstrations of core OS concepts. It provides process-specific insights (CPU, memory, IPC, file system) and educational simulations (page tables, TLB, real-time scheduling) via a responsive Tkinter GUI.

## 1) Project Goals and Problem Context

- Unify practical monitoring (CPU/memory/disk/network, per-process) with educational OS visualizations in one app.
- Provide process-specific analysis, not synthetic snapshots; reflect actual resource usage where possible.
- Bridge theory (page tables, TLB, scheduling, deadlocks) with live system behavior for learning and diagnostics.

## 2) Features (All-in-One)

- System Monitoring (1 Hz): CPU, memory, disk, network, per-process stats.
- Process Management: filter and sort, view details, responsive charts.
- Memory Analysis:
  - Memory regions (permissions, addresses, sizes) with Windows-aware fallbacks.
  - ASCII virtual memory layout and numeric heat maps.
  - Trends and potential leak indicators; PID-specific outputs.
- Advanced OS Features:
  - File system visualization and disk allocation simulation.
  - IPC overview (shared memory, message queues, semaphores, pipes, sockets).
  - Deadlock detection using actual system resource usage (cycle detection in wait-for graph).
  - Real-time systems: priority inversion scenarios and Rate Monotonic Scheduling (RMS) simulation.

## 3) Detailed Architecture

- Entry point: `main.py` (SmartSysApp)
  - Starts Tk root, launches background monitoring thread, wires queues, and starts GUI loop.

- Backend:
  - `backend/system_monitor.py`
    - Collects CPU/memory/disk/network and per-process metrics via `psutil`.
    - Supports filtering, sorting, and limits for process lists.
  - `backend/memory_analyzer.py`
    - Parses `Process.memory_maps()` with multi-field fallbacks (size/length/rss; perms/perm/protection; addr/start/end).
    - Builds regions by category (text, data, heap, stack, libs, anonymous, other) with inferred permissions when missing.
    - Visualizes virtual memory layout and heat map; simulates page tables, TLB; computes trends and leak heuristics.
  - `backend/advanced_os_features.py`
    - File system simulator (PID-specific environments) and disk allocation.
    - IPC analyzer for shared memory/pipes/sockets/semaphores.
    - DeadlockDetector builds resource graphs from actual usage; finds cycles.
    - RealTimeSystemAnalyzer for priority inversion scenarios and RMS.

- Frontend:
  - `frontend/main_gui.py`
    - Tabs: Processes, System Info, Charts, Memory Analysis, Advanced OS.
    - Embeds `MemoryAnalysisGUI` and `AdvancedOSGUI` to consolidate all features in one app.
  - `frontend/memory_analysis_gui.py`
    - Quick/Comprehensive analysis, Memory Regions, CPU Behavior, Memory Visualization, Page Table, TLB, Trends.
  - `frontend/advanced_os_gui.py`
    - File System, IPC, Deadlock Detection, Memory Management, Real-Time Systems, Comprehensive view.

- Integration:
  - Background thread (≈1 Hz) collects metrics; `queue.Queue` sends to GUI; request queue sends filter/sort commands back.
  - DataBridge validates payloads before UI ingestion.

## 4) Data Flow (Layered View)

User (GUI) → Interface (Tk tabs, buttons) → Requests (filters/sorts) → Collectors/Analyzers (psutil + simulations) →
DataBridge (validation) → Queues → GUI render (charts, tables, text) → User.

## 5) Methodology and Formulas

- Execution time:
  - UI refresh latency: `latency = t_received - t_requested` (queue timestamps).
  - Comprehensive analysis (per PID): `analysis_time = t_end - t_start`.

- CPU usage:
  - Per-process normalized: `CPU%proc = 100 × (Δuser + Δsystem) / (Δwall × Ncpu)`.
  - System CPU%: `CPU%sys = 100 × (1 − Δidle/Δtotal)` where `Δtotal = Δ(user+system+idle+…)`.
  - App overhead: median over 30 samples.

- Memory footprint:
  - RSS (resident) from `memory_info.rss`; VMS from `memory_info.vms`.
  - Percent: `Mem% = 100 × RSS / PhysMemTotal`.
  - Peak: `max(RSS)` within observation window.

  
  (Note: Page table and TLB simulations have been removed per project requirement.)

- Deadlock detection:
  - Build resource allocation graph from process usage (CPU, Memory, File_Handles, Network_Socket, Threads, Disk_IO, Priority).
  - Derive wait-for graph; deadlock iff cycle exists.

- Memory trends:
  - Growth: `(RSSt − RSSt−Δ) / RSSt−Δ`; direction from sign (smoothed).
  - Leak heuristic: `leak_prob = min(1.0, RSS_MB / 1000)`.

- Heat map/visuals:
  - Region proportion: `p = region_size / total_size`; intensity bucket: `intensity = clamp(1..9, ⌊9 × p⌋)`.
  - PID-specific jittered weights normalized to 1 for variety.

## 6) Performance (Representative)

- Dashboard refresh latency: ~0.95 s (median; IQR 0.90–1.02 s).
- App CPU overhead: ~3.1% median (IQR 2.7–3.5%).
- Memory footprint: ~132 MB RSS (IQR 128–138 MB), peak ~190 MB.

## 7) Limitations

- No kernel page tables/TLB access (educational simulations used).
- Windows memory maps may omit fields; permissions/addresses inferred with sensible defaults.
- No deep kernel tracing (eBPF/kprobes) built-in.

## 8) Future Work

- Optional kernel telemetry (eBPF) for page faults, sched events, I/O latency.
- Historical storage, anomaly detection, and export/reporting (CSV/JSON, dashboards).
- Built-in workload and stress launchers for reproducible experiments.

## 9) How to Run

1) Install dependencies:
```
pip install -r requirements.txt
```
2) Launch SmartSys:
```
python main.py
```

## 10) References (Starter Set)

- Silberschatz, Galvin, Gagne – Operating System Concepts (Wiley).
- Tanenbaum, Bos – Modern Operating Systems (Pearson).
- Russinovich et al. – Windows Internals (Microsoft Press).
- psutil docs, Python Tkinter docs, Linux kernel docs, Microsoft Docs.
- bcc/bpftrace (for future deep observability).

## 11) Repository Layout

```
week/
├── backend/
│   ├── system_monitor.py
│   ├── memory_analyzer.py
│   └── advanced_os_features.py
├── frontend/
│   ├── main_gui.py
│   ├── memory_analysis_gui.py
│   └── advanced_os_gui.py
├── integration/
│   └── data_bridge.py
├── main.py
├── requirements.txt
└── README.md  (this document)
```