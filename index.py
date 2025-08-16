import os
import string
import threading
import queue
import time
from collections import defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False

THEME_BG = "#F9FAFB"
THEME_BG_ALT = "#FFFFFF"
THEME_FG = "#111827"
ACCENT = "#3B82F6"
ACCENT_ALT = "#2563EB"

FILE_GROUPS = {
    "Archive (zip/rar/7z)": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
    "Video (mp4/mkv/avi)": [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv"],
    "Music/Audio (mp3/wav)": [".mp3", ".wav", ".flac", ".aac", ".ogg"],
    "Word (doc/docx)": [".doc", ".docx"],
    "Excel (xls/xlsx)": [".xls", ".xlsx"],
    "Image (png/jpg)": [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"],
    "Text (txt)": [".txt", ".log", ".md"],
    "Application (exe/msi)": [".exe", ".msi"],
}

TOP_N_SLICES = 9

def human_bytes(n: int) -> str:
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    v = float(n)
    while v >= step and i < len(units)-1:
        v /= step
        i += 1
    return f"{v:.2f} {units[i]}"

def list_windows_drives():
    return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]

def default_roots():
    if os.name == "nt":
        drives = list_windows_drives()
        return drives if drives else ["C:\\"]
    else:
        return ["/"]

class DiskScanner(threading.Thread):
    def __init__(self, roots, selected_exts, progress_q):
        super().__init__(daemon=True)
        self.roots = roots
        self.selected_exts = set(e.lower() for e in selected_exts) if selected_exts else None
        self.progress_q = progress_q
        self.result_sizes = defaultdict(int)
        self.result_counts = defaultdict(int)
        self.recent_files = defaultdict(list)
        self.old_files = defaultdict(list)
        self.total_bytes = 0
        self.total_files = 0
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        one_month_ago = time.time() - 30*24*60*60
        try:
            for root in self.roots:
                if self._stop.is_set(): break
                for cur, dirs, files in os.walk(root, topdown=True, onerror=None):
                    if self._stop.is_set(): break
                    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(cur,d))]
                    for fname in files:
                        if self._stop.is_set(): break
                        fpath = os.path.join(cur, fname)
                        ext = os.path.splitext(fname)[1].lower()
                        if self.selected_exts is not None and ext not in self.selected_exts: continue
                        try:
                            size = os.path.getsize(fpath)
                            mtime = os.path.getmtime(fpath)
                            atime = os.path.getatime(fpath)
                        except Exception:
                            continue
                        self.result_sizes[ext] += size
                        self.result_counts[ext] += 1
                        self.total_bytes += size
                        self.total_files += 1
                        if max(mtime, atime) >= one_month_ago:
                            self.recent_files[ext].append(fpath)
                        else:
                            self.old_files[ext].append(fpath)
                        if self.total_files % 200 == 0:
                            self.progress_q.put(("PROG", {"files":self.total_files,"bytes":self.total_bytes}))
        finally:
            self.progress_q.put(("DONE",{
                "sizes": dict(self.result_sizes),
                "counts": dict(self.result_counts),
                "total_bytes": self.total_bytes,
                "total_files": self.total_files,
                "recent": dict(self.recent_files),
                "old": dict(self.old_files)
            }))

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Disk Space Analyzer by File Type")
        self.geometry("1100x680")
        self.configure(bg=THEME_BG)
        self.progress_q = queue.Queue()
        self.scanner = None
        self._setup_style()
        self._build_layout()
        self._set_default_roots()
        self.after(150, self._poll_progress)

    def _setup_style(self):
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except Exception: pass
        style.configure("TFrame", background=THEME_BG)
        style.configure("Card.TFrame", background=THEME_BG_ALT)
        style.configure("TLabel", background=THEME_BG, foreground=THEME_FG)
        style.configure("Accent.TButton", background=ACCENT, foreground="white", padding=8, borderwidth=0)
        style.map("Accent.TButton", background=[("active", ACCENT_ALT)])
        style.configure("Ghost.TButton", background=THEME_BG_ALT, foreground=THEME_FG, padding=8, borderwidth=1, relief="solid")
        style.map("Ghost.TButton", background=[("active", THEME_BG_ALT)])
        style.configure("TCheckbutton", background=THEME_BG_ALT, foreground=THEME_FG)
        style.configure("Horizontal.TProgressbar", troughcolor=THEME_BG_ALT, background=ACCENT_ALT)

    def _build_layout(self):
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Controls
        self.controls = ttk.Frame(self, padding=16, relief="groove", borderwidth=2)
        self.controls.grid(row=0, column=0, sticky="nsw", padx=12, pady=12)

        # File Types
        file_frame = ttk.LabelFrame(self.controls, text="File Types", padding=10, relief="ridge")
        file_frame.grid(row=0, column=0, sticky="ew", pady=(0,10))
        self.chk_vars = {}
        for idx, (gname, exts) in enumerate(FILE_GROUPS.items()):
            var = tk.BooleanVar(value=True)
            self.chk_vars[gname] = var
            cb = ttk.Checkbutton(file_frame, text=gname, variable=var)
            cb.grid(row=idx, column=0, sticky="w", pady=2)

        # Folder List
        folder_frame = ttk.LabelFrame(self.controls, text="Folders to Scan", padding=10, relief="ridge")
        folder_frame.grid(row=1, column=0, sticky="ew", pady=(0,10))
        self.roots_list = tk.Listbox(folder_frame, bg=THEME_BG_ALT, fg=THEME_FG, selectmode=tk.EXTENDED, height=6, bd=2, relief="sunken")
        self.roots_list.grid(row=0, column=0, sticky="ew", pady=5)

        # Folder Buttons
        btn_frame = ttk.Frame(folder_frame)
        btn_frame.grid(row=1, column=0, sticky="ew", pady=5)
        ttk.Button(btn_frame, text="Add Folder", command=self._add_root).grid(row=0, column=0, sticky="ew", padx=2)
        ttk.Button(btn_frame, text="Remove Selected", command=self._remove_selected_root).grid(row=0, column=1, sticky="ew", padx=2)
        ttk.Button(btn_frame, text="Clear All Folders", command=lambda: self.roots_list.delete(0, tk.END)).grid(row=0, column=2, sticky="ew", padx=2)
        ttk.Button(btn_frame, text="Add All Drives", command=self._add_all_drives).grid(row=0, column=3, sticky="ew", padx=2)

        # Start / Stop
        self.start_btn = ttk.Button(self.controls, text="Start Scan", style="Accent.TButton", command=self._start_scan)
        self.start_btn.grid(sticky="ew", pady=(16,6))
        self.stop_btn = ttk.Button(self.controls, text="Stop Scan", style="Ghost.TButton", command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.grid(sticky="ew")

        # Progress
        self.prog = ttk.Progressbar(self.controls, mode="indeterminate", style="Horizontal.TProgressbar")
        self.prog.grid(sticky="ew", pady=(10,0))
        self.status = ttk.Label(self.controls, text="Ready", foreground="#374151")
        self.status.grid(sticky="w", pady=(6,0))

        # Results frame
        self.results = ttk.Frame(self, style="Card.TFrame", padding=16)
        self.results.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        self.results.columnconfigure(0, weight=1)
        self.results.rowconfigure(1, weight=1)

        ttk.Label(self.results, text="Results", font=("Segoe UI", 12, "bold"), foreground=THEME_FG).grid(row=0, column=0, sticky="w")
        self.chart_container = ttk.Frame(self.results, style="TFrame")
        self.chart_container.grid(row=1, column=0, sticky="nsew", pady=(10,10))
        self.tree = ttk.Treeview(self.results, columns=("type","count","size"), show="headings", height=8)
        self.tree.grid(row=2, column=0, sticky="nsew")
        self.tree.heading("type", text="Type/Extension")
        self.tree.heading("count", text="File Count")
        self.tree.heading("size", text="Total Size")
        self.total_label = ttk.Label(self.results, text="Total: -", foreground="#374151")
        self.total_label.grid(row=3, column=0, sticky="w", pady=(8,0))

        if not MATPLOTLIB_AVAILABLE:
            info = ttk.Label(self.chart_container, text="Matplotlib required for chart (pip install matplotlib)", foreground="#DC2626")
            info.pack(pady=20)
    def _set_default_roots(self):
        for r in default_roots():
            self.roots_list.insert(tk.END, r)

    def _add_root(self):
        path = filedialog.askdirectory(title="Select Folder to Scan")
        if path:
            self.roots_list.insert(tk.END, path)

    def _remove_selected_root(self):
        sel = list(self.roots_list.curselection())
        sel.reverse()
        for idx in sel:
            self.roots_list.delete(idx)

    def _add_all_drives(self):
        self.roots_list.delete(0, tk.END)
        for r in default_roots() if os.name != 'nt' else list_windows_drives():
            self.roots_list.insert(tk.END, r)

    def _collect_selected_exts(self):
        selected_exts = set()
        any_checked = False
        for gname, var in self.chk_vars.items():
            if var.get():
                any_checked = True
                selected_exts.update([e.lower() for e in FILE_GROUPS[gname]])
        return selected_exts if any_checked else None

    def _start_scan(self):
        if self.scanner is not None: return
        roots = [self.roots_list.get(i) for i in range(self.roots_list.size())]
        if not roots:
            messagebox.showwarning("Warning", "Please add at least one folder or drive.")
            return
        selected_exts = self._collect_selected_exts()
        self._clear_results()
        self._toggle_controls(False)
        self.status.config(text="Scanning…")
        self.prog.start(12)
        self.scanner = DiskScanner(roots=roots, selected_exts=selected_exts, progress_q=self.progress_q)
        self.scanner.start()

    def _stop_scan(self):
        if self.scanner is not None:
            self.scanner.stop()
            self.status.config(text="Stopping…")

    def _toggle_controls(self, enable: bool):
        state = tk.NORMAL if enable else tk.DISABLED
        for child in self.controls.winfo_children():
            if child in (self.status, self.prog): continue
            try: child.configure(state=state)
            except Exception: pass
        self.stop_btn.configure(state=(tk.NORMAL if not enable else tk.DISABLED))
        self.start_btn.configure(state=(tk.NORMAL if enable else tk.DISABLED))

    def _poll_progress(self):
        try:
            while True:
                tag, data = self.progress_q.get_nowait()
                if tag == "PROG":
                    self.status.config(text=f"Scanning: Files {data.get('files',0)} | Size {human_bytes(data.get('bytes',0))}")
                elif tag == "DONE":
                    self._on_done(data)
                self.progress_q.task_done()
        except queue.Empty:
            pass
        self.after(150, self._poll_progress)

    def _on_done(self, data):
        self.prog.stop()
        self._toggle_controls(True)
        self.status.config(text="Completed")
        self.scanner = None

        sizes = data.get("sizes", {})
        counts = data.get("counts", {})
        total_bytes = data.get("total_bytes", 0)
        total_files = data.get("total_files", 0)

        # Populate Treeview
        rows = sorted(sizes.items(), key=lambda x: x[1], reverse=True)
        for ext, sz in rows:
            self.tree.insert("", tk.END, values=(ext if ext else "(no extension)", counts.get(ext, 0), human_bytes(sz)))
        self.total_label.config(text=f"Total Files: {total_files:,} | Total Size: {human_bytes(total_bytes)}")

        if MATPLOTLIB_AVAILABLE:
            self._draw_pie_chart(sizes)

        # Write recent/old files report
        self._write_report(data)

    def _clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.total_label.config(text="Total: -")
        for w in self.chart_container.winfo_children():
            w.destroy()

    def _draw_pie_chart(self, sizes_by_ext: dict):
        from collections import defaultdict
        group_totals = defaultdict(int)
        ext_to_group = {}
        for gname, exts in FILE_GROUPS.items():
            for e in exts:
                ext_to_group[e] = gname
        other_total = 0
        for ext, sz in sizes_by_ext.items():
            g = ext_to_group.get(ext.lower())
            if g:
                group_totals[g] += sz
            else:
                other_total += sz
        if other_total:
            group_totals["Other"] += other_total
        items = sorted(group_totals.items(), key=lambda x:x[1], reverse=True)
        if len(items) > TOP_N_SLICES:
            top = items[:TOP_N_SLICES]
            rest = sum(sz for _, sz in items[TOP_N_SLICES:])
            items = top + [("Other (small)", rest)]
        labels = [k for k,_ in items]
        values = [v for _,v in items]
        fig = Figure(figsize=(6.8,4.2), dpi=100)
        ax = fig.add_subplot(111)
        fig.patch.set_facecolor(THEME_BG_ALT)
        ax.set_facecolor(THEME_BG_ALT)
        if sum(values) > 0:
            wedges,texts,autotexts = ax.pie(values, labels=labels, autopct=lambda p:f"{p:.1f}%", startangle=120)
            for t in texts+autotexts: t.set_color(THEME_FG)
        else:
            ax.text(0.5,0.5,"No files", ha="center", va="center", color=THEME_FG)
        canvas = FigureCanvasTkAgg(fig, master=self.chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _write_report(self, data):
        now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"disk_scan_report_{now_str}.txt"
        with open(filename,"w", encoding="utf-8") as f:
            f.write("RECENT FILES (last 1 month):\n")
            for ext, files in data.get("recent",{}).items():
                f.write(f"\n[{ext if ext else '(no extension)'}]\n")
                for fp in files:
                    f.write(f"{fp}\n")
            f.write("\nOLD FILES (not opened/modified in last 1 month):\n")
            for ext, files in data.get("old",{}).items():
                f.write(f"\n[{ext if ext else '(no extension)'}]\n")
                for fp in files:
                    f.write(f"{fp}\n")
        messagebox.showinfo("Scan Report", f"Report saved as {filename}")

if __name__ == "__main__":
    app = App()
    app.mainloop()
