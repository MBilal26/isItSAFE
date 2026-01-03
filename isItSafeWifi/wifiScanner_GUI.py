import ctypes
import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import re
import time
from datetime import datetime
from typing import Dict, Set, List

# Core functionality imports
try:
    from database import DatabaseManager
    from scanner import NetworkScanner, NetworkBlocker
except ImportError:
    # If imports fail, the app cannot function
    pass

# Logger integration
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"))
try:
    from logger import log_event
except ImportError:
    def log_event(m, msg, l="info"): pass

# ============================================================================
#                          CONFIGURATION
# ============================================================================
BG_DARK = "#0B0E14"
BG_SIDE = "#151921"
BG_CARD = "#1E293B"
ACCENT = "#00D1FF"
DANGER = "#FF3131"
SUCCESS = "#00FF41"
WARNING = "#FFB800"
TEXT_MAIN = "#E0E6ED"
TEXT_DIM = "#888888"

SCAN_INTERVAL = 5

class IsItSafeGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("isItSafe - WiFi Security Monitor v2.0")
        self.root.state('zoomed')
        self.root.configure(bg=BG_DARK)
        
        try:
            self.db = DatabaseManager()
            self.scanner = NetworkScanner()
            self.blocker = NetworkBlocker()
            log_event("WiFi_GUI", "Core services initialized.")
        except NameError as e:
            messagebox.showerror("Fatal Error", f"Missing component: {str(e)}")
            log_event("WiFi_GUI", f"Fatal init error: {str(e)}", "critical")
            self.root.destroy()
            return
        
        self.alerted_ssids: Set[str] = set()
        self.sort_column = None
        self.sort_reverse = False
        
        self._create_sidebar()
        self._create_main_area()
        self._configure_styles()
        
        self._start_scan_thread()
        self._start_ui_update_loop()
        self._animate_pulse()
        log_event("WiFi_GUI", "GUI loaded and scan cycles started.")
    
    def _create_sidebar(self):
        self.sidebar = tk.Frame(self.root, bg=BG_SIDE, width=280)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)
        
        title_frame = tk.Frame(self.sidebar, bg=BG_SIDE)
        title_frame.pack(pady=(30, 10))
        
        tk.Label(title_frame, text="isItSafe", font=("Consolas", 28, "bold"), bg=BG_SIDE, fg=ACCENT).pack()
        tk.Label(title_frame, text="WiFi Security Monitor", font=("Segoe UI", 9), bg=BG_SIDE, fg=TEXT_DIM).pack()
        
        self.canvas = tk.Canvas(self.sidebar, width=180, height=180, bg=BG_SIDE, highlightthickness=0)
        self.canvas.pack(pady=20)
        self.canvas.create_oval(40, 40, 140, 140, outline="#2D3748", width=3)
        self.canvas.create_oval(60, 60, 120, 120, outline="#2D3748", width=2)
        self.canvas.create_oval(80, 80, 100, 100, outline="#2D3748", width=1)
        
        self.pulse_circle = self.canvas.create_oval(85, 85, 95, 95, fill=ACCENT, state='hidden')
        
        self.status_label = tk.Label(self.sidebar, text="IDLE", font=("Segoe UI", 12, "bold"), bg=BG_SIDE, fg=TEXT_DIM)
        self.status_label.pack(pady=(0, 20))
        
        btn_frame = tk.Frame(self.sidebar, bg=BG_SIDE)
        btn_frame.pack(pady=10)
        
        self.refresh_btn = tk.Button(btn_frame, text="🔄 REFRESH", command=self._manual_refresh, bg=BG_CARD, fg=TEXT_MAIN, font=("Segoe UI", 9, "bold"), relief="flat", cursor="hand2", padx=15, pady=8, width=10)
        self.refresh_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.pause_btn = tk.Button(btn_frame, text="⏸️ PAUSE", command=self._toggle_pause, bg=BG_CARD, fg=TEXT_MAIN, font=("Segoe UI", 9, "bold"), relief="flat", cursor="hand2", padx=15, pady=8, width=10)
        self.pause_btn.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(self.sidebar, text="━" * 30, font=("Arial", 8), bg=BG_SIDE, fg="#2D3748").pack(pady=15)
        
        self._create_stat_display("NETWORKS", ACCENT, "total")
        self._create_stat_display("THREATS", DANGER, "threats")
        self._create_stat_display("BLOCKED", WARNING, "blocked")
    
    def _create_stat_display(self, label: str, color: str, attr_suffix: str):
        frame = tk.Frame(self.sidebar, bg=BG_SIDE)
        frame.pack(pady=8)
        value_label = tk.Label(frame, text="0", font=("Segoe UI", 24, "bold"), bg=BG_SIDE, fg=color)
        value_label.pack()
        tk.Label(frame, text=label, font=("Segoe UI", 9), bg=BG_SIDE, fg=TEXT_DIM).pack()
        setattr(self, f"{attr_suffix}_label", value_label)

    def _create_main_area(self):
        self.main = tk.Frame(self.root, bg=BG_DARK)
        self.main.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        header = tk.Frame(self.main, bg=BG_DARK)
        header.pack(fill=tk.X, pady=(0, 15))
        tk.Label(header, text="📡 Active Spectrum Analysis", font=("Segoe UI", 18, "bold"), bg=BG_DARK, fg=TEXT_MAIN).pack(side=tk.LEFT)
        
        table_frame = tk.Frame(self.main, bg=BG_DARK)
        table_frame.pack(fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree = ttk.Treeview(table_frame, columns=("SSID", "BSSID", "SIGNAL", "SECURITY", "STATUS"), show='headings', yscrollcommand=scrollbar.set, selectmode='browse')
        for col, width, anchor in [("SSID", 250, "w"), ("BSSID", 160, "center"), ("SIGNAL", 80, "center"), ("SECURITY", 220, "center"), ("STATUS", 150, "center")]:
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_by_column(c))
            self.tree.column(col, width=width, anchor=anchor)
        
        self.tree.tag_configure('danger', background="#4A0000", foreground=DANGER)
        self.tree.tag_configure('warning', background="#4A3800", foreground=WARNING)
        self.tree.tag_configure('safe', background=BG_DARK, foreground=TEXT_MAIN)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
        
        action_bar = tk.Frame(self.main, bg=BG_CARD, height=80)
        action_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(15, 0))
        action_bar.pack_propagate(False)
        
        tk.Button(action_bar, text="🚫 BLOCK NETWORK", command=self._block_selected_network, bg="#7F1D1D", fg=DANGER, font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2", padx=20, pady=12).pack(side=tk.LEFT, padx=15)
        tk.Button(action_bar, text="📋 BLOCKED LIST", command=self._show_blocked_list, bg="#374151", fg=TEXT_MAIN, font=("Segoe UI", 10), relief="flat", cursor="hand2", padx=20, pady=12).pack(side=tk.LEFT, padx=5)
        tk.Button(action_bar, text="📜 THREAT HISTORY", command=self._show_threat_history, bg="#1E3A5F", fg=TEXT_MAIN, font=("Segoe UI", 10), relief="flat", cursor="hand2", padx=20, pady=12).pack(side=tk.RIGHT, padx=15)

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=BG_DARK, foreground=TEXT_MAIN, fieldbackground=BG_DARK, borderwidth=0, rowheight=35)
        style.configure("Treeview.Heading", background=BG_CARD, foreground=ACCENT, borderwidth=1, font=("Segoe UI", 10, "bold"))
        style.map("Treeview.Heading", background=[("active", "#2D3748")])

    def _start_scan_thread(self):
        def scan_loop():
            while True:
                try:
                    if not self.scanner.paused:
                        self.scanner.scan_networks()
                except Exception as e:
                    log_event("Scanner", f"Loop error: {str(e)}", "error")
                time.sleep(SCAN_INTERVAL)
        threading.Thread(target=scan_loop, daemon=True).start()

    def _animate_pulse(self):
        def pulse_loop():
            while True:
                if self.scanner.is_scanning and not self.scanner.paused:
                    self.status_label.config(text="SCANNING...", fg=ACCENT)
                    for size in range(10, 110, 5):
                        half = size / 2
                        self.canvas.coords(self.pulse_circle, 90 - half, 90 - half, 90 + half, 90 + half)
                        self.canvas.itemconfig(self.pulse_circle, state='normal')
                        time.sleep(0.03)
                    self.canvas.itemconfig(self.pulse_circle, state='hidden')
                elif self.scanner.paused:
                    self.status_label.config(text="PAUSED", fg=WARNING)
                else:
                    self.status_label.config(text="PROTECTED", fg=SUCCESS)
                time.sleep(0.5)
        threading.Thread(target=pulse_loop, daemon=True).start()

    def _manual_refresh(self):
        self.refresh_btn.config(state='disabled', text="⏳ SCANNING...")
        def refresh():
            self.scanner.scan_networks()
            time.sleep(1)
            self.refresh_btn.config(state='normal', text="🔄 REFRESH")
        threading.Thread(target=refresh, daemon=True).start()

    def _toggle_pause(self):
        self.scanner.paused = not self.scanner.paused
        self.pause_btn.config(text="▶️ RESUME" if self.scanner.paused else "⏸️ PAUSE", fg=SUCCESS if self.scanner.paused else TEXT_MAIN)
        log_event("WiFi_GUI", f"Scanner {'paused' if self.scanner.paused else 'resumed'}.")

    def _start_ui_update_loop(self):
        self._update_network_table()

    def _update_network_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        networks = self.scanner.networks
        evil_twins = self.scanner.detect_evil_twins()
        threat_count = 0
        
        for bssid, data in networks.items():
            ssid = data.get("SSID", "[Hidden]")
            signal = f"{data.get('Signal')}%"
            security = f"{data.get('Auth')} / {data.get('Encrypt')}"
            
            is_threat = ssid in evil_twins
            is_open = "none" in data.get('Encrypt', '').lower()
            
            verdict = "⚠️ CLONE DETECTED" if is_threat else ("🔓 UNSECURE" if is_open else "🛡️ SECURE")
            tag = 'danger' if is_threat else ('warning' if is_open else 'safe')
            
            if is_threat:
                threat_count += 1
                if ssid not in self.alerted_ssids:
                    self.alerted_ssids.add(ssid)
                    self.db.log_threat(ssid, bssid)
                    self._show_threat_alert(ssid, len(evil_twins[ssid]))
                    log_event("Detection", f"Evil Twin detected! SSID: {ssid}", "critical")
            
            self.tree.insert("", "end", values=(ssid, bssid, signal, security, verdict), tags=(tag,))
            
        self.total_label.config(text=str(len(networks)))
        self.threats_label.config(text=str(threat_count))
        self.blocked_label.config(text=str(len(self.db.get_all_blocks())))
        self.root.after(2000, self._update_network_table)

    def _show_threat_alert(self, ssid: str, count: int):
        try:
            import winsound
            threading.Thread(target=lambda: winsound.Beep(2500, 300), daemon=True).start()
        except: pass
        messagebox.showwarning("⚠️ Evil Twin Detected!", f"Potential rogue access point detected!\n\nNetwork: {ssid}\nDuplicate APs: {count}\n\nVerify before connecting!")

    def _sort_by_column(self, column: str):
        if self.sort_column == column: self.sort_reverse = not self.sort_reverse
        else: self.sort_column, self.sort_reverse = column, False
        items = [(self.tree.set(item, column), item) for item in self.tree.get_children()]
        if column == "SIGNAL": items.sort(key=lambda x: int(re.search(r'\d+', x[0]).group() if re.search(r'\d+', x[0]) else '0'), reverse=self.sort_reverse)
        else: items.sort(reverse=self.sort_reverse)
        for index, (_, item) in enumerate(items): self.tree.move(item, '', index)

    def _block_selected_network(self):
        selection = self.tree.selection()
        if not selection: return
        ssid = self.tree.item(selection[0])['values'][0]
        if messagebox.askyesno("Confirm Block", f"Block network '{ssid}'?"):
            if self.blocker.block_ssid(ssid):
                self.db.add_block(ssid); messagebox.showinfo("Success", f"Network '{ssid}' blocked.")
                log_event("Blocker", f"User blocked SSID: {ssid}")
            else: messagebox.showerror("Error", "Failed to block. Requires Administrator.")

    def _show_blocked_list(self):
        dialog = tk.Toplevel(self.root); dialog.configure(bg=BG_SIDE); dialog.title("Blocked Networks")
        dialog.geometry("400x500")
        tk.Label(dialog, text="🚫 Blocked Networks", font=("Segoe UI", 16, "bold"), bg=BG_SIDE, fg=DANGER).pack(pady=20)
        lb = tk.Listbox(dialog, bg=BG_DARK, fg=TEXT_MAIN, font=("Consolas", 11), borderwidth=0, highlightthickness=0); lb.pack(fill=tk.BOTH, expand=True, padx=20)
        blocked = self.db.get_all_blocks()
        for s in blocked: lb.insert(tk.END, s)
        def unblock():
            try:
                s = lb.get(lb.curselection()); 
                if self.blocker.unblock_ssid(s): self.db.remove_block(s); lb.delete(lb.curselection()); log_event("Blocker", f"User unblocked SSID: {s}")
            except: pass
        tk.Button(dialog, text="UNBLOCK SELECTED", command=unblock, bg=BG_CARD, fg=SUCCESS, relief="flat", padx=20, pady=10).pack(pady=20)

    def _show_threat_history(self):
        dialog = tk.Toplevel(self.root); dialog.configure(bg=BG_SIDE); dialog.title("Threat History")
        dialog.geometry("600x500")
        tk.Label(dialog, text="📜 Threat History", font=("Segoe UI", 16, "bold"), bg=BG_SIDE, fg=DANGER).pack(pady=20)
        txt = tk.Text(dialog, bg=BG_DARK, fg=TEXT_MAIN, font=("Consolas", 10), borderwidth=0, padx=15, pady=15); txt.pack(fill=tk.BOTH, expand=True, padx=20)
        for t in self.db.get_all_threats(): txt.insert(tk.END, f"{t}\n")
        txt.config(state="disabled")

def main():
    root = tk.Tk()
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        root.destroy()
        return
    app = IsItSafeGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
