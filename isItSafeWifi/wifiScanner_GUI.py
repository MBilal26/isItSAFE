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

SCAN_INTERVAL = 3

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
        
        # --- ACTION BAR ---
        self.action_bar = tk.Frame(self.main, bg=BG_CARD, height=60)
        self.action_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 15))
        self.action_bar.pack_propagate(False)
        
        self.block_btn = tk.Button(self.action_bar, text="🚫 BLOCK SSID", command=self._block_selected_network, bg="#7F1D1D", fg="#FFFFFF", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2", padx=15, pady=8)
        self.block_btn.pack(side=tk.LEFT, padx=10)
        
        self.connect_btn = tk.Button(self.action_bar, text="📡 CONNECT", command=self._connect_to_network, bg=BG_CARD, fg=TEXT_DIM, font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2", padx=15, pady=8, state='disabled')
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.blocked_list_btn = tk.Button(self.action_bar, text="📋 BLOCKED", command=self._show_blocked_list, bg="#374151", fg=TEXT_MAIN, font=("Segoe UI", 10), relief="flat", cursor="hand2", padx=15, pady=8)
        self.blocked_list_btn.pack(side=tk.LEFT, padx=5)
        
        self.history_btn = tk.Button(self.action_bar, text="📜 HISTORY", command=self._show_threat_history, bg="#1E3A5F", fg=TEXT_MAIN, font=("Segoe UI", 10), relief="flat", cursor="hand2", padx=15, pady=8)
        self.history_btn.pack(side=tk.RIGHT, padx=10)
        
        # --- TABLE ---
        table_frame = tk.Frame(self.main, bg=BG_DARK)
        table_frame.pack(fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree = ttk.Treeview(table_frame, columns=("SSID", "BSSID", "SIGNAL", "SECURITY", "STATUS"), show='headings', yscrollcommand=scrollbar.set, selectmode='browse')
        for col, width, anchor in [("SSID", 250, "w"), ("BSSID", 160, "center"), ("SIGNAL", 80, "center"), ("SECURITY", 220, "center"), ("STATUS", 150, "center")]:
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_by_column(c))
            self.tree.column(col, width=width, anchor=anchor)
        
        self.tree.tag_configure('danger', background="#7F1D1D", foreground=DANGER)
        self.tree.tag_configure('warning', background=WARNING, foreground=BG_DARK)
        self.tree.tag_configure('safe', background=BG_DARK, foreground=TEXT_MAIN)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._show_context_menu)
        scrollbar.config(command=self.tree.yview)
        
        # Context Menu (already defined)
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=BG_SIDE, fg=TEXT_MAIN, font=("Segoe UI", 10))
        self.context_menu.add_command(label="🚫 BLOCK SSID", command=self._block_selected_network)

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=BG_DARK, foreground=TEXT_MAIN, fieldbackground=BG_DARK, borderwidth=0, rowheight=35)
        style.configure("Treeview.Heading", background=BG_CARD, foreground=ACCENT, borderwidth=1, font=("Segoe UI", 10, "bold"))
        style.map("Treeview.Heading", background=[("active", "#2D3748")])
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG_DARK)])

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
            self.scanner.clear_networks() # Clear stale data
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
        # Store expansion and selection state
        expanded = {self.tree.item(i)['values'][0]: self.tree.item(i, 'open') for i in self.tree.get_children()}
        selected_vals = None
        curr_sel = self.tree.selection()
        if curr_sel: selected_vals = self.tree.item(curr_sel[0])['values']
        
        # Clear table
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        networks = self.scanner.networks
        evil_twins = self.scanner.detect_evil_twins()
        blocked_ssids = self.db.get_all_blocks()
        
        # Group data for SSID Parents
        ssid_groups = {}
        for bssid, data in networks.items():
            ssid = data.get("SSID", "[Hidden]")
            if ssid in blocked_ssids: continue
            
            if ssid not in ssid_groups:
                ssid_groups[ssid] = {"bssids": [], "max_signal": 0, "security": []}
            
            sig = int(data.get("Signal", 0))
            ssid_groups[ssid]["bssids"].append((bssid, data))
            ssid_groups[ssid]["max_signal"] = max(ssid_groups[ssid]["max_signal"], sig)
            sec = f"{data.get('Auth')} / {data.get('Encrypt')}"
            if sec not in ssid_groups[ssid]["security"]:
                ssid_groups[ssid]["security"].append(sec)

        threat_count = 0
        for ssid, group in ssid_groups.items():
            threat_info = evil_twins.get(ssid)
            is_mismatch = threat_info and threat_info["type"] == "mismatch"
            is_duplicate = threat_info and threat_info["type"] == "duplicate"
            
            # Determine color/verdict for parent
            tag = 'safe'
            verdict = "🛡️ SECURE"
            if is_mismatch:
                verdict = "🚨 EVIL TWIN"
                tag = 'danger'
                threat_count += 1
            elif is_duplicate:
                verdict = "📶 MESH NETWORK"
                tag = 'warning'
            
            parent_id = self.tree.insert("", "end", values=(ssid, f"{len(group['bssids'])} APs", f"{group['max_signal']}%", ", ".join(group['security']), verdict), tags=(tag,), open=expanded.get(ssid, False))
            
            # Insert children (BSSIDs)
            for bssid, data in group['bssids']:
                c_sig = f"{data.get('Signal')}%"
                c_sec = f"{data.get('Auth')} / {data.get('Encrypt')}"
                c_tag = 'danger' if "none" in data.get('Encrypt', '').lower() else 'safe'
                c_verdict = "🔓 UNSECURE" if "none" in data.get('Encrypt', '').lower() else "🛡️ AP VALID"
                
                self.tree.insert(parent_id, "end", values=("  ↳ " + bssid, bssid, c_sig, c_sec, c_verdict), tags=(c_tag,))

            if is_mismatch or is_duplicate:
                if ssid not in self.alerted_ssids:
                    self.alerted_ssids.add(ssid)
                    if is_mismatch:
                        self.db.log_threat(ssid, group['bssids'][0][0])
                        self._show_threat_alert(ssid, len(group['bssids']), is_evil_twin=True)
                    else:
                        self._show_threat_alert(ssid, len(group['bssids']), is_evil_twin=False)
        
        # Restore selection
        if selected_vals:
            for item in self.tree.get_children():
                if self.tree.item(item)['values'][0] == selected_vals[0]:
                    self.tree.selection_set(item)
                    self.tree.see(item)
                    break
                # Check children
                for child in self.tree.get_children(item):
                    if self.tree.item(child)['values'][0] == selected_vals[0]:
                        self.tree.selection_set(child)
                        self.tree.see(child)
                        break
            self._on_tree_select(None) # Force visibility check
            
        self.total_label.config(text=str(len(ssid_groups)))
        self.threats_label.config(text=str(threat_count))
        self.blocked_label.config(text=str(len(blocked_ssids)))
        self.root.after(3000, self._update_network_table)

    def _show_threat_alert(self, ssid: str, count: int, is_evil_twin: bool = True):
        def play_alert():
            try:
                import winsound
                if is_evil_twin:
                    for _ in range(3):
                        winsound.Beep(2500, 400)
                        time.sleep(0.1)
                else:
                    winsound.Beep(1000, 300)
            except: pass
        threading.Thread(target=play_alert, daemon=True).start()
        
        title = "🚨 Evil Twin Detected!" if is_evil_twin else "📶 Mesh Network Detected"
        msg = (f"Potential rogue access point detected!\n\nNetwork: {ssid}\nDuplicate APs: {count}\n\nVerify before connecting!" 
               if is_evil_twin else 
               f"Multiple access points detected for: {ssid}\nAPs found: {count}\n\nThis is usually a legitimate mesh network.")
        messagebox.showwarning(title, msg) if is_evil_twin else messagebox.showinfo(title, msg)

    def _on_tree_select(self, event=None):
        # Toggle button state based on selection
        if self.tree.selection():
            self.connect_btn.config(state='normal', bg="#065F46", fg=SUCCESS)
        else:
            self.connect_btn.config(state='disabled', bg=BG_CARD, fg=TEXT_DIM)


    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _connect_to_network(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please click on a WiFi network in the list first, then click Connect!")
            return
            
        values = self.tree.item(selection[0])['values']
        target = values[0].replace("  ↳ ", "").strip()
        is_bssid = ":" in target and len(target) > 10
        ssid = target if not is_bssid else self.tree.item(self.tree.parent(selection[0]))['values'][0]
        
        # Check if profile exists
        try:
            check_cmd = f'netsh wlan show profile name="{ssid}"'
            has_profile = subprocess.run(check_cmd, shell=True, capture_output=True, creationflags=0x08000000).returncode == 0
            
            password = None
            if not has_profile:
                password = self._ask_password(ssid)
                if password is None: return # User cancelled
                
            self.connect_btn.config(state='disabled', text="⏳ CONNECTING...")
            
            def do_connect():
                try:
                    if not has_profile and password:
                        # Create profile
                        xml_content = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""
                        temp_xml = os.path.join(os.environ["TEMP"], f"{ssid}.xml")
                        with open(temp_xml, "w") as f: f.write(xml_content)
                        subprocess.run(f'netsh wlan add profile filename="{temp_xml}"', shell=True, creationflags=0x08000000)
                        os.remove(temp_xml)

                    cmd = f'netsh wlan connect name="{ssid}"'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)
                    if result.returncode == 0:
                        self.root.after(0, lambda: messagebox.showinfo("Success", f"Connecting to {ssid}..."))
                    else:
                        self.root.after(0, lambda: messagebox.showerror("Error", f"Failed: {result.stdout}"))
                finally:
                    self.root.after(0, lambda: self.connect_btn.config(state='normal', text="📡 CONNECT"))

            threading.Thread(target=do_connect, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _ask_password(self, ssid):
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Password for {ssid}")
        dialog.geometry("350x180")
        dialog.configure(bg=BG_SIDE)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text=f"Enter password for {ssid}:", bg=BG_SIDE, fg=TEXT_MAIN, font=("Segoe UI", 10)).pack(pady=15)
        entry = tk.Entry(dialog, show="*", bg=BG_DARK, fg=TEXT_MAIN, insertbackground=ACCENT, font=("Segoe UI", 11), relief="flat")
        entry.pack(padx=20, pady=5, fill=tk.X)
        entry.focus()
        
        res = [None]
        def ok(): res[0] = entry.get(); dialog.destroy()
        def cancel(): dialog.destroy()
        
        btn_f = tk.Frame(dialog, bg=BG_SIDE)
        btn_f.pack(pady=15)
        tk.Button(btn_f, text="CONNECT", command=ok, bg=ACCENT, fg=BG_DARK, font=("Segoe UI", 9, "bold"), padx=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="CANCEL", command=cancel, bg=BG_CARD, fg=TEXT_MAIN, font=("Segoe UI", 9), padx=15).pack(side=tk.LEFT, padx=5)
        
        self.root.wait_window(dialog)
        return res[0]

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
        ssid = self.tree.item(selection[0])['values'][0].replace("  ↳ ", "").strip()
        # If Child BSSID selected, get parent SSID
        if self.tree.parent(selection[0]):
            ssid = self.tree.item(self.tree.parent(selection[0]))['values'][0]
            
        if messagebox.askyesno("Confirm Block", f"Block all access to '{ssid}'?"):
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
