"""
NetGuard Pro - Advanced Network Security Suite
Firewall & Traffic Monitor + WiFi Security Auditor
Developed by: USAID, BILAL, SHADAN and AYAN
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import threading
import socket
import time
from datetime import datetime
import platform
import os
import sys
import ctypes

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

class UnifiedPacketScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Unified Packet Scanner & Traffic Monitor")
        self.root.geometry("1100x650")
        self.root.configure(bg='#0a0e27')
        self.capturing = False
        self.thread = None
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.active_connections = 0
        self.setup_ui()
        self.update_stats_loop()
        self.root.mainloop()

    def setup_ui(self):
        header = tk.Frame(self.root, bg='#1e2749', height=60)
        header.pack(fill='x')
        tk.Label(header, text="NetGuard Pro - Packet Scanner & Traffic Monitor", font=('Arial', 22, 'bold'), fg='#00d9ff', bg='#1e2749').pack(pady=12)
        main = tk.Frame(self.root, bg='#0a0e27')
        main.pack(fill='both', expand=True, padx=10, pady=10)
        left = tk.Frame(main, bg='#1e2749', width=260)
        left.pack(side='left', fill='y', padx=(0,10))
        tk.Label(left, text='Control Panel', bg='#1e2749', fg='white', font=('Arial', 13, 'bold')).pack(pady=10)
        self.start_btn = tk.Button(left, text='▶ Start Capture', bg='#00d9ff', fg='#0a0e27', command=self.toggle_capture, relief='flat', font=('Arial', 11, 'bold'))
        self.start_btn.pack(pady=8, padx=10, fill='x')
        tk.Label(left, text='Filter (BPF or substring):', bg='#1e2749', fg='#8892b0', font=('Arial', 9)).pack(pady=(20,5), padx=10)
        self.filter_entry = tk.Entry(left)
        self.filter_entry.pack(padx=10, fill='x')
        tk.Button(left, text='Export Log', bg='#50fa7b', fg='#0a0e27', command=self.export_log, relief='flat').pack(pady=20, padx=10, fill='x')
        stats_frame = tk.LabelFrame(left, text="Live Statistics", bg='#1e2749', fg='#00d9ff', font=('Arial', 11, 'bold'))
        stats_frame.pack(pady=10, padx=10, fill='x')
        self.stats_labels = {}
        for stat in ['Bytes Sent', 'Bytes Recv', 'Active Connections']:
            frame = tk.Frame(stats_frame, bg='#1e2749')
            frame.pack(fill='x', padx=5, pady=3)
            tk.Label(frame, text=f"{stat}:", fg='#8892b0', bg='#1e2749', font=('Arial', 9)).pack(side='left')
            self.stats_labels[stat] = tk.Label(frame, text="0", fg='#00d9ff', bg='#1e2749', font=('Arial', 9, 'bold'))
            self.stats_labels[stat].pack(side='right')
        right = tk.Frame(main, bg='#0a0e27')
        right.pack(side='left', fill='both', expand=True)
        cols = ('Time','Proto','Source','Destination','Len','Info')
        self.packet_tree = ttk.Treeview(right, columns=cols, show='headings', height=22)
        for c in cols:
            self.packet_tree.heading(c, text=c)
            self.packet_tree.column(c, width=140)
        self.packet_tree.pack(side='top', fill='both', expand=True)
        self.log_text = scrolledtext.ScrolledText(right, height=7, bg='#0a0e27', fg='#00ff00', font=('Consolas', 10))
        self.log_text.pack(fill='x', pady=(8,0))
        backend = 'Scapy' if SCAPY_AVAILABLE else 'psutil (no raw capture)'
        self.log(f'Using backend: {backend} | Admin: {self.is_admin()}')
        footer = tk.Label(self.root, text="Developed by: USAID, BILAL, SHADAN and AYAN", font=('Arial', 10), fg='#00d9ff', bg='#0a0e27')
        footer.pack(side='bottom', pady=8)

    def is_admin(self):
        try:
            if platform.system() == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def toggle_capture(self):
        if not self.capturing:
            self.capturing = True
            self.start_btn.config(text='⏸ Stop Capture', bg='#ff5555')
            self.thread = threading.Thread(target=self.capture_loop, daemon=True)
            self.thread.start()
            self.log('🟢 Capture started')
        else:
            self.capturing = False
            self.start_btn.config(text='▶ Start Capture', bg='#00d9ff')
            self.log('🔴 Capture stopped')

    def capture_loop(self):
        if SCAPY_AVAILABLE and self.is_admin():
            try:
                bpf = self.filter_entry.get().strip()
                sniff(prn=self.handle_packet, store=False, filter=bpf if bpf else None)
            except Exception as e:
                self.log(f'❌ Scapy capture error: {e}')
        while self.capturing:
            if PSUTIL_AVAILABLE:
                try:
                    conns = psutil.net_connections(kind='inet')
                    now = datetime.now().strftime('%H:%M:%S')
                    self.active_connections = sum(1 for c in conns if c.status == 'ESTABLISHED')
                    for c in conns:
                        proto = 'TCP' if c.type == socket.SOCK_STREAM else 'UDP'
                        laddr = f"{getattr(c.laddr,'ip', '')}:{getattr(c.laddr,'port','') if getattr(c.laddr,'port',None) else ''}"
                        raddr = f"{getattr(c.raddr,'ip', '')}:{getattr(c.raddr,'port','') if getattr(c.raddr,'port',None) else ''}"
                        info = f"{c.status}"
                        self.root.after(0, lambda t=now,p=proto,s=laddr,d=raddr,l=0,i=info: self.packet_tree.insert('', 'end', values=(t,p,s,d,l,i)))
                    time.sleep(2)
                except Exception as e:
                    self.log(f'❌ Polling error: {e}')
                    break
            else:
                self.log('❌ psutil not available for fallback capture')
                break

    def handle_packet(self, pkt):
        try:
            ts = datetime.now().strftime('%H:%M:%S')
            proto = 'OTHER'
            src = ''
            dst = ''
            length = len(pkt)
            info = ''
            if IP in pkt:
                ip = pkt[IP]
                src = f"{ip.src}:{getattr(pkt.payload,'sport','')}"
                dst = f"{ip.dst}:{getattr(pkt.payload,'dport','')}"
                if TCP in pkt:
                    proto = 'TCP'
                    info = f"Flags={pkt[TCP].flags}"
                elif UDP in pkt:
                    proto = 'UDP'
                else:
                    proto = str(ip.proto)
            self.root.after(0, lambda: self.packet_tree.insert('', 'end', values=(ts, proto, src, dst, length, info)))
        except Exception as e:
            self.log(f'❌ Packet parse error: {e}')

    def update_stats_loop(self):
        if PSUTIL_AVAILABLE:
            try:
                net_io = psutil.net_io_counters()
                self.bytes_sent = net_io.bytes_sent
                self.bytes_recv = net_io.bytes_recv
                self.stats_labels['Bytes Sent'].config(text=self.format_bytes(self.bytes_sent))
                self.stats_labels['Bytes Recv'].config(text=self.format_bytes(self.bytes_recv))
                self.stats_labels['Active Connections'].config(text=str(self.active_connections))
            except Exception:
                pass
        self.root.after(2000, self.update_stats_loop)

    def format_bytes(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024.0:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.2f} PB"

    def export_log(self):
        filename = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text','*.txt'),('All','*.*')])
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get(1.0, tk.END))
            self.log(f'💾 Log exported to {filename}')

    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert('end', f"[{timestamp}] {message}\n")
        self.log_text.see('end')

if __name__ == "__main__":
    UnifiedPacketScanner()