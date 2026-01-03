import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import sys
import os

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector import check_fake_url
from utils import extract_url_features, log_result, validate_url

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

class DetectorApp(tk.Tk):
    """Main application class for the Fake URL Detector with Premium UI."""
    
    def __init__(self):
        super().__init__()
        
        self.title("isItSafe - URL Security Detector")
        self.state('zoomed')
        self.configure(bg=BG_DARK)
        
        self.setup_styles()
        self.build_gui()
        self.bulk_results = []
        
    def setup_styles(self):
        """Configure custom styles for the application."""
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure(
            "Treeview",
            background=BG_DARK,
            foreground=TEXT_MAIN,
            fieldbackground=BG_DARK,
            borderwidth=0,
            rowheight=35
        )
        
        style.configure(
            "Treeview.Heading",
            background=BG_CARD,
            foreground=ACCENT,
            borderwidth=1,
            font=("Segoe UI", 10, "bold")
        )
        
        style.map("Treeview.Heading", background=[("active", "#2D3748")])
        
    def build_gui(self):
        """Build the premium GUI components."""
        # Sidebar
        sidebar = tk.Frame(self, bg=BG_SIDE, width=280)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Logo Area
        logo_frame = tk.Frame(sidebar, bg=BG_SIDE)
        logo_frame.pack(pady=(40, 20))
        
        tk.Label(
            logo_frame,
            text="isItSafe",
            font=("Consolas", 28, "bold"),
            bg=BG_SIDE,
            fg=ACCENT
        ).pack()
        
        tk.Label(
            logo_frame,
            text="URL Security Shield",
            font=("Segoe UI", 9),
            bg=BG_SIDE,
            fg=TEXT_DIM
        ).pack()
        
        # Icon/Illustration space
        tk.Label(
            sidebar,
            text="🔍",
            font=("Segoe UI", 72),
            bg=BG_SIDE,
            fg=BG_CARD
        ).pack(pady=30)
        
        # Quick Info
        tk.Label(
            sidebar,
            text="Heuristic Analysis Engine v2.0",
            font=("Segoe UI", 8, "italic"),
            bg=BG_SIDE,
            fg=TEXT_DIM,
            wraplength=200
        ).pack(side=tk.BOTTOM, pady=20)

        # Main Content Area
        main_area = tk.Frame(self, bg=BG_DARK)
        main_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Header
        header = tk.Frame(main_area, bg=BG_DARK)
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            header,
            text="🛡️ URL Detection Console",
            font=("Segoe UI", 18, "bold"),
            bg=BG_DARK,
            fg=TEXT_MAIN
        ).pack(side=tk.LEFT)

        # Single URL Card
        single_card = tk.Frame(main_area, bg=BG_CARD, padx=20, pady=20)
        single_card.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            single_card, 
            text="SCAN SINGLE URL", 
            font=("Segoe UI", 10, "bold"), 
            bg=BG_CARD, 
            fg=ACCENT
        ).pack(anchor=tk.W)
        
        entry_frame = tk.Frame(single_card, bg=BG_CARD)
        entry_frame.pack(fill=tk.X, pady=10)
        
        self.url_entry = tk.Entry(
            entry_frame,
            bg=BG_DARK,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
            font=("Segoe UI", 11),
            relief="flat",
            highlightthickness=1,
            highlightbackground="#2D3748"
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(0, 10))
        self.url_entry.bind("<Return>", lambda e: self.detect_single_url())
        
        tk.Button(
            entry_frame,
            text="ANALYZE",
            command=self.detect_single_url,
            bg=ACCENT,
            fg=BG_DARK,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=20
        ).pack(side=tk.RIGHT)

        # Result display area in single card
        self.res_display_frame = tk.Frame(single_card, bg=BG_CARD)
        self.res_display_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.result_label = tk.Label(
            self.res_display_frame,
            text="ENTER A URL TO BEGIN SCAN",
            font=("Segoe UI", 11, "bold"),
            bg=BG_CARD,
            fg=TEXT_DIM
        )
        self.result_label.pack(side=tk.LEFT)
        
        self.score_label = tk.Label(
            self.res_display_frame,
            text="",
            font=("Consolas", 11, "bold"),
            bg=BG_CARD,
            fg=WARNING
        )
        self.score_label.pack(side=tk.RIGHT)

        # Bulk Scanning Card
        bulk_card = tk.Frame(main_area, bg=BG_CARD, padx=20, pady=20)
        bulk_card.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(
            bulk_card, 
            text="BATCH PROCESSING", 
            font=("Segoe UI", 10, "bold"), 
            bg=BG_CARD, 
            fg=ACCENT
        ).pack(anchor=tk.W)
        
        batch_ctrl = tk.Frame(bulk_card, bg=BG_CARD)
        batch_ctrl.pack(fill=tk.X, pady=10)
        
        tk.Button(
            batch_ctrl,
            text="📁 IMPORT FILE",
            command=self.detect_bulk_urls,
            bg="#2D3748",
            fg=TEXT_MAIN,
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=15,
            pady=5
        ).pack(side=tk.LEFT)
        
        tk.Button(
            batch_ctrl,
            text="🧹 CLEAR",
            command=self.clear_bulk_results,
            bg="#2D3748",
            fg=TEXT_MAIN,
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=10)
        
        self.progress_label = tk.Label(
            batch_ctrl,
            text="",
            bg=BG_CARD,
            fg=TEXT_DIM,
            font=("Segoe UI", 9)
        )
        self.progress_label.pack(side=tk.RIGHT)

        # Bulk table
        table_frame = tk.Frame(bulk_card, bg=BG_DARK)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_table = ttk.Treeview(
            table_frame,
            columns=("URL", "Risk Score", "Result", "Domain"),
            show='headings',
            yscrollcommand=scrollbar.set
        )
        
        self.results_table.heading("URL", text="URL", anchor=tk.W)
        self.results_table.heading("Risk Score", text="SCORE", anchor=tk.CENTER)
        self.results_table.heading("Result", text="VERDICT", anchor=tk.CENTER)
        self.results_table.heading("Domain", text="DOMAIN", anchor=tk.W)
        
        self.results_table.column("URL", width=400, anchor=tk.W)
        self.results_table.column("Risk Score", width=80, anchor=tk.CENTER)
        self.results_table.column("Result", width=120, anchor=tk.CENTER)
        self.results_table.column("Domain", width=150, anchor=tk.W)
        
        self.results_table.tag_configure('danger', background="#4A0000", foreground=DANGER)
        self.results_table.tag_configure('safe', background=BG_DARK, foreground=TEXT_MAIN)
        
        self.results_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.results_table.yview)

    def detect_single_url(self):
        """Detect a single URL and display the premium result."""
        url = self.url_entry.get().strip()
        
        if not url:
            return
        
        if not validate_url(url):
            messagebox.showerror("Invalid URL", "Please enter a valid URL (starting with http/https)")
            return
        
        score = check_fake_url(url)
        subdomain, domain, tld = extract_url_features(url)
        
        if score >= 5:
            self.result_label.config(text="❌ THREAT DETECTED: FAKE / PHISHING", fg=DANGER)
            log_event("URL_Detector", f"Threat detected: {url} (Score: {score})", "warning")
        else:
            self.result_label.config(text="✅ LEGITIMATE: NO THREATS FOUND", fg=SUCCESS)
            log_event("URL_Detector", f"Safe URL: {url}")
            
        self.score_label.config(text=f"RISK SCORE: {score}/10")
        log_result(url, score, "FAKE" if score >= 5 else "LEGIT", (subdomain, domain, tld))

    def detect_bulk_urls(self):
        file_path = filedialog.askopenfilename(
            title="Select URL File",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file_path:
            thread = threading.Thread(target=self._bulk_scan_thread, args=(file_path,))
            thread.daemon = True
            thread.start()
            
    def _bulk_scan_thread(self, file_path):
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        for item in self.results_table.get_children():
            self.results_table.delete(item)

        for index, url in enumerate(urls):
            if not validate_url(url): continue
            
            score = check_fake_url(url)
            subdomain, domain, tld = extract_url_features(url)
            verdict = "PHISHING" if score >= 5 else "SAFE"
            tag = 'danger' if score >= 5 else 'safe'
            
            self.results_table.insert("", tk.END, values=(url, score, verdict, domain), tags=(tag,))
            self.progress_label.config(text=f"Progress: {index+1}/{len(urls)}")
            self.update_idletasks()

        messagebox.showinfo("Complete", f"Successfully scanned {len(urls)} URLs")

    def clear_bulk_results(self):
        for item in self.results_table.get_children():
            self.results_table.delete(item)
        self.progress_label.config(text="")

if __name__ == "__main__":
    app = DetectorApp()
    app.mainloop()


