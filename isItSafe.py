import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk
import subprocess
import os
import sys
import threading

# Logger integration
sys.path.append(os.path.join(os.getcwd(), "logs"))
try:
    from logger import log_event
except ImportError:
    def log_event(m, msg, l="info"): pass


BG_DARK = "#0B0E14"
BG_SIDE = "#151921"
BG_CARD = "#1E293B"
ACCENT = "#00D1FF"
DANGER = "#FF3131"
SUCCESS = "#00FF41"
WARNING = "#FFB800"
TEXT_MAIN = "#E0E6ED"
TEXT_DIM = "#888888"

MODULES = [
    {
        "name": "WiFi Security Monitor",
        "desc": "Detect and prevent Evil Twin attacks",
        "path": "isItSafeWifi/wifiScanner_GUI.py",
        "icon": "📡"
    },
    {
        "name": "URL Detector",
        "desc": "Heuristic analysis for phishing URLs",
        "path": "isItSafeURL/src/phishingUrl_GUI.py",
        "icon": "🔍"
    },
    {
        "name": "Metadata Cleaner",
        "desc": "Strip sensitive data from files",
        "path": "isItSafePIC/metaData_GUI.py",
        "icon": "🖼️"
    }
]

class MainMenu:
    def __init__(self, root):
        self.root = root
        self.root.title("isItSAFE - Unified Security Suite")
        self.root.state('zoomed')
        self.root.configure(bg=BG_DARK)

        self._setup_styles()
        self._create_widgets()

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", background=BG_CARD, foreground=TEXT_MAIN, font=("Segoe UI", 10))

    def _create_widgets(self):
        # Hero Section
        hero_frame = tk.Frame(self.root, bg=BG_DARK, pady=40)
        hero_frame.pack(fill=tk.X)

        tk.Label(
            hero_frame, 
            text="isItSAFE", 
            font=("Consolas", 48, "bold"), 
            bg=BG_DARK, 
            fg=ACCENT
        ).pack()
        
        tk.Label(
            hero_frame, 
            text="Ultimate Protection Suite for your Digital Life", 
            font=("Segoe UI", 12), 
            bg=BG_DARK, 
            fg=TEXT_DIM
        ).pack(pady=5)

        # Prominent Dependency Button in Hero
        tk.Button(
            hero_frame,
            text="⚙️ INITIAL SETUP: INSTALL DEPENDENCIES",
            command=self._install_deps,
            bg=BG_CARD,
            fg=SUCCESS,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=30,
            pady=10,
            highlightthickness=1,
            highlightbackground=SUCCESS
        ).pack(pady=20)

        # Card Container
        self.card_frame = tk.Frame(self.root, bg=BG_DARK)
        self.card_frame.pack(expand=True, fill=tk.BOTH, padx=50)

        for i, module in enumerate(MODULES):
            self._create_module_card(module, i)

        # Footer
        footer = tk.Frame(self.root, bg=BG_CARD, height=50)
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        footer.pack_propagate(False)

        tk.Label(
            footer,
            text="Developed by: USAID, BILAL, SHADAN and AYAN",
            font=("Segoe UI", 8),
            bg=BG_CARD,
            fg=TEXT_DIM,
            padx=20
        ).pack(side=tk.RIGHT, fill=tk.Y)

        tk.Button(
            footer,
            text="ⓘ About isItSAFE",
            command=self._show_about,
            bg=BG_CARD,
            fg=ACCENT,
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            cursor="hand2",
            padx=20
        ).pack(side=tk.LEFT, fill=tk.Y)

    def _show_about(self):
        about_text = (
            "isItSAFE - Unified Security Suite\n"
            "Version 2.0\n\n"
            "A comprehensive toolkit for modern digital protection.\n"
            "Built with Python and passion.\n\n"
            "Contributors:\n"
            "• USAID\n"
            "• BILAL\n"
            "• SHADAN\n"
            "• AYAN"
        )
        messagebox.showinfo("About isItSAFE", about_text)

    def _create_module_card(self, module, index):
        card = tk.Frame(self.card_frame, bg=BG_CARD, padx=15, pady=20, highlightthickness=1, highlightbackground="#2D3748")
        card.grid(row=0, column=index, padx=10, sticky="nsew")
        self.card_frame.grid_columnconfigure(index, weight=1)

        tk.Label(card, text=module["icon"], font=("Segoe UI", 32), bg=BG_CARD).pack(pady=(0, 10))
        
        tk.Label(
            card, 
            text=module["name"], 
            font=("Segoe UI", 13, "bold"), 
            bg=BG_CARD, 
            fg=TEXT_MAIN
        ).pack()

        tk.Label(
            card, 
            text=module["desc"], 
            font=("Segoe UI", 9), 
            bg=BG_CARD, 
            fg=TEXT_DIM, 
            wraplength=180,
            justify="center"
        ).pack(pady=10)

        launch_btn = tk.Button(
            card,
            text="LAUNCH",
            command=lambda m=module: self._launch_module(m),
            bg=ACCENT,
            fg=BG_DARK,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=20,
            pady=8
        )
        launch_btn.pack(side=tk.BOTTOM, pady=(10, 0))

    def _launch_module(self, module):
        abs_script_path = os.path.abspath(module["path"])
        module_dir = os.path.dirname(abs_script_path)
        
        if not os.path.exists(abs_script_path):
            log_event("Main_Hub", f"Entry point missing: {abs_script_path}", "error")
            messagebox.showerror("Error", f"Could not find {module['name']} at:\n{abs_script_path}")
            return

        def run():
            try:
                log_event("Main_Hub", f"Launching {module['name']}...")
                subprocess.run([sys.executable, abs_script_path], cwd=module_dir, check=True)
            except Exception as e:
                log_event("Main_Hub", f"Launch failed for {module['name']}: {str(e)}", "error")
                messagebox.showerror("Execution Error", f"Failed to launch {module['name']}:\n{str(e)}")

        threading.Thread(target=run, daemon=True).start()

    def _install_deps(self):
        req_path = os.path.abspath("requirements.txt")
        if not os.path.exists(req_path):
            log_event("Main_Hub", "Attempted dependency install but requirements.txt is missing", "error")
            messagebox.showerror("Error", "requirements.txt not found in root directory!")
            return
            
        if messagebox.askyesno("Install Dependencies", "Do you want to install all required dependencies?\n(Requires Internet)"):
            def run_install():
                try:
                    log_event("Main_Hub", "Starting dependency installation...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path])
                    log_event("Main_Hub", "Dependencies installed successfully.")
                    self.root.after(0, lambda: messagebox.showinfo("Success", "All dependencies installed successfully!"))
                except Exception as e:
                    log_event("Main_Hub", f"Dependency install failed: {str(e)}", "error")
                    self.root.after(0, lambda: messagebox.showerror("Installation Error", f"Failed to install requirements:\n{str(e)}"))

            threading.Thread(target=run_install, daemon=True).start()
            messagebox.showinfo("Installation Started", "Dependencies are being installed in the background. Please wait for completion message.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainMenu(root)
    root.mainloop()
