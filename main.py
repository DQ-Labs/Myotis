import customtkinter as ctk
import sys
import os
import threading
import subprocess
import platform
import logging
import time
import ctypes
from shutil import which
from logger import setup_logger

# Initialize Logging
log = setup_logger()

# Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def get_nmap_path():
    """ 
    Returns the path to nmap executable.
    Windows: checks bin/nmap.exe (bundled or local)
    Linux: assumes 'nmap' is in PATH
    """
    system = platform.system()
    if system == "Windows":
        # Use resource_path to handle _MEIPASS detection for frozen exe
        nmap_exe = resource_path(os.path.join("bin", "nmap.exe"))
        if os.path.exists(nmap_exe):
            return nmap_exe
        return None
    else:
        return which("nmap")

def is_admin():
    """ Check if the script is running with administrative privileges """
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def handle_uncaught_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    log.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

# Set the global exception hook
sys.excepthook = handle_uncaught_exception

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.nmap_path = get_nmap_path()
        self.active_process = None 
        self.is_scanning = False
        self.is_admin_user = is_admin()

        admin_suffix = "[ADMIN]" if self.is_admin_user else "[USER]"
        self.title(f"Myotis - Vulnerability Scanner {admin_suffix}")
        self.geometry("800x600")
        
        # Grid Configuration
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1) 

        self._setup_ui()
        
        # Initial System Check
        self.after(500, self.check_system_ready)

    def _setup_ui(self):
        # 1. Header / Status
        self.status_label = ctk.CTkLabel(
            self, 
            text="Initializing...", 
            font=("Roboto", 20, "bold")
        )
        self.status_label.grid(row=0, column=0, pady=(20, 10), sticky="ew")

        # 2. Target Input
        target_frame = ctk.CTkFrame(self, fg_color="transparent")
        target_frame.grid(row=1, column=0, pady=5, padx=20, sticky="ew")
        
        ctk.CTkLabel(target_frame, text="Target:").pack(side="left", padx=5)
        self.target_entry = ctk.CTkEntry(target_frame, width=300)
        self.target_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.target_entry.insert(0, "127.0.0.1")

        # 3. Controls
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=2, column=0, pady=10, padx=20, sticky="ew")

        # Define Profiles
        self.scan_profiles = {
            "Quick Scan (-F)": "-F",
            "Service Version (-sV)": "-sV",
            "Detailed Scan (-sS -sV -sC)": "-sS -sV -sC",
            "Ping Sweep (-sn)": "-sn"
        }
        
        # Profile Dropdown
        self.profile_combo = ctk.CTkComboBox(
            btn_frame, 
            values=list(self.scan_profiles.keys()),
            width=200
        )
        self.profile_combo.pack(side="left", padx=5)

        # Start Button
        self.start_btn = ctk.CTkButton(
            btn_frame,
            text="Start Scan",
            command=self.start_scan
        )
        self.start_btn.pack(side="left", padx=5, expand=True)

        # Stop Button
        self.stop_btn = ctk.CTkButton(
            btn_frame, 
            text="Stop", 
            command=self.stop_scan,
            fg_color="#D32F2F", # Red
            hover_color="#B71C1C",
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5, expand=True)

        # 4. Output Textbox
        font_family = "Consolas" if platform.system() == "Windows" else "Courier"
        self.output_box = ctk.CTkTextbox(
            self, 
            font=(font_family, 12),
            activate_scrollbars=True
        )
        self.output_box.grid(row=3, column=0, padx=20, pady=20, sticky="nsew")

    def check_system_ready(self):
        if self.nmap_path:
            self.status_label.configure(text="System Ready", text_color="#3B8ED0")
            log.info("System Ready: Nmap found.")
        else:
            self.status_label.configure(text="Nmap Missing", text_color="red")
            self.append_output("Error: nmap binary not found.\n")
            self._set_buttons_state("disabled")

    def _set_buttons_state(self, state):
        self.start_btn.configure(state=state)
        # Stop button checks is_scanning logic separately in stop_scan

    def start_scan(self, args=None):
        if not self.nmap_path or self.is_scanning:
            return

        target = self.target_entry.get().strip()
        if not target:
            self.append_output("Error: No target specified.\n")
            return

        # Get flags from profile
        profile_name = self.profile_combo.get()
        scan_flags = self.scan_profiles.get(profile_name, "-F") 

        self.is_scanning = True
        self.stop_btn.configure(state="normal")
        self._set_buttons_state("disabled")
        self.output_box.delete("0.0", "end")
        self.append_output(f"Starting {profile_name} on {target}...\n")

        thread = threading.Thread(target=self._scan_thread, args=(target, scan_flags))
        thread.daemon = True
        thread.start()

    def stop_scan(self):
        if self.active_process and self.is_scanning:
            log.info("User requested Stop.")
            try:
                self.active_process.terminate()
                self.append_output("\n[!] Process terminated by user.\n")
            except Exception as e:
                log.error(f"Failed to terminate process: {e}")
                self.append_output(f"\n[!] Error terminating process: {e}\n")
        
    def _scan_thread(self, target, args):
        try:
            # Construct command
            cmd = [self.nmap_path] + args.split() + [target]
            log.info(f"Running command: {cmd}")
            
            # Windows hidden console
            startupinfo = None
            if platform.system() == "Windows":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            # Popen for streaming
            # Use shell=True check if needed (from previous fix logic)
            # Actually, robust subprocess from Step 107 used subprocess.run but scan uses Popen
            # Popen with list args and shell=True on windows *can* be weird. 
            # But the user requested shell=True earlier for robustness.
            # Let's check nmap execution manually. `args` are flags.
            # If we use list, usually we don't need shell=True unless it's a built-in.
            # But earlier fix for version check used shell=True (passed list, which works on some py versions/windows setups because it auto-joins, or fails).
            # subprocess.Popen on Windows with shell=True expects a string unless we want weird behavior.
            # However, `nmap.exe` check earlier (Step 110) worked with `.run`.
            # Let's respect the Vibe Coding safety: lists are best.
            # If it fails, we fall back. But standard is list.

            self.active_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Merge stderr
                text=True,
                bufsize=1, # Line buffered
                startupinfo=startupinfo
            )

            # Stream output
            for line in iter(self.active_process.stdout.readline, ''):
                if line:
                    self.after(0, self.append_output, line)
            
            self.active_process.stdout.close()
            return_code = self.active_process.wait()
            
            msg = f"\nScan finished with exit code: {return_code}\n"
            self.after(0, self.append_output, msg)
            log.info(msg.strip())

        except Exception as e:
            log.error(f"Scan thread error: {e}", exc_info=True)
            self.after(0, self.append_output, f"\nError: {e}\n")
        finally:
            self.active_process = None
            self.is_scanning = False
            self.after(0, self._scan_complete_ui_reset)

    def _scan_complete_ui_reset(self):
        self.stop_btn.configure(state="disabled")
        self._set_buttons_state("normal")
        self.status_label.configure(text="Scan Complete", text_color="#3B8ED0")

    def append_output(self, text):
        self.output_box.insert("end", text)
        self.output_box.see("end")

if __name__ == "__main__":
    if platform.system() == "Windows":
        if not is_admin():
            try:
                executable = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                params = [script_path] + sys.argv[1:]
                cmd_params = subprocess.list2cmdline(params)
                cwd = os.path.dirname(script_path)

                log.info(f"Attempting elevation. Exe: {executable}, Params: {cmd_params}, Cwd: {cwd}")
                
                ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas", 
                    executable, 
                    cmd_params, 
                    cwd, 
                    1
                )
                sys.exit() 
            except Exception as e:
                log.error(f"Failed to elevate privileges: {e}", exc_info=True)

    app = App()
    app.mainloop()
