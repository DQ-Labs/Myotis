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
from tkinter import filedialog
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import csv
import re
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

def _nmap_from_registry():
    """
    Look up a system-installed Nmap via the Windows registry.
    The official Nmap installer writes its install dir under the Nmap key.
    Returns the full path to nmap.exe, or None.
    """
    try:
        import winreg
    except ImportError:
        return None

    # The Nmap NSIS installer records its location here (both hives + WOW6432Node).
    candidates = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Nmap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Nmap"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Nmap"),
    ]
    for hive, subkey in candidates:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                install_dir, _ = winreg.QueryValueEx(key, "")  # default value
                exe = os.path.join(install_dir, "nmap.exe")
                if os.path.exists(exe):
                    return exe
        except OSError:
            continue
    return None

def get_nmap_path():
    """
    Returns the path to nmap executable.
    Windows: prefers the bundled bin/nmap.exe, then falls back to a
             system-installed Nmap found on PATH, in the registry, or in
             the standard Program Files locations.
    Linux: assumes 'nmap' is in PATH
    """
    system = platform.system()
    if system != "Windows":
        return which("nmap")

    # 1. Bundled copy (resource_path handles _MEIPASS for the frozen exe)
    bundled = resource_path(os.path.join("bin", "nmap.exe"))
    if os.path.exists(bundled):
        return bundled

    # 2. Nmap on PATH
    on_path = which("nmap")
    if on_path:
        return on_path

    # 3. Registry (official installer)
    from_registry = _nmap_from_registry()
    if from_registry:
        return from_registry

    # 4. Standard install locations
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if base:
            exe = os.path.join(base, "Nmap", "nmap.exe")
            if os.path.exists(exe):
                return exe

    return None

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
        self.live_ports_data = {}

        admin_suffix = "[ADMIN]" if self.is_admin_user else "[USER]"
        self.title(f"Myotis - Vulnerability Scanner {admin_suffix}")
        self.geometry("800x600")
        
        # Grid Configuration
        self.grid_columnconfigure(0, weight=3) # Console
        self.grid_columnconfigure(1, weight=1) # Findings Panel
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
            text="Start",
            font=("Roboto", 12, "bold"),
            text_color="white",
            width=100,
            command=self.start_scan
        )
        self.start_btn.pack(side="left", padx=5, expand=True)

        # Stop Button
        self.stop_btn = ctk.CTkButton(
            btn_frame, 
            text="Stop", 
            font=("Roboto", 12, "bold"),
            text_color="white",
            width=100,
            command=self.stop_scan,
            fg_color="#C62828", # Deeper Red
            hover_color="#B71C1C",
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5, expand=True)

        # Export Button
        self.export_btn = ctk.CTkButton(
            btn_frame,
            text="Export",
            font=("Roboto", 12, "bold"),
            text_color="white",
            width=100,
            command=self.export_results,
            fg_color="#2E7D32", # Forest Green
            hover_color="#1B5E20",
            state="disabled"
        )
        self.export_btn.pack(side="left", padx=5, expand=True)

        # Network Report Button (LLM-friendly host inventory)
        self.report_btn = ctk.CTkButton(
            btn_frame,
            text="Report",
            font=("Roboto", 12, "bold"),
            text_color="white",
            width=100,
            command=self.generate_network_report,
            fg_color="#1565C0", # Blue
            hover_color="#0D47A1",
            state="disabled"
        )
        self.report_btn.pack(side="left", padx=5, expand=True)

        # 4. Output Textbox (Console Style)
        font_family = "Consolas" if platform.system() == "Windows" else "Courier"
        self.output_box = ctk.CTkTextbox(
            self, 
            font=(font_family, 12),
            activate_scrollbars=True
        )
        self.output_box.grid(row=3, column=0, padx=(20, 10), pady=20, sticky="nsew")

        # 5. Live Findings Panel
        self.findings_frame = ctk.CTkScrollableFrame(
            self, 
            label_text="Live Findings",
            fg_color="transparent", # Slightly distinctive background via transparency or explicit color
            label_font=("Roboto", 14, "bold")
        )
        self.findings_frame.grid(row=3, column=1, padx=(0, 20), pady=20, sticky="nsew")

    def add_port_card(self, port, protocol, service, ip):
        port_key = f"{port}/{protocol}"
        
        if port_key in self.live_ports_data:
            self.live_ports_data[port_key]['ips'].add(ip)
            new_count = len(self.live_ports_data[port_key]['ips'])
            self.live_ports_data[port_key]['count_label'].configure(text=f"x{new_count}")
        else:
            card = ctk.CTkFrame(self.findings_frame, fg_color="#2B2B2B", cursor="hand2")
            card.pack(fill="x", pady=5, padx=5)
            
            # Port Number
            port_label = ctk.CTkLabel(
                card, 
                text=port_key, 
                font=("Roboto", 16, "bold"),
                text_color="#4CAF50", # Green
                cursor="hand2"
            )
            port_label.pack(side="left", padx=10, pady=5)
            
            # Service Name
            service_label = ctk.CTkLabel(
                card, 
                text=service, 
                font=("Roboto", 12),
                text_color="#B0BEC5",
                cursor="hand2"
            )
            service_label.pack(side="left", padx=10, pady=5)
            
            # Count Label aligned to the right
            count_label = ctk.CTkLabel(
                card,
                text="x1",
                font=("Roboto", 14, "bold"),
                text_color="#FFFFFF",
                cursor="hand2"
            )
            count_label.pack(side="right", padx=10, pady=5)
            
            # Store in tracking dictionary
            self.live_ports_data[port_key] = {
                'count_label': count_label,
                'ips': {ip}
            }

            click_handler = lambda event, pk=port_key: self.show_port_details(pk)
            card.bind("<Button-1>", click_handler)
            port_label.bind("<Button-1>", click_handler)
            service_label.bind("<Button-1>", click_handler)
            count_label.bind("<Button-1>", click_handler)

    def show_port_details(self, port_key):
        details_win = ctk.CTkToplevel(self)
        details_win.title(f"Details for {port_key}")
        details_win.geometry("400x300")
        details_win.attributes("-topmost", True)
        
        textbox = ctk.CTkTextbox(details_win, font=("Roboto", 12))
        textbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        data = self.live_ports_data.get(port_key)
        if data and 'ips' in data:
            ips = sorted(list(data['ips']))
            textbox.insert("0.0", "\n".join(ips))
        
        textbox.configure(state="disabled")

    def check_system_ready(self):
        if self.nmap_path:
            self.status_label.configure(text="System Ready", text_color="#3B8ED0")
            log.info("System Ready: Nmap found.")
        else:
            self.status_label.configure(text="Nmap Missing", text_color="red")
            self.append_output(
                "Error: nmap not found.\n"
                "Install Nmap from https://nmap.org/download.html "
                "(the installer also installs Npcap), then restart Myotis.\n"
            )
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
        self.export_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self._set_buttons_state("disabled")
        self.output_box.delete("0.0", "end")
        
        # Clear findings
        for widget in self.findings_frame.winfo_children():
            widget.destroy()
        self.live_ports_data.clear()

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
            # Add -oX temp_scan.xml for parsing later
            cmd = [self.nmap_path] + args.split() + ["-oX", "temp_scan.xml"] + [target]
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
            current_ip = None
            for line in iter(self.active_process.stdout.readline, ''):
                if line:
                    self.after(0, self.append_output, line)
                    
                    # Update current IP if host is found
                    ip_match = re.search(r"Nmap scan report for (?:[^\s]+ \()?([\d\.]+)\)?", line)
                    if ip_match:
                        current_ip = ip_match.group(1)

                    # Regex for "80/tcp open http"
                    match = re.search(r"(\d+)/(\w+)\s+open\s+(\S+)", line)
                    if match and current_ip:
                        port, proto, service = match.groups()
                        self.after(0, lambda p=port, pr=proto, s=service, ip=current_ip: self.add_port_card(p, pr, s, ip))
            
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
        self.export_btn.configure(state="normal")
        self.report_btn.configure(state="normal")
        self._set_buttons_state("normal")
        self.status_label.configure(text="Scan Complete", text_color="#3B8ED0")

    def _parse_hosts_from_xml(self, xml_path="temp_scan.xml"):
        """
        Parse an nmap XML output file into a list of host dicts.
        Each host carries identity (ipv4, hostname, mac, vendor, status)
        plus a list of open/known ports. Shared by export + report.
        """
        tree = ET.parse(xml_path)
        root = tree.getroot()

        hosts = []
        for host in root.findall("host"):
            # Status (up/down)
            status_el = host.find("status")
            status = status_el.get("state", "unknown") if status_el is not None else "unknown"

            # Addresses: a host may have both an ipv4 and a mac address
            ip_addr = "N/A"
            mac_addr = "N/A"
            vendor = "N/A"
            for address in host.findall("address"):
                addrtype = address.get("addrtype", "")
                if addrtype == "ipv4":
                    ip_addr = address.get("addr", ip_addr)
                elif addrtype == "mac":
                    mac_addr = address.get("addr", mac_addr)
                    vendor = address.get("vendor", vendor)

            # Hostname (PTR / user record)
            hostname = "N/A"
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                hostname_el = hostnames_el.find("hostname")
                if hostname_el is not None:
                    hostname = hostname_el.get("name", "N/A")

            # Ports
            ports_list = []
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    state_el = port.find("state")
                    service_el = port.find("service")
                    ports_list.append({
                        "Port": port.get("portid", "N/A"),
                        "Protocol": port.get("protocol", "N/A"),
                        "State": state_el.get("state", "N/A") if state_el is not None else "N/A",
                        "Service": service_el.get("name", "N/A") if service_el is not None else "N/A",
                    })

            hosts.append({
                "IP": ip_addr,
                "Hostname": hostname,
                "MAC": mac_addr,
                "Vendor": vendor,
                "Status": status,
                "Ports": ports_list,
            })

        return hosts

    def export_results(self):
        target_file = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv"), ("JSON File", "*.json")]
        )
        if not target_file:
            return

        try:
            hosts = self._parse_hosts_from_xml()

            scan_data = []
            for host in hosts:
                for port in host["Ports"]:
                    scan_data.append({
                        "IP": host["IP"],
                        "Port": port["Port"],
                        "Protocol": port["Protocol"],
                        "State": port["State"],
                        "Service": port["Service"],
                    })

            if target_file.lower().endswith(".json"):
                with open(target_file, "w") as f:
                    json.dump(scan_data, f, indent=4)
                log.info(f"Exported JSON to {target_file}")
            
            else: # CSV
                with open(target_file, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["IP", "Port", "Protocol", "State", "Service"])
                    writer.writeheader()
                    writer.writerows(scan_data)
                log.info(f"Exported CSV to {target_file}")
            
            self.append_output(f"\n[+] Results exported to {target_file}\n")

        except Exception as e:
            log.error(f"Export failed: {e}", exc_info=True)
            self.append_output(f"\n[!] Export failed: {e}\n")

    def generate_network_report(self):
        """
        Write an LLM-friendly network inventory (host identity only) as
        both Markdown and JSON next to a user-chosen base path.
        """
        base_path = filedialog.asksaveasfilename(
            defaultextension=".md",
            initialfile="network_report",
            filetypes=[("Markdown + JSON report", "*.md")]
        )
        if not base_path:
            return

        # Strip a trailing .md/.json so we can write both siblings
        root_path = re.sub(r"\.(md|json)$", "", base_path, flags=re.IGNORECASE)
        md_path = root_path + ".md"
        json_path = root_path + ".json"

        try:
            hosts = self._parse_hosts_from_xml()

            # Host identity only: ip, hostname, mac, vendor, status
            inventory = [
                {
                    "ip": h["IP"],
                    "hostname": h["Hostname"],
                    "mac": h["MAC"],
                    "vendor": h["Vendor"],
                    "status": h["Status"],
                }
                for h in hosts
            ]
            generated_at = datetime.now().isoformat(timespec="seconds")

            # JSON report
            report = {
                "report": "network_inventory",
                "generated_at": generated_at,
                "host_count": len(inventory),
                "hosts": inventory,
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            # Markdown report
            lines = [
                "# Network Inventory",
                "",
                f"- Generated: {generated_at}",
                f"- Hosts discovered: {len(inventory)}",
                "",
                "| Hostname | IP Address | MAC | Vendor | Status |",
                "| --- | --- | --- | --- | --- |",
            ]
            for h in inventory:
                lines.append(
                    f"| {h['hostname']} | {h['ip']} | {h['mac']} | {h['vendor']} | {h['status']} |"
                )
            lines.append("")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

            log.info(f"Network report written: {md_path}, {json_path}")
            self.append_output(
                f"\n[+] Network report written ({len(inventory)} hosts):\n"
                f"    {md_path}\n    {json_path}\n"
            )

        except Exception as e:
            log.error(f"Report generation failed: {e}", exc_info=True)
            self.append_output(f"\n[!] Report generation failed: {e}\n")

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
