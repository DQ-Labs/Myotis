# Myotis - Vulnerability Scanner
**A modern, high-contrast Nmap GUI built for sysadmins.**

![Myotis Version](https://img.shields.io/badge/version-v1.1-blue.svg)
![Build Status](https://github.com/DQ-Labs/myotis/actions/workflows/build.yml/badge.svg)

Myotis leverages the "Vibe Stack" (Python + `customtkinter`) to provide a sleek, dark-mode, multi-threaded interface over standard Nmap. It abstracts away complex command-line arguments, replacing them with a streamlined, easily readable UI tailored for rapid infrastructure assessment operations.

## Key Features

* **UAC Auto-Elevation:** Automatically prompts for Administrator rights on Windows to seamlessly allow raw-socket SYN scans (`-sS`) without requiring command-line tweaking.
* **Interactive Live Findings:** Features a real-time, responsive port aggregation dashboard. Discovered duplicate ports across hosts are grouped elegantly (e.g., `22/tcp x15`).
* **Target Drill-Down:** Clickable port badges act as real-time filters. Left-clicking a port badge instantly pops up a copy-pasteable list of every individual IP address hosting that specific service.
* **Data Export:** With one click, safely export cleanly-parsed scan results into structured CSV or JSON formats for reporting or further analysis.

## Installation & Usage

**Dependencies Note**: Myotis serves as a GUI to `nmap`.

### Windows Users
* Simply download the latest compiled `.exe` from the [Releases Tab](../../releases).
* Double-click the executable to run it.
* *Prerequisite:* Remember that **Npcap** must be installed on your system for advanced network scanning.

### Linux Users
* Install `nmap` via your native package manager:
  ```bash
  sudo apt update && sudo apt install nmap
  ```
* Clone the repository and install the Python requirements:
  ```bash
  git clone https://github.com/DQ-Labs/myotis.git
  cd myotis
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```
* Launch the GUI:
  ```bash
  python3 main.py
  ```

## Building from Source (Windows)

To manually compile Myotis into a standalone Windows Executable:

1. Validate you have Python 3.11+ installed.
2. Run the included batch script:
  ```cmd
  build.bat
  ```
3. The newly minted executable will be located inside the `dist/` folder.

**CI/CD Pipeline Note:** 
This repository natively includes a fully automated GitHub Actions CI/CD pipeline. Every time a new tag (e.g., `v1.1`) is pushed, GitHub servers will automatically check out the code, utilize Chocolatey to download an ephemeral build version of Nmap, bundle the dependencies using PyInstaller, and attach the finished binary to the new Release.
