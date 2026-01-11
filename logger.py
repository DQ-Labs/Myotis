import logging
import os
import platform
import sys

def setup_logger(app_name="Myotis"):
    """
    Sets up a logger that writes to a debug.log file in:
    - %APPDATA%/app_name/debug.log (Windows)
    - ~/.config/app_name/debug.log (Linux)
    """
    
    system = platform.system()
    
    if system == "Windows":
        base_dir = os.getenv("APPDATA")
        if not base_dir:
            base_dir = os.path.expanduser("~\\AppData\\Roaming")
    else:
        # Linux / MacOS fallback
        base_dir = os.path.expanduser("~/.config")

    log_dir = os.path.join(base_dir, app_name)
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, "debug.log")
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode='a', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logging.info(f"Logger initialized. Writing to: {log_file}")
    return logging.getLogger(app_name)
