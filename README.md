# Myotis

A modern desktop GUI application built with `customtkinter`.

## Developer Setup

1.  **Clone the repository.**
2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```
3.  **Activate the virtual environment:**
    - Windows: `venv\Scripts\activate`
4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
5.  **Run the application:**
    ```bash
    python main.py
    ```

## External Binaries
This application may require external tools (like FFmpeg).
- Place `ffmpeg.exe` and `ffprobe.exe` in the `bin/` or `assets/` folder (configure in code as needed).

## How to Build
To create a standalone Windows Executable (`.exe`):
1.  Ensure you have activated the virtual environment.
2.  Run the build script:
    ```cmd
    build.bat
    ```
3.  The executable will be located in the `dist/` folder.
