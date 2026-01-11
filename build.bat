@echo off
echo Building Myotis...

if not exist assets (
    mkdir assets
    echo Created assets directory.
)

:CheckVenv
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate
) else (
    echo Venv not found or structure invalid. Proceeding with system python...
)

echo Cleaning previous builds...
rmdir /s /q build dist 2>nul
del /q *.spec 2>nul

echo Running PyInstaller...
:: Assumes assets directory exists. If it has content, it will be copied.
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "Myotis" --add-data "assets;assets" --add-data "bin;bin" main.py

echo Build complete. Check dist/Myotis.exe
pause
