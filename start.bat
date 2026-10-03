@echo off
setlocal
cd /d "%~dp0"
set "PYCMD="

rem Find a real Python 3.10+. The version check also rejects the Microsoft Store
rem "python.exe" shortcut that Windows ships when Python is not installed.
for %%C in ("py -3" "python" "python3") do (
  if not defined PYCMD (
    %%~C -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "PYCMD=%%~C"
  )
)

if not defined PYCMD (
  echo.
  echo  SAYNO needs Python 3.10 or newer, and it was not found on this computer.
  echo.
  echo  1. The download page is opening now: https://www.python.org/downloads/
  echo  2. Run the installer and tick "Add python.exe to PATH" on the first screen.
  echo  3. When it finishes, double-click start.bat again.
  echo.
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)

if not exist config.json copy config.example.json config.json >nul
%PYCMD% server\app.py %*
echo.
echo SAYNO stopped.
pause
