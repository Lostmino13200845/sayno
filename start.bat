@echo off
cd /d "%~dp0"
where py >nul 2>nul && (set PYCMD=py) || (set PYCMD=python)
%PYCMD% --version >nul 2>nul || (echo Python 3.10+ is required: https://www.python.org/downloads/ & pause & exit /b 1)
if not exist config.json copy config.example.json config.json >nul
%PYCMD% server\app.py
pause
