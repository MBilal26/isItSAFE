@echo off
title isItSAFE - Unified Security Suite
echo Starting isItSAFE...

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found! Please install Python from python.org.
    pause
    exit /b
)

:: Run the main application
python main.py

if %errorlevel% neq 0 (
    echo [ERROR] Application crashed. Check logs/app.log for details.
    pause
)
