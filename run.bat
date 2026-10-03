@echo off
setlocal EnableDelayedExpansion

:: 1. Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs -WindowStyle Hidden"
    exit /b
)

:: 2. Set working directory to the directory where this script is located
cd /d "%~dp0"

:: 3. Detect Python executable (prefer venv if it exists)
if exist "%~dp0venv\Scripts\pythonw.exe" (
    set "PY_BIN=%~dp0venv\Scripts\pythonw.exe"
) else (
    where pythonw >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY_BIN=pythonw.exe"
    ) else (
        where python >nul 2>&1
        if !errorlevel! equ 0 (
            set "PY_BIN=python.exe"
        ) else (
            msg * "Error: Python was not found on this system or in your PATH."
            exit /b 1
        )
    )
)

:: 4. Launch main.py detached so the batch file closes immediately
start "" "!PY_BIN!" "%~dp0main.py"
exit /b