@echo off
echo checking for python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] python was not found. please install python and ensure 'add python to path' is checked.
    pause
    exit /b 1
)

echo [*] creating virtual environment (venv)...
python -m venv venv
call venv\scripts\activate.bat

echo [*] installing dependencies from requirements.txt...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [+] setup completed successfully. launch the app using run.bat.
pause