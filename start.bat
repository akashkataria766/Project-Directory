@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel%==0 (
    set "PYTHON=python"
) else if exist "C:\Python313\python.exe" (
    set "PYTHON=C:\Python313\python.exe"
) else (
    echo Python was not found. Install Python 3.11 or newer and try again.
    pause
    exit /b 1
)

echo Installing or checking dependencies...
%PYTHON% -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

if "%GOOGLE_SAFE_BROWSING_API_KEY%"=="" (
    echo Warning: GOOGLE_SAFE_BROWSING_API_KEY is not set.
    echo The app will run local checks, but Google Safe Browsing will be unavailable.
)

echo.
echo Starting Web Security Analyzer...
echo Open http://127.0.0.1:5000 in your browser.
echo Press Ctrl+C to stop the server.
echo.
%PYTHON% app.py
pause
