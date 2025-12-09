@echo off
REM SonarLink v2.0 - Windows Installation Script
REM Supports Python 3.8+ with automatic architecture detection
REM Features: Audio file transfer, private/open chat, encryption, audit logs

echo =======================================
echo   SonarLink v2.0 - Windows Installer
echo =======================================
echo.
echo Features: Audio-based file transfer + chat messaging
echo Encryption: AES-256-GCM, RSA-4096, FSS1 format
echo Limit: 10 KB files (keys, passwords, credentials)
echo.

REM Check Python installation
echo [1/6] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo.
    echo Please install Python from https://www.python.org/downloads/
    echo IMPORTANT: During installation, check "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version
echo.

REM Detect Python version and architecture
echo [2/6] Detecting system configuration...
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

REM Detect architecture
python -c "import platform; print(platform.machine())" > temp_arch.txt
set /p ARCH=<temp_arch.txt
del temp_arch.txt

echo Python Version: %PYTHON_MAJOR%.%PYTHON_MINOR%
echo Architecture: %ARCH%
echo.

REM Check pip
echo [3/6] Checking pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip not found!
    echo Installing pip...
    python -m ensurepip --upgrade
)

echo [OK] pip found
python -m pip --version
echo.

REM Install PyAudio based on Python version
echo [4/6] Installing PyAudio...
echo.

REM Check if Python 3.13+
if %PYTHON_MAJOR% GEQ 3 if %PYTHON_MINOR% GEQ 13 (
    echo Detected Python 3.13+ - Using direct wheel installation
    echo.
    
    REM Determine architecture and set variables
    if /i "%ARCH%"=="AMD64" (
        set "WHEEL_URL=https://github.com/intxcc/pyaudio_portaudio/releases/download/v0.2.14/PyAudio-0.2.14-cp313-cp313-win_amd64.whl"
        set "WHEEL_FILE=PyAudio-0.2.14-cp313-cp313-win_amd64.whl"
    ) else if /i "%ARCH%"=="x86_64" (
        set "WHEEL_URL=https://github.com/intxcc/pyaudio_portaudio/releases/download/v0.2.14/PyAudio-0.2.14-cp313-cp313-win_amd64.whl"
        set "WHEEL_FILE=PyAudio-0.2.14-cp313-cp313-win_amd64.whl"
    ) else if /i "%ARCH%"=="x86" (
        set "WHEEL_URL=https://github.com/intxcc/pyaudio_portaudio/releases/download/v0.2.14/PyAudio-0.2.14-cp313-cp313-win32.whl"
        set "WHEEL_FILE=PyAudio-0.2.14-cp313-cp313-win32.whl"
    ) else if /i "%ARCH%"=="ARM64" (
        echo [ERROR] ARM64 Windows is not supported for PyAudio prebuilt wheels
        echo You may need to build from source
        pause
        exit /b 1
    ) else (
        echo [ERROR] Unknown architecture: %ARCH%
        pause
        exit /b 1
    )
    
    echo Downloading PyAudio wheel...
    echo URL: %WHEEL_URL%
    echo File: %WHEEL_FILE%
    echo.
    
    REM Try to download using PowerShell with proper variable expansion
    powershell -Command "$url='%WHEEL_URL%'; $file='%WHEEL_FILE%'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile $file"
    
    if exist "%WHEEL_FILE%" (
        echo [OK] Download successful
        echo Installing PyAudio...
        pip install "%WHEEL_FILE%"
        del "%WHEEL_FILE%"
    ) else (
        echo [WARNING] Automatic download failed
        echo.
        echo Please download PyAudio manually:
        echo 1. Visit: https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio
        echo 2. Download: %WHEEL_FILE%
        echo 3. Run: pip install %WHEEL_FILE%
        echo.
        echo Continue with other dependencies? (Y/N)
        set /p continue=
        if /i not "%continue%"=="Y" exit /b 1
    )
) else (
    REM Python 3.12 or lower - try pipwin
    echo Using pipwin method for Python %PYTHON_MAJOR%.%PYTHON_MINOR%...
    pip install pipwin
    pipwin install pyaudio
    
    if errorlevel 1 (
        echo.
        echo [WARNING] pipwin method failed
        echo.
        echo Please install PyAudio manually:
        echo 1. Visit: https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio
        echo 2. Download the .whl file for your Python version
        echo 3. Run: pip install downloaded_file.whl
        echo.
        echo Continue with other dependencies? (Y/N)
        set /p continue=
        if /i not "%continue%"=="Y" exit /b 1
    )
)

echo.

REM Install other dependencies
echo [5/6] Installing other dependencies...
echo Installing: ggwave-wheels, cryptography, numpy, colorama, qrcode
echo.
pip install ggwave-wheels cryptography numpy colorama qrcode

if errorlevel 1 (
    echo.
    echo [WARNING] Some dependencies failed to install
    echo Trying individual installations...
    echo.
    pip install ggwave-wheels
    pip install cryptography
    pip install numpy
    pip install colorama
    pip install qrcode
)

echo.

REM Install optional: PyInstaller for creating executables
echo [6/6] Optional: PyInstaller for creating standalone executables
echo.
pip install pyinstaller

echo.
echo =======================================
echo   Verifying Installation
echo =======================================
echo.

python -c "import pyaudio; print('[OK] PyAudio:', pyaudio.__version__)" 2>nul || echo [FAILED] PyAudio
python -c "import ggwave; print('[OK] ggwave')" 2>nul || echo [FAILED] ggwave
python -c "import cryptography; print('[OK] cryptography')" 2>nul || echo [FAILED] cryptography
python -c "import numpy; print('[OK] numpy:', numpy.__version__)" 2>nul || echo [FAILED] numpy
python -c "import colorama; print('[OK] colorama')" 2>nul || echo [FAILED] colorama
python -c "import qrcode; print('[OK] qrcode (optional)')" 2>nul || echo [INFO] qrcode (optional) not installed

echo.
echo =======================================
echo   Installation Complete!
echo =======================================
echo.
echo To start SonarLink v2.0:
echo   python sonarlink2_0.py
echo.
echo To create standalone executable:
echo   pyinstaller --onefile sonarlink2_0.py
echo.
echo For help, see README.md
echo.
pause
