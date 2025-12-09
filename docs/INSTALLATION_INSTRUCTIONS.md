# SonarLink v2.0 - Installation Guide

SonarLink v2.0 requires Python 3.8+ and several system dependencies. This guide covers installation for Windows, Linux, and macOS.

## Quick Start

### Windows
```
install_windows.bat
```

### Linux
```
bash install_linux.sh
```

### macOS
```
bash install_macos.sh
```

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.8+ |
| RAM | 256 MB minimum |
| Storage | ~50 MB for dependencies |
| Audio | Working microphone + speakers |

---

## Detailed Installation

### Windows

1. **Prerequisites**
   - Python 3.8+ installed and added to PATH
   - Administrator privileges recommended (not required)

2. **Installation**
   ```
   install_windows.bat
   ```
   The script will:
   - ✅ Check Python version
   - ✅ Detect architecture (AMD64/x86)
   - ✅ Install PyAudio (handles Python 3.13+ separately)
   - ✅ Install ggwave, cryptography, numpy, colorama, qrcode
   - ✅ Verify installation

3. **Run SonarLink**
   ```
   python sonarlink2_0.py
   ```

4. **Create Standalone Executable** (optional)
   ```
   pip install pyinstaller
   pyinstaller --onefile sonarlink2_0.py
   ```

**Known Issues:**
- PyAudio is tricky on Windows. If installation fails, download the wheel manually from [Christoph Gohlke's library](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio)

---

### Linux

1. **Prerequisites**
   - Python 3.8+ (usually pre-installed)
   - sudo access for system package installation

2. **Installation**
   ```bash
   bash install_linux.sh
   ```
   The script will:
   - ✅ Detect Linux distribution (Debian, Fedora, Arch, etc.)
   - ✅ Install system packages (portaudio-dev, build tools)
   - ✅ Install or verify PyAudio
   - ✅ Install Python dependencies
   - ✅ Verify installation

3. **Run SonarLink**
   ```bash
   python3 sonarlink2_0.py
   ```

4. **Raspberry Pi / ARM Support**
   - ✅ ARM64 (Raspberry Pi 4/5, 64-bit systems)
   - ✅ ARM32 (Raspberry Pi 3/Zero with compilation)
   - Installation is automatic; may take longer on ARM32

**Troubleshooting:**
```bash
# If PyAudio fails to install
# Ubuntu/Debian
sudo apt-get install python3-pyaudio

# Arch
sudo pacman -S python-pyaudio

# Manual installation
pip3 install --user pyaudio
```

**Audio Warnings:**
The script suppresses ALSA warnings (they're harmless). If you see them during normal operation, it's fine.

---

### macOS

1. **Prerequisites**
   - Homebrew installed ([brew.sh](https://brew.sh))
   - Python 3.8+ (can be installed via Homebrew)
   - Microphone + speaker permissions

2. **Installation**
   ```bash
   bash install_macos.sh
   ```
   The script will:
   - ✅ Detect Mac architecture (Intel/Apple Silicon)
   - ✅ Install Homebrew (if missing)
   - ✅ Install PortAudio via Homebrew
   - ✅ Install Python dependencies
   - ✅ Verify installation

3. **Run SonarLink**
   ```bash
   python3 sonarlink2_0.py
   ```

4. **Apple Silicon (M1/M2/M3/M4)**
   - All packages install natively (no Rosetta 2)
   - Performance is excellent

5. **Grant Microphone Permissions**
   ```
   System Settings → Privacy & Security → Microphone → Add Terminal
   ```

---

## Manual Installation (All Platforms)

If the installation scripts fail, you can install manually:

```bash
# Python dependencies
pip install -r requirements.txt

# Which includes:
# - ggwave-wheels==0.4.2.5
# - numpy==2.3.5
# - cryptography==46.0.3
# - colorama==0.4.6
# - qrcode==8.2
# - pyaudio==0.2.14 (may need special handling)
```

**PyAudio Special Cases:**

Windows (Python 3.13+):
```batch
pip install https://github.com/intxcc/pyaudio_portaudio/releases/download/v0.2.14/PyAudio-0.2.14-cp313-cp313-win_amd64.whl
```

Linux (if pip fails):
```bash
# Ubuntu/Debian
sudo apt-get install python3-pyaudio

# Fedora
sudo dnf install portaudio-devel python3-devel
pip3 install pyaudio

# Arch
sudo pacman -S python-pyaudio
```

macOS (if pip fails):
```bash
brew reinstall portaudio
pip3 install --user pyaudio
```

---

## Verifying Installation

Test each dependency:

```python
python -c "import pyaudio; print('PyAudio OK')"
python -c "import ggwave; print('ggwave OK')"
python -c "import cryptography; print('cryptography OK')"
python -c "import numpy; print('numpy OK')"
python -c "import colorama; print('colorama OK')"
python -c "import qrcode; print('qrcode OK (optional)')"
```

All should print `[...] OK` except qrcode which is optional.

---

## Creating Standalone Executable

SonarLink can be compiled into a single executable for easier distribution:

```bash
pip install pyinstaller

# Windows
pyinstaller --onefile sonarlink2_0.py

# Linux/macOS
pyinstaller --onefile sonarlink2_0.py
```

Output will be in `dist/sonarlink2_0.exe` (Windows) or `dist/sonarlink2_0` (Unix).

---

## Troubleshooting

### PyAudio Issues
**Error:** `ModuleNotFoundError: No module named 'pyaudio'`

**Solution:**
- Windows: Download wheel from [Christoph Gohlke](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio)
- Linux: `sudo apt-get install python3-pyaudio` or `sudo pacman -S python-pyaudio`
- macOS: `brew reinstall portaudio && pip3 install --user pyaudio`

### Audio Permission Issues (macOS)
**Error:** `RuntimeError: [Errno -1] Unanticipated host error`

**Solution:** Grant microphone access in System Settings

### ALSA Warnings (Linux)
**Warning:** `ALSA lib confmisc.c ... Cannot connect to server`

**Solution:** Harmless and suppressed by default. Safe to ignore.

### Low Audio Levels
If reception is weak:
- Increase system volume to maximum
- Move devices closer (within 1-2 meters)
- Reduce background noise
- Check microphone/speaker functionality

---

## Next Steps

After installation:
1. Run `python3 sonarlink2_0.py`
2. Choose an operation from the menu
3. See README.md for feature details

**Questions?** Check the [GitHub repository](https://github.com/marianopeluso/sonarlink)
