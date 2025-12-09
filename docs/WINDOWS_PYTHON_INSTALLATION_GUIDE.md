# SonarLink v2.0 - Windows Python Installation Guide

Complete step-by-step guide for installing Python on Windows before running SonarLink.

---

## Step-by-Step Instructions

### Step 1: Download Python

1. Go to https://www.python.org/downloads/
2. Click the blue **"Download Python"** button (latest version recommended)
3. Save the installer to your computer (usually in Downloads folder)

**Important:** Download Python 3.8 or higher. SonarLink v2.0 requires Python 3.8+

---

### Step 2: Run the Installer

1. Find the downloaded file (usually in Downloads folder)
2. Double-click to run the installer
3. You'll see a window with installation options

**If prompted by Windows:**
- Click "Yes" to allow the installer to make changes

---

### Step 3: ⚠️ CRITICAL - Add Python to PATH

**This is the MOST IMPORTANT step!**

In the installer window, look for this option:

```
☑ Add Python 3.xx to PATH
```

**This checkbox MUST be CHECKED (☑)**

⚠️ If you skip this, Python won't work from Command Prompt and SonarLink installation will fail!

---

### Step 4: Install pip and Optional Features

Make sure these boxes are CHECKED (☑):

```
Installation Options:
☑ pip (absolutely required for SonarLink)
☑ Documentation (optional but helpful)
☑ tcl/tk and IDLE (optional)
☑ Python test suite (optional)
☑ py launcher (optional)
```

**CRITICAL:** pip MUST be installed - it downloads SonarLink's dependencies

---

### Step 5: Advanced Options

Click "Advanced Options" and ensure these are CHECKED (☑):

```
Advanced Options:
☑ Install for all users (recommended)
☑ Associate files with Python
☑ Create shortcuts for installed applications
☑ Add Python to environment variables (CRITICAL!)
☑ Precompile standard library
```

**Key setting:** "Add Python to environment variables" - This is what makes Python work everywhere

---

### Step 6: Complete Installation

1. Click **"Install Now"** to begin installation
2. Wait for installation to complete (may take 1-2 minutes)
3. You'll see "Setup was successful"
4. Click **"Close"** to finish

---

### Step 7: Verify Python Installation ✅

**Open Command Prompt:**
1. Press `Win + R` (Windows Run dialog)
2. Type `cmd`
3. Press Enter

**In Command Prompt, type:**
```cmd
python --version
```

**You should see:**
```
Python 3.8.x or higher (e.g., Python 3.11.7)
```

✅ **If you see a version number** - Python is installed correctly!  
❌ **If you see "python is not recognized"** - Go back to Step 3 and reinstall (add Python to PATH)

---

### Step 8: Verify pip Installation ✅

Still in Command Prompt, type:
```cmd
pip --version
```

**You should see:**
```
pip 24.x.x from C:\Users\YourUsername\AppData\Local\Programs\Python\Python311\lib\site-packages\pip ...
```

✅ **If you see pip version** - pip is ready for SonarLink!

---

## Common Issues & Solutions

### Issue 1: "python is not recognized"

**Problem:** Command Prompt can't find Python

**Solution:**

1. **Completely uninstall Python:**
   - Open Windows Settings
   - Go to Apps → Apps & Features
   - Find "Python 3.xx" in the list
   - Click it and select "Uninstall"
   - Wait for uninstall to complete

2. **Restart your computer**

3. **Download Python again:**
   - Visit https://www.python.org/downloads/
   - Download the latest version

4. **Run installer CAREFULLY:**
   - ☑ Add Python to PATH (MOST IMPORTANT!)
   - ☑ pip
   - ☑ Add Python to environment variables
   - Click "Install Now"

5. **Restart your computer** (to apply PATH changes)

6. **Open a NEW Command Prompt** and test:
   ```cmd
   python --version
   ```

---

### Issue 2: "pip is not recognized"

**Problem:** pip wasn't installed with Python

**Solution:**

1. Use Python to run pip:
   ```cmd
   python -m pip --version
   ```
   
   If this works, continue with:
   ```cmd
   python -m pip install -r requirements.txt
   ```

2. **If that doesn't work:**
   - Uninstall Python (see Issue 1)
   - Reinstall and ENSURE pip is checked
   - Make sure "Add Python to PATH" is checked

---

### Issue 3: "permission denied" or "access denied"

**Problem:** Windows blocked the installation

**Solution:**

1. **Restart as Administrator:**
   - Right-click Command Prompt
   - Select "Run as Administrator"
   - Click "Yes" if prompted

2. **Try the command again:**
   ```cmd
   python --version
   ```

---

### Issue 4: Python installed but SonarLink installation still fails

**Problem:** Dependencies won't install

**Solution:**

1. **Upgrade pip:**
   ```cmd
   python -m pip install --upgrade pip
   ```

2. **Install from requirements.txt:**
   ```cmd
   python -m pip install -r requirements.txt
   ```

3. **If PyAudio fails specifically:**
   - This is common on Windows
   - Try manual installation:
   ```cmd
   python -m pip install pyaudio
   ```
   
   - If that fails, download wheel from: https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio
   - Then install it:
   ```cmd
   python -m pip install PyAudio-0.2.14-cp311-cp311-win_amd64.whl
   ```
   (Replace filename with your Python version)

---

### Issue 5: "ModuleNotFoundError" when running SonarLink

**Problem:** Missing dependencies

**Solution:**

1. **Install all dependencies:**
   ```cmd
   python -m pip install -r requirements.txt
   ```

2. **Verify each module:**
   ```cmd
   python -c "import pyaudio; print('PyAudio OK')"
   python -c "import ggwave; print('ggwave OK')"
   python -c "import cryptography; print('cryptography OK')"
   python -c "import numpy; print('numpy OK')"
   python -c "import colorama; print('colorama OK')"
   ```

3. **If any fail**, install that specific module:
   ```cmd
   python -m pip install ggwave-wheels
   ```

---

## Visual Checklist for Python Installation

**When you see the Python installer, make sure these are ALL CHECKED (☑):**

```
MAIN SCREEN:
☑ pip (required!)
☑ Add Python 3.xx to PATH (CRITICAL!)
☑ Associate files with Python
☑ Create shortcuts for installed applications

ADVANCED OPTIONS:
☑ Install for all users
☑ Add Python to environment variables (CRITICAL!)
☑ Create shortcuts for installed applications
```

**If ANY of the CRITICAL items are unchecked, uninstall and try again!**

---

## What Each Option Does

| Option | Purpose | Required for SonarLink? |
|--------|---------|------------------------|
| **Add Python to PATH** | Lets Command Prompt find Python | 🔴 **YES - CRITICAL** |
| **pip** | Installs packages (dependencies) | 🔴 **YES - CRITICAL** |
| **Add to environment variables** | Makes Python available everywhere | 🔴 **YES - CRITICAL** |
| Documentation | Python reference manuals | 🟡 Optional |
| tcl/tk and IDLE | Development IDE | 🟡 Optional |
| py launcher | Quick Python shortcut | 🟡 Optional |
| Test suite | Development testing tools | 🟡 Optional |

---

## Quick Path to SonarLink Success

### 1️⃣ Install Python Correctly (10 minutes)
```cmd
python --version
pip --version
```
Both should show version numbers ✅

### 2️⃣ Download SonarLink (2 minutes)
- `install_windows.bat` (installer)
- `sonarlink2_0.py` (application)
- `requirements.txt` (dependencies)

### 3️⃣ Run SonarLink Installer (5 minutes)
```cmd
install_windows.bat
```

### 4️⃣ Launch SonarLink (30 seconds)
```cmd
python sonarlink2_0.py
```

**Total time: ~20 minutes to fully working SonarLink** ⏱️

---

## After Python Installation - Next Steps

Once Python verification shows ✅ for both `python --version` and `pip --version`:

1. **Download SonarLink files:**
   - `install_windows.bat` (installer script)
   - `sonarlink2_0.py` (main application)
   - `requirements.txt` (dependency list)

2. **Put all three files in the SAME folder**

3. **Run the installer:**
   ```cmd
   install_windows.bat
   ```
   The script will:
   - ✅ Check Python version
   - ✅ Install PyAudio (tricky on Windows, but handled)
   - ✅ Install ggwave-wheels, cryptography, numpy
   - ✅ Install colorama, qrcode (UI and donations)
   - ✅ Verify all installations

4. **Launch SonarLink:**
   ```cmd
   python sonarlink2_0.py
   ```

5. **You'll see the SonarLink menu:**
   ```
   🔊 SonarLink v2.0 - Audio-Based File Transfer 🔊
   
   [1] 💬 Open Chat
   [2] 📁 Send file
   [3] 🎧 Receive messages or files
   [4] 🔓 Decrypt received file
   [5] 📊 View Audit Log
   [6] ℹ️ Credits
   [7] ❌ Exit
   ```

✅ **You're ready to use SonarLink!**

---

## What SonarLink Needs (Requirements)

### Minimum Requirements
- Python 3.8 or higher
- 100 MB free disk space
- Microphone + speakers
- Windows 7 or higher

### What Gets Installed
```
After install_windows.bat runs, you'll have:

ggwave-wheels==0.4.2.5       (audio encoding)
numpy==2.3.5                 (numerical computing)
cryptography==46.0.3         (AES-256, RSA encryption)
colorama==0.4.6              (terminal colors)
qrcode==8.2                  (Lightning donations)
PyAudio==0.2.14              (microphone/speaker access)
```

All automatically downloaded and installed by pip!

---

## Troubleshooting Checklist

If SonarLink doesn't work, check this order:

- [ ] Python version 3.8+ installed? → `python --version`
- [ ] pip working? → `pip --version`
- [ ] Python added to PATH? → Reinstall if not
- [ ] Downloaded all 3 files? → check folder contents
- [ ] Ran install_windows.bat? → re-run if needed
- [ ] All dependencies installed? → check installation output
- [ ] Microphone plugged in and enabled? → test in Windows Sound settings
- [ ] Running latest SonarLink? → download fresh copy from GitHub

---

## Alternative: Manual Installation (If Installer Fails)

If `install_windows.bat` fails, you can install manually:

```cmd
REM Open Command Prompt in the SonarLink folder and run:

REM Upgrade pip first
python -m pip install --upgrade pip

REM Install dependencies one by one
python -m pip install ggwave-wheels
python -m pip install numpy
python -m pip install cryptography
python -m pip install colorama
python -m pip install qrcode[pil]
python -m pip install pyaudio

REM Then launch SonarLink
python sonarlink2_0.py
```

---

## Key Takeaways

### 🔴 Most Common Problem
**"Add Python to PATH" checkbox not checked during installation**

This prevents everything else from working!

**Solution:** Uninstall Python, reinstall with that box CHECKED ☑

### 🟡 Second Most Common
**pip not installed**

Check the "pip" checkbox during Python installation!

### 🟢 Most Common Solution
Restart your computer after Python installation. Windows needs to reload the PATH.

---

## Still Having Issues?

### If Python won't install:
- Try official Python website: https://www.python.org/downloads/
- Make sure you have administrator privileges
- Windows Defender may block installation (allow it)

### If pip won't work:
- Make sure you're in Command Prompt, not PowerShell
- Try: `python -m pip --version`
- Upgrade pip: `python -m pip install --upgrade pip`

### If SonarLink won't run:
- All dependencies installed? Check requirements.txt
- Microphone working? Test in Windows Sound settings
- Latest version? Download fresh from GitHub

### For more help:
- **Installation Guide:** See `INSTALL.md`
- **Quick Start:** See `QUICKSTART.md`
- **GitHub Issues:** https://github.com/marianopeluso/sonarlink

---

## Command Reference

Quick command reference for Command Prompt:

```cmd
# Check Python version
python --version

# Check pip version
pip --version

# Install SonarLink dependencies
python -m pip install -r requirements.txt

# Install specific package
python -m pip install ggwave-wheels

# Upgrade pip
python -m pip install --upgrade pip

# Check if module installed
python -c "import ggwave; print('OK')"

# Launch SonarLink
python sonarlink2_0.py
```

---

## Glossary

| Term | Meaning |
|------|---------|
| **PATH** | List of folders Windows searches for programs |
| **pip** | Package Installer for Python (downloads dependencies) |
| **Command Prompt** | Windows terminal for typing commands |
| **Module** | Python code library/package |
| **Requirements.txt** | File listing all dependencies |
| **Virtual Environment** | Isolated Python installation (optional) |

---

## Next: Run SonarLink! 🚀

Once Python is verified and SonarLink is installed:

```cmd
python sonarlink2_0.py
```

Then choose from the menu:
- 💬 Open Chat - Send messages via audio
- 📁 Send file - Encrypted file transfer
- 🎧 Receive - Listen for messages/files
- 🔓 Decrypt - Unlock received files
- 📊 Audit Log - See operation history
- ℹ️ Credits - About SonarLink
- ❌ Exit - Close application

**Enjoy secure audio-based communication!** 🔊🔐

---

**SonarLink v2.0 - Secure Audio-Based File Transfer**  
**Windows Python Installation Guide**  
*Last Updated: December 2025*  
*License: Open Source*
