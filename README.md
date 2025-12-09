# 🔊 SonarLink v2.0

**SonarLink - Secure audio-based file transfer and encrypted messaging, powered by sound**

Transfer files and messages between computers using sound waves. No network required!

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/marianopeluso/SonarLink)

---

## 📋 Table of Contents

- [Breaking Changes Notice](#-breaking-changes-v10--v20)
- [What Makes SonarLink Unique](#-what-makes-sonarlink-unique)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
- [Use Cases](#-use-cases)
- [Technical Details](#-technical-details)
- [Security](#-security)
- [What's New in v2.0](#-whats-new-in-v20)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚠️ Breaking Changes: v1.0 → v2.0

**SonarLink v2.0 is NOT backward compatible with v1.0.** This is a major security and architecture upgrade.

### Why v2.0 is Not Compatible with v1.0

**File Format Incompatibility:**
- v1.0 encrypted files use old format (MAC + IV + ciphertext)
- v2.0 uses **FSS1 format** (File Secure Suite v1) with structured metadata
- v1.0 files cannot be decrypted by v2.0 (different format, different encryption mode)
- **Action required:** If you have v1.0 encrypted files, decrypt them with v1.0 before upgrading

**Encryption Algorithm Changes:**
- **AES Mode Change:** v1.0 used CFB mode with separate HMAC → v2.0 uses **GCM mode** (integrated authentication)
- **RSA Key Size:** v1.0 used 2048-bit → v2.0 requires **4096-bit** keys
- **Key Derivation:** v1.0 used simple password padding → v2.0 uses **PBKDF2 with 600,000 iterations**
- These changes make v2.0 files incompatible with v1.0 decryption tools

**Command Change:**
- v1.0: `python sonarlink.py`
- v2.0: `python sonarlink2_0.py` (different filename to prevent conflicts)

### Why This Breaking Change Was Necessary

**Security Hardening:**
1. **GCM vs CFB**: GCM provides authenticated encryption in a single step, preventing tampering automatically. v1.0's CFB + HMAC required manual verification.
2. **PBKDF2 Key Derivation**: 600,000 iterations (~100ms per password) makes brute-force attacks computationally expensive. v1.0's simple padding was vulnerable to fast password cracking.
3. **4096-bit RSA**: Future-resistant against emerging cryptanalytic techniques. v1.0's 2048-bit keys face increasing risk as computing power grows.
4. **FSS1 Format**: Prevents format confusion attacks by including magic bytes, version field, and hash verification. v1.0's generic format had no such protections.

**Usability Improvements:**
1. **Open Chat + Private Chat**: v1.0 had generic messaging. v2.0 separates unencrypted (instant) from encrypted (token-based) modes for clarity and speed.
2. **Audit Logging**: v2.0 tracks all operations with timestamps, encryption methods, and status. v1.0 had no logging.
3. **Realistic File Limits**: v2.0 honestly documents 10 KB practical limit. v1.0 claimed 10 MB support (unrealistic - transfers would take hours).
4. **Better Error Messages**: v2.0 provides detailed guidance on password strength, file validity, and operation status.

**Cryptographic Standards:**
- NIST recommends GCM over CFB for authenticated encryption
- PBKDF2 with high iteration counts is the standard for password-based key derivation
- 4096-bit RSA provides 128-bit symmetric equivalent security level

### Migration Path

If you're upgrading from v1.0:

1. **Decrypt all v1.0 encrypted files using v1.0** before upgrading
2. **Keep v1.0 installed** until migration is complete (don't delete `sonarlink.py`)
3. **Install v2.0** alongside v1.0 (different filename: `sonarlink2_0.py`)
4. **Re-encrypt files with v2.0** if needed for long-term storage
5. **Delete v1.0** only after confirming all files are migrated

### Benefits of Upgrading Despite Breaking Changes

- ✅ **Stronger Encryption**: GCM mode + 4096-bit RSA = production-grade security
- ✅ **Brute-Force Resistance**: PBKDF2 600K iterations makes password attacks impractical
- ✅ **Two Chat Modes**: Separate encrypted (token) and unencrypted messaging for flexibility
- ✅ **Audit Trail**: Complete operation logging for compliance and debugging
- ✅ **Format Protection**: FSS1 format prevents confusion and corruption attacks
- ✅ **Realistic Expectations**: Honest about capabilities, no overpromising
- ✅ **Production Ready**: Extensive testing and security hardening

---

## 🌟 What Makes SonarLink Unique

**SonarLink v2.0 is a production-ready system for secure encrypted messaging and file transfer purely through sound waves, with no network connection required.**

### Why SonarLink v2.0

- **True Air-Gapped Transfer**: No network, no WiFi, no Bluetooth - just sound waves
- **Encrypted Communication**: AES-256-GCM and RSA-4096 options with PBKDF2 key derivation
- **Two Chat Modes**: Open chat (instant, unencrypted) + Private chat (token-based, encrypted)
- **Realistic Limits**: Honest about capabilities (10 KB practical limit, not overpromised)
- **Complete Solution**: Compression, encryption, integrity verification, and audio transfer in one tool
- **Cross-Platform**: Works on Windows, Linux (all distros), and macOS (Intel + Apple Silicon)
- **Secure Defaults**: FSS1 format, PBKDF2 key derivation, GCM authentication, audit logging
- **Open Source**: Built on trusted libraries with transparent, auditable code

---

## ✨ Features

### Core Capabilities

#### 💬 Open Chat (NEW)
- Real-time unencrypted messaging
- Fast transmission (2-5 seconds per message)
- No password needed
- Perfect for non-sensitive communication

#### 🔒 Private Chat (NEW)
- AES-256-GCM encryption + GZIP compression
- Ephemeral 8-digit session tokens
- Faster transmission (1-3 seconds due to GZIP)
- Optimized for audio bandwidth
- No token storage after session ends

#### 📁 File Transfer
- Encrypted file transfer up to 10 KB
- **AES-256-GCM encryption** with PBKDF2 key derivation
- **RSA-4096 encryption** for maximum security
- **FSS1 format** with file integrity verification (SHA-256)
- Automatic GZIP compression for smaller files

#### 📊 Audit Log (NEW)
- Complete operation tracking
- Metadata-only logging (privacy-preserving)
- Timestamps, operation type, encryption method, status
- File-based log: `audiologs/sonarlink_audit.log`

#### 🔐 Security Features
- **AES-256-GCM**: Authenticated encryption with associated data
- **RSA-4096**: Strong asymmetric encryption
- **PBKDF2**: 600,000 iterations for password-based key derivation
- **SHA-256**: File integrity verification
- **FSS1 Format**: Structured encryption format prevents confusion attacks

### File Size Support

**Practical limits based on realistic transmission times:**

| File Size | Transfer Time | Recommended |
|-----------|---------------|-------------|
| **1-5 KB** | < 1 minute | ✅ Excellent |
| **5-10 KB** | 1-2 minutes | ✅ Good |
| **10+ KB** | 2+ minutes | ⚠️ Works but slower |
| **100+ KB** | 10+ minutes | 🔴 Impractical |

**Why 10 KB limit?** Unlike v1.0's unrealistic 10 MB claim (would take hours!), SonarLink v2.0 is honest about practical limits. 10 KB files transfer in ~2 minutes - a reasonable trade-off.

### Technical Innovation
- **Dual Optimization Paths**: Chat and file transfer have separate optimization
- **Intelligent Compression**: GZIP for chat (50-60% reduction), FSS1 for files
- **Chunking Protocol**: Intelligent 120-byte chunks for reliable transmission
- **Multi-Layer Encoding**: GZIP → Encryption → Audio encoding
- **Format Preservation**: Original files fully recovered with integrity verified
- **Error Recovery**: Detailed error messages for debugging
- **Adaptive Delays**: Configurable timing between chunks

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Working microphone and speakers
- 100 MB free disk space

### Installation (Choose Your Platform)

**Windows:**
```cmd
installers\install_windows.bat
```

**Linux:**
```bash
bash installers/install_linux.sh
```

**macOS:**
```bash
bash installers/install_macos.sh
```

### First Transfer

```bash
# 1. Run SonarLink
python sonarlink2_0.py

# 2. Choose from main menu:
#    [1] 💬 Open Chat           (unencrypted)
#    [2] 📁 Send file           (encrypted)
#    [3] 🎧 Receive             (listen for messages/files)
#    [4] 🔓 Decrypt file        (decrypt received files)
#    [5] 📊 View Audit Log      (see operation history)
#    [6] ℹ️ Credits             (about + donations)
#    [7] ❌ Exit

# 3. Follow the prompts!
```

**Pro Tip**: Start with [1] Open Chat to test your audio setup before using encryption.

---

## 💻 Installation

### System Requirements

**Minimum:**
- Python 3.8+
- 256 MB RAM
- 100 MB disk space
- Working microphone and speakers

**Recommended:**
- Python 3.10+
- 2 GB RAM
- Modern OS (Windows 10+, Ubuntu 20.04+, macOS 10.15+)
- Quality audio devices
- Quiet environment for file transfers

### Supported Platforms

- ✅ **Windows** 10/11 (64-bit and 32-bit)
- ✅ **Linux** x86_64 (Ubuntu, Debian, Arch, Fedora, openSUSE, Mint)
- ✅ **Linux ARM** (Raspberry Pi 4/5 64-bit, Raspberry Pi 3/Zero 32-bit)
- ✅ **macOS Intel** (10.15+)
- ✅ **macOS Apple Silicon** (M1/M2/M3/M4 native)

### Platform-Specific Guides

For detailed installation instructions:

- **[docs/QUICKSTART.md](docs/QUICKSTART.md)** - Get running in 5 minutes
- **[docs/INSTALLATION_INSTRUCTION.md](docs/INSTALLATION_INSTRUCTION.md)** - Complete installation for all platforms
- **[docs/WINDOWS_PYTHON_INSTALLATION_GUIDE.md](docs/WINDOWS_PYTHON_INSTALLATION_GUIDE.md)** - Windows Python setup
- **[CHANGELOG.md](CHANGELOG.md)** - What's new in v2.0 (with code-verified changes)

### Manual Installation

If automated installers don't work:

```bash
# Install dependencies
pip install -r requirements.txt

# Run SonarLink
python sonarlink2_0.py
```

---

## 📖 Usage Guide

### Main Menu

```
🔊 SonarLink v2.0 - Audio-Based File Transfer 🔊
═══════════════════════════════════════════════════

[1] 💬 Open Chat          ← Send unencrypted messages
[2] 📁 Send file          ← Send encrypted files (up to 10 KB)
[3] 🎧 Receive            ← Listen for messages/files
[4] 🔓 Decrypt file       ← Decrypt received encrypted files
[5] 📊 View Audit Log     ← See operation history
[6] ℹ️ Credits            ← About & Lightning donations
[7] ❌ Exit               ← Close application
```

### Task: Send Open Chat Message

```
[1] 💬 Open Chat
→ Type your message
→ Message transmits via audio (2-5 seconds)
→ Recipient receives instantly
```

**Best for:** Non-sensitive communication, testing setup, quick messaging

### Task: Send Private Chat Message

```
[1] 💬 Open Chat
→ Select "Private Chat"
→ System generates 8-digit token (e.g., 12345678)
→ Share token with recipient (verbally or separate channel)
→ Type encrypted message
→ Recipient enters token and receives decrypted message
```

**Best for:** Sensitive messages that need encryption but quick setup

### Task: Send Encrypted File

**Receiver prepares first:**
```
[3] 🎧 Receive
→ File option → Choose decryption method (AES or RSA)
→ Enter password (for AES) or just confirm (for RSA)
→ Ready to receive
```

**Sender:**
```
[2] 📁 Send file
→ Choose encryption: AES-256-GCM (fast) or RSA-4096 (secure)
→ Enter password (for AES)
→ Select file (drag & drop or type path)
→ File transmits via audio
```

**Receiver extracts:**
```
[4] 🔓 Decrypt file
→ Select encrypted file from audio_received/
→ Enter password
→ File extracted and decrypted
```

### Best Practices

**For Reliable Transmission:**
- Keep devices 1-2 meters apart
- Use quiet environment (< 40 dB background noise)
- Set speaker volume to 80-100%
- Test with text messages first
- Close unnecessary applications

**For Secure File Transfer:**
- Use strong passwords (16+ characters with mixed case/digits/symbols)
- Use RSA-4096 for maximum security
- Verify file checksums if possible
- Delete plaintext files after encryption
- Use air-gapped systems for sensitive data

**Performance Tips:**
- Private Chat is faster than Open Chat (GZIP compression)
- AES-256-GCM is faster than RSA-4096
- Keep files under 10 KB for practical transfer times
- Compress files before sending if they're text
- Pre-compress audio files (already compressed, won't shrink further)

---

## 🎯 Use Cases

### 1. Air-Gapped Systems
Transfer sensitive files between isolated computers with zero network exposure - perfect for high-security environments.

### 2. Covert Communication
Audio transmission provides plausible deniability - appears as normal audio file, no visible QR codes or network traces.

### 3. Emergency Data Transfer
Backup method when network infrastructure is down but devices still function.

### 4. Privacy-Conscious Users
No data passes through cloud services or networks - complete offline operation.

### 5. SSH/GPG Key Exchange
Securely transfer cryptographic keys without network exposure.

### 6. Password Backup
Store encrypted passwords on offline devices without cloud services.

### 7. Business Intelligence
Secure exchange of confidential data at conferences without network traces.

### 8. Embedded Systems & IoT
Simple speaker/microphone setup, no complex network stack needed.

---

## 🔧 Technical Details

### Audio Specifications

| Parameter | Value |
|-----------|-------|
| Sample Rate | 48000 Hz |
| Chunk Size | 4096 samples |
| Volume | 80 (0-100 scale) |
| Protocol | GGWAVE_AUDIBLE_FAST (Protocol ID = 1) |
| Max Bytes/Chunk | 120 bytes |

### Encryption Specifications

#### AES-256-GCM (v2.0)
- **Cipher**: AES with GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (derived via PBKDF2)
- **IV Size**: 12 bytes (random, 2^96 combinations)
- **Authentication Tag**: 16 bytes (prevents tampering)
- **Key Derivation**: PBKDF2-SHA256 with 600,000 iterations
- **Format**: FSS1 (File Secure Suite v1)

#### RSA-4096 (v2.0)
- **Key Size**: 4096 bits (maximum practical security)
- **Padding**: OAEP with MGF1-SHA256
- **Hybrid Encryption**: RSA encrypts AES key, AES encrypts data
- **Generation Time**: 5-10 seconds (slow but one-time)

#### File Integrity
- **Hash Algorithm**: SHA-256
- **Verification**: Computed after decryption
- **Purpose**: Detect corruption or tampering

### Performance (Text Files with GZIP Compression)

| File Size | Compression | Approx Time | Chunks |
|-----------|-------------|-------------|--------|
| 1 KB | 30-50% | ~16 seconds | ~8 |
| 5 KB | 40-60% | ~1 minute | ~40 |
| 10 KB | 50-70% | ~2 minutes | ~80 |
| 20 KB | 50-70% | ~4 minutes | ~160 |
| 50 KB | 50-70% | ~10 minutes | ~400 |

**Note:** Already compressed files (JPG, MP3, ZIP, etc.) won't compress further.

### Data Processing Pipeline

```
Original File / Message
    ↓
GZIP Compression (optimization for audio)
    ↓
Encryption (AES-256-GCM or RSA-4096)
    ↓
Base64 Encoding (if needed)
    ↓
120-byte Chunks
    ↓
Audio Transmission (ggwave at 48 kHz)
    ↓
Reception & Buffering
    ↓
Base64 Decoding
    ↓
Reassembly
    ↓
Decryption (automatic verification)
    ↓
GZIP Decompression
    ↓
Original File / Message Restored
    ↓
Integrity Verification (SHA-256 hash check)
```

---

## 🔒 Security

### Security Features (v2.0)

- **AES-256-GCM**: Government-grade symmetric encryption
- **RSA-4096**: Strong asymmetric encryption (future-resistant)
- **PBKDF2**: Password-based key derivation with 600,000 iterations
- **SHA-256**: Cryptographic hash for integrity verification
- **FSS1 Format**: Structured format prevents confusion attacks
- **Ephemeral Tokens**: Session-based, not stored or reused
- **No Network Exposure**: Completely offline operation
- **Audit Log**: Operation tracking without logging sensitive data

### Best Practices

1. **Use Strong Passwords**
   - Minimum 16 characters
   - Mix of uppercase, lowercase, digits, special characters
   - Generate with password manager
   - Never reuse across services

2. **Share Passwords Securely**
   - Never via audio transmission
   - Use separate secure channel (phone call, encrypted message)
   - Private Chat tokens: Share verbally or out-of-band

3. **File Transfer Security**
   - Use RSA-4096 for maximum security
   - Use AES-256-GCM for speed + good security trade-off
   - Verify checksums when possible
   - Delete plaintext files after encryption

4. **Operational Security**
   - Use in private spaces
   - Minimize background noise
   - Verify recipient identity before sending
   - Check audit log after critical transfers
   - Use air-gapped systems for maximum security

5. **Audit Log Review**
   - Check operation history regularly
   - Detect unauthorized transfer attempts
   - Archive logs to separate secure storage
   - Rotate logs weekly

### Privacy Considerations

- ✅ **No network traces** - Completely offline
- ✅ **No cloud storage** - Files never leave your device
- ✅ **No metadata leakage** - Audit log records metadata only
- ⚠️ **Audio can be recorded** - Use in private spaces for sensitive transfers
- ⚠️ **Physical security needed** - Protect the environment where transfers occur

For detailed security analysis, see [docs/SECURITY_DOC.md](docs/SECURITY_DOC.md)

---

## 🎯 What's New in v2.0

### Major Changes
- **AES Mode**: CFB → **GCM** (authenticated encryption)
- **RSA Size**: 2048-bit → **4096-bit** (stronger keys)
- **Key Derivation**: Password padding → **PBKDF2 600K iterations** (brute-force resistant)
- **File Format**: Generic → **FSS1 format** (structured, secure)
- **File Limit**: 10 MB → **10 KB** (realistic and documented)

### New Features
- **Open Chat**: Unencrypted fast messaging
- **Private Chat**: Token-based encrypted messaging
- **Audit Logging**: Complete operation tracking
- **Better UI**: Colorama for color-coded output
- **Lightning Donations**: Support open-source development

### Security Improvements
- Stronger encryption (GCM vs CFB)
- More iterations for password hashing
- Larger RSA keys (future-resistant)
- File integrity verification
- Password strength validation
- Format prevents confusion attacks

### Full Details
See [CHANGELOG.md](CHANGELOG.md) for complete code-verified list of changes.

---

## 📚 Documentation

### Quick References
- **[docs/QUICKSTART.md](docs/QUICKSTART.md)** - 5-minute getting started
- **[CHANGELOG.md](CHANGELOG.md)** - What's new in v2.0 (code-verified)

### Installation & Setup
- **[docs/INSTALLATION_INSTRUCTION.md](docs/INSTALLATION_INSTRUCTION.md)** - Complete installation guide
- **[docs/WINDOWS_PYTHON_INSTALLATION_GUIDE.md](docs/WINDOWS_PYTHON_INSTALLATION_GUIDE.md)** - Windows Python setup

### Deep Dives
- **[SECURITY.md](SECURITY.md)** - Security policy, threat model, GPG signing

### Interactive Help
```bash
# Launch SonarLink and explore
python sonarlink2_0.py
```

---

## 🤝 Contributing

SonarLink is inspired by community needs and welcomes contributions!

### How to Contribute

1. **Report Issues**: Found a bug? Open an issue on GitHub
2. **Suggest Features**: Have an idea? Create a discussion
3. **Submit PRs**: Code contributions welcome with tests
4. **Improve Docs**: Help make documentation better
5. **Share Use Cases**: Tell us how you're using SonarLink

---

## 🙏 Credits

### Built With

- **[ggwave](https://github.com/ggerganov/ggwave)** by Georgi Gerganov - Core audio-over-sound library
- **[PyAudio](https://people.csail.mit.edu/hubert/pyaudio/)** - Python audio I/O
- **[cryptography](https://cryptography.io/)** by PyCA - Cryptographic primitives
- **[NumPy](https://numpy.org/)** - Numerical computing
- **[colorama](https://github.com/tartley/colorama)** - Terminal colors
- **[qrcode](https://github.com/lincolnloop/python-qrcode)** - QR code generation

### Inspiration

- ggwave Issue #41 (2021) - Community request for pure audio file transfer
- Air-gapped system requirements
- Privacy-conscious users seeking offline solutions
- Business need for secure data exchange without networks

**Standing on the shoulders of giants** - SonarLink takes ggwave's raw audio-over-sound capability and builds a complete, production-ready, security-hardened solution.

---

## 📄 License

SonarLink is released under the MIT License. See [LICENSE](LICENSE) file for details.

### Dependencies Licenses
- ggwave: MIT License
- PyAudio: MIT License
- cryptography: Apache 2.0 / BSD License
- NumPy: BSD License
- colorama: BSD License
- qrcode: BSD License

---

## ⚠️ Known Limitations

1. **Speed**: Slower than network transfer (limitation of physics, not implementation)
2. **Distance**: Limited to ~3 meters maximum reliable range
3. **Environment**: Requires quiet environment (< 40 dB noise) for reliable transmission
4. **File Size**: Practical limit 10 KB (larger files work but very slow)
5. **Reliability**: Affected by background noise and audio device quality
6. **Hardware**: Dependent on microphone/speaker quality
7. **Sequential**: One file/message at a time (inherent to audio protocol)

These are features, not bugs - they're the price of offline, network-free operation!

---

## 🌟 Key Advantages of v2.0

1. ✅ **No Network Required** - Works completely offline
2. ✅ **Air-Gap Compatible** - Transfer to isolated systems
3. ✅ **Strong Encryption** - AES-256-GCM and RSA-4096 options
4. ✅ **Honest Limits** - No overpromising, realistic 10 KB practical limit
5. ✅ **Cross-Platform** - Windows, Linux, macOS with native installers
6. ✅ **Well-Documented** - Comprehensive guides with real examples
7. ✅ **Easy Installation** - Automated scripts handling platform differences
8. ✅ **Open Source** - Transparent code, trusted libraries, community-driven
9. ✅ **Privacy-Focused** - No cloud, no networks, audit log only
10. ✅ **Plausible Deniability** - Audio files appear innocent vs QR codes

---

## 📊 Version Summary

| Aspect | v1.0 | v2.0 |
|--------|------|------|
| Release Date | October 2025 | December 2025 |
| Python Support | 3.8+ | 3.8+ |
| AES Encryption | CFB + HMAC | GCM (authenticated) |
| RSA Key Size | 2048-bit | 4096-bit |
| Key Derivation | Password padding | PBKDF2 600K iterations |
| Max File Size | 10 MB | 10 KB (honest) |
| Chat Modes | Single | Open + Private |
| Audit Log | None | Complete |
| UI Colors | Basic | Enhanced (colorama) |
| File Format | Generic | FSS1 structured |
| Donations | None | Lightning Network |

---

## 🚀 Getting Started

Ready to transfer securely via sound waves?

1. **Choose your platform** and run the appropriate installer
2. **Read [docs/QUICKSTART.md](docs/QUICKSTART.md)** (5 minutes)
3. **Test with Open Chat** (no encryption, fastest)
4. **Try Private Chat** (with token encryption)
5. **Send a small test file** (< 5 KB recommended)
6. **Explore RSA-4096** (maximum security option)

---

**SonarLink v2.0 - Transform Your Files Into Sound Waves!** 🔊📁→🎵

*Built with ❤️ using [ggwave](https://github.com/ggerganov/ggwave) and hardened with production-ready security for real-world use.*

---

For detailed technical information, see the comprehensive documentation in the `docs/` folder.
