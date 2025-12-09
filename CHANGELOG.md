# SonarLink - Changelog

All notable changes to SonarLink are documented here.

## [2.0] - December 2025

### Breaking Changes
- **File size limit**: Reduced from 10 MB to 10 KB (v1.0's 10 MB was unrealistic - files took hours to transfer)
- **Encryption algorithms**: AES cipher changed from CFB to GCM mode
- **RSA key size**: Increased from 2048-bit to 4096-bit

### Security Improvements

#### Cryptography Upgrades
- **AES Mode Change**: CFB mode → **GCM mode** (AEAD - Authenticated Encryption with Associated Data)
  - v1.0: AES-256-CFB + separate HMAC-SHA256 (two-step authentication)
  - v2.0: AES-256-GCM (integrated authentication tag, prevents tampering automatically)
  - Benefit: More secure, single-step authentication

- **RSA Key Size**: 2048-bit → **4096-bit**
  - Provides stronger protection against future attacks
  - More resistant to emerging cryptanalytic techniques

- **Key Derivation**: Primitive password padding → **PBKDF2 with 600,000 iterations**
  - v1.0: Simple key extension by repeating password
  - v2.0: PBKDF2-SHA256 with random salt, 600,000 iterations (~100ms per derivation)
  - Benefit: Brute-force password attacks become computational expensive

#### File Format
- **New FSS1 Format** (File Secure Suite v1):
  - Magic bytes: "FSS1" (format identification)
  - Version field (allows future format upgrades)
  - SHA-256 hash of original file (integrity verification)
  - Filename preservation with length prefix
  - Structured encryption metadata
  - Benefit: Prevents format confusion attacks, verifies integrity

#### Password Strength
- **Added validation**: Minimum 8 characters, mixed case/digits/special chars
- **Prevents weak passwords**: Check before encryption begins

### Feature Additions

#### Chat System Redesign
- **Open Chat** (new):
  - Unencrypted real-time messages
  - No setup needed (just type and send)
  - Fastest transmission mode
  
- **Private Chat** (new):
  - Ephemeral 8-digit tokens (session-based, not stored)
  - AES-256-GCM encryption + GZIP compression (optimized for audio)
  - Size reduction: 50-60% via GZIP before encryption
  - Transmission time: 1-3 seconds (vs 2-5 for open chat)

- **v1.0 had**: Generic "send_text()" without distinction

#### Audit Logging
- **New audit log system**:
  - Located: `audiologs/sonarlink_audit.log`
  - Tracks: timestamp, operation, filename, encryption method, status
  - Privacy: No message content logged (metadata only)
  - File permissions: 0600 (owner read/write only)

#### User Interface
- **Colorama integration**:
  - Color-coded output: Success (green), Error (red), Warning (yellow), Info (cyan)
  - Better menu navigation with emoji indicators
  - Status messages are more readable

- **Main Menu**:
  ```
  [1] 💬 Open Chat          (NEW)
  [2] 📁 Send file
  [3] 🎧 Receive
  [4] 🔓 Decrypt file
  [5] 📊 View Audit Log     (NEW)
  [6] ℹ️ Credits             (UPDATED)
  [7] ❌ Exit
  ```

#### Lightning Network Support
- **QR code display** for donations
- **Optional qrcode library** integration
- Enables community support for project maintenance

#### Audio Transmission Optimization
- **Separate optimization paths**:
  - Chat: GZIP compression optimized for audio bandwidth
  - Files: FSS1 format with structured metadata
  - v1.0: Single code path for all transmission types

### Bug Fixes & Improvements

#### Cross-Platform
- **Windows**: PyInstaller compatibility improved
  - Proper path resolution for PyInstaller --onefile mode
  - Keyboard interrupt handling more robust
  
- **Linux**: Audio warning suppression
  - ALSA error suppression via environment variables
  - JACK_NO_AUDIO_SYNC added
  - File descriptor redirection for C library warnings

- **macOS**: Apple Silicon support verified
  - Native compilation for arm64
  - No Rosetta 2 needed

#### Error Handling
- **Password validation**: Prevents weak passwords before encryption
- **File path validation**: Prevents directory traversal attacks
- **Filename sanitization**: Removes dangerous characters from filenames
- **Path traversal protection**: Absolute path resolution for received files

#### Installation
- **Comprehensive installers**:
  - Windows: Automatic PyAudio handling for Python 3.13+
  - Linux: Multi-distro support (Debian, Arch, Fedora, openSUSE)
  - macOS: Homebrew integration, PortAudio management
  - All: Fallback procedures documented

### Removed Features
- **Multiple file transfer** in unencrypted mode:
  - v1.0: Could send multiple files separated by commas
  - v2.0: One file per transfer (simplicity + reliability)
  - Workaround: Send files sequentially or use ZIP

- **Configurable file size limit**:
  - v1.0: Set MAX_FILE_SIZE in code
  - v2.0: Fixed at 10 KB (realistic and documented)

### Performance Changes

#### File Transfer Times (Estimated)
| File Size | v1.0 Time | v2.0 Time | Note |
|-----------|-----------|-----------|------|
| 1 KB | ~16 sec | ~16 sec | Same |
| 10 KB | ~2.5 min | ~2.5 min | Same |
| **Practical limit** | 100 KB+ | 10 KB | v2.0 is realistic |

#### Chat Transmission
| Mode | v1.0 | v2.0 | Improvement |
|------|------|------|-------------|
| Text message | 2-5 sec | 2-5 sec | Same speed |
| Private message | N/A | 1-3 sec | NEW (smaller due to GZIP) |
| Unencrypted message | 2-5 sec | 2-5 sec | Same |

### Documentation Updates

#### New Guides
- **QUICKSTART.md**: Get running in 5 minutes with real examples
- **SECURITY.md**: Complete threat model with 7 threat analysis
- **WINDOWS_PYTHON_INSTALLATION_GUIDE.md**: Step-by-step Python setup
- **INSTALLATION_INSTRUCTIONS.md**: Comprehensive platform-specific installation

#### Updated Documentation
- **README.md**: v1.0 → v2.0, realistic file limits, updated features
- **Feature descriptions**: Added Private Chat, Audit Log, Lightning donations
- **Encryption details**: AES-256-GCM, RSA-4096, PBKDF2 specifications
- **Best practices**: User and administrator security guidance

### Dependencies

#### Version Changes
- **cryptography**: Updated to latest stable (AES-256-GCM, RSA-4096 support)
- **ggwave-wheels**: Maintained at v0.4.2.5 (no breaking changes)
- **numpy**: Maintained for numerical operations

#### New Dependencies
- **colorama**: Terminal color output (optional, degrades gracefully)
- **qrcode**: Lightning Network QR codes (optional, try/except handling)
- **pyinstaller**: Standalone executable creation (optional)

### Migration Guide (v1.0 → v2.0)

#### For Users
1. **Backup old files**: Save any v1.0 encrypted files before upgrading
2. **Reinstall Python dependencies**: New requirements for AES-256-GCM
3. **Update file references**: 10 MB files won't work - use 10 KB limit
4. **Check scripts**: If you have custom scripts, update for v2.0 API

#### For Developers
1. **Key derivation changed**: Use `derive_key_from_password()` instead of padding
2. **Encryption API**: `aes_encrypt_fss1()` replaces old `aes_encrypt()`
3. **File format**: FSS1 format replaces old format
4. **No HMAC**: GCM mode handles authentication automatically
5. **RSA key size**: Generate 4096-bit keys (takes longer, ~5-10 seconds)

### Known Issues (v2.0)

#### None known at release
- All identified v1.0 issues resolved
- Extensive cross-platform testing completed

### Future Considerations (Post v2.0)

Potential improvements for v2.1+:
- Quantum-resistant encryption options
- Larger file support with resume capability
- Mobile application (iOS/Android)
- GUI interface option
- Ultrasound mode for higher speeds
- Bidirectional transfer protocol

---

## [1.0] - October 2025

### Initial Release

#### Core Features
- Audio-based file transfer via ggwave library
- AES-256-CFB encryption with HMAC authentication
- RSA-2048-OAEP encryption
- Text message support
- Multiple file transfer (unencrypted mode)
- Error recovery system
- Cross-platform support

#### Supported Platforms
- Windows (10/11, 64-bit and 32-bit)
- Linux (x86_64, ARM64, ARM32)
- macOS (Intel and Apple Silicon)

#### Installation
- Automated installers for all platforms
- Support for 7 platform architectures
- Manual installation instructions included

#### Documentation
- Complete README with examples
- Quick start guide
- Troubleshooting section
- Security considerations

---

## Version Comparison Summary

| Feature | v1.0 | v2.0 |
|---------|------|------|
| **AES Encryption** | CFB mode + HMAC | GCM mode (authenticated) |
| **RSA Key Size** | 2048-bit | 4096-bit |
| **Key Derivation** | Password padding | PBKDF2 600K iterations |
| **File Format** | Basic | FSS1 with metadata |
| **Chat Modes** | Single mode | Open + Private |
| **Max File Size** | 10 MB | 10 KB |
| **Audit Log** | None | Full metadata log |
| **UI Colors** | Plain text | Colorama enhanced |
| **Donations** | None | Lightning Network |
| **Password Validation** | None | Strength checking |
| **File Integrity** | HMAC (only files) | SHA-256 hash (all) |
| **Cross-Platform Installers** | 3 basic | 3 enhanced with fallbacks |
| **Supported Python Versions** | 3.8+ | 3.8+ (3.13+ special handling) |

---

**SonarLink v2.0 represents a major security and usability upgrade from v1.0.**

*Key improvements: Stronger encryption, realistic limits, better tooling, comprehensive documentation, and production-ready reliability.*
