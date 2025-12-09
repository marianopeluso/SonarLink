# SonarLink v2.0 - Quick Start Guide

Get up and running with SonarLink v2.0 in 5 minutes.

---

## 🚀 Installation (2 minutes)

### Windows
```batch
install_windows.bat
```

### Linux
```bash
bash install_linux.sh
```

### macOS
```bash
bash install_macos.sh
```

**All done?** Run:
```bash
python sonarlink2_0.py
```

---

## 📋 Main Menu Overview

When you start SonarLink, you'll see:

```
🔊 SonarLink v2.0 - Audio-Based File Transfer 🔊
================================================

[1] 💬 Open Chat          ← Send unencrypted messages
[2] 📁 Send file          ← Send encrypted files (up to 10 KB)
[3] 🎧 Receive            ← Listen for messages/files
[4] 🔓 Decrypt file       ← Decrypt received files
[5] 📊 View Audit Log     ← See operation history
[6] ℹ️ Credits             ← About & donations
[7] ❌ Exit               ← Close application
```

---

## 💬 Quick Task: Send a Message

### Open Chat (No encryption)

**Sender:**
1. Press `1` (Open Chat)
2. Type your message
3. Speaker icon appears, transmission happens (takes 2-5 seconds)
4. Message sent via audio waves 🔊

**Receiver:**
1. Press `3` (Receive messages or files)
2. Hold phone/device close
3. Message appears in terminal when received

---

## 🔒 Quick Task: Send Encrypted Message

### Private Chat (AES-256-GCM + GZIP)

**Step 1: Sender generates token**
```
[1] 💬 Open Chat
→ Private Chat (option at bottom)
→ System generates 8-digit token
→ Share token with receiver verbally or via separate channel
```

**Step 2: Receiver enters token**
```
[3] 🎧 Receive
→ Private Chat
→ Enter the 8-digit token
→ Ready to receive
```

**Step 3: Send message**
- Sender types message
- Encrypted transmission (smaller, faster than open chat)
- Receiver sees decrypted message

---

## 📁 Quick Task: Send a File

### File Transfer (up to 10 KB)

**Perfect for:**
- SSH keys 🔑
- GPG keys 🔐
- Passwords 🛡️
- Small credentials 📋
- Short documents 📄

**Sender:**
1. Press `2` (Send file)
2. Choose encryption:
   - `1`: AES-256-GCM (faster, recommended)
   - `2`: RSA-4096 (slower, maximum security)
3. Enter password (for AES) or just confirm (for RSA)
4. Select file to send (drag & drop or type path)
5. Transmission starts 🔊

**Receiver:**
1. Press `3` (Receive)
2. File option → Choose decryption method
3. Hold device close
4. File saved to `audio_received/` folder

**Extract encrypted file:**
1. Press `4` (Decrypt file)
2. Select file from `audio_received/`
3. Enter password
4. Done! File extracted to `audio_send/` (decrypted version)

---

## 📊 Audit Log

Track all operations:

```
Press [5] → View Audit Log
```

Shows:
- Timestamp of each operation
- File name
- Encryption method (AES, RSA, plain)
- Status (SUCCESS, FAILED)

**Privacy note:** Log records metadata only, NOT message content.

---

## 🎯 Common Scenarios

### Scenario 1: Share SSH Key Securely (Air-gapped)
```
1. Generate SSH key on secure computer
2. Use SonarLink to send via audio
3. Receiver captures on offline device
4. Transfer via USB/network after air-gap
```

### Scenario 2: Exchange Passwords in Covert Environment
```
1. Sender: Press [1] → Private Chat
2. System generates token (e.g., 12345678)
3. Share token verbally or via separate secure channel
4. Sender types password
5. Receiver uses token to decrypt
```

### Scenario 3: Backup Encryption Keys
```
1. Export encryption key to file
2. Press [2] (Send file)
3. Use RSA-4096 (maximum security)
4. Send to offline backup device
5. Audit log tracks backup event
```

---

## ⚡ Performance Tips

### For Faster Transmission
- Use **AES-256-GCM** (smaller, faster)
- Keep files under 5 KB when possible
- Reduce background noise
- Move devices closer (0.5-1 meter)

### For More Reliable Reception
- Set system volume to **100%**
- Use **Private Chat** (GZIP compresses better)
- Ensure good microphone quality
- Keep quiet environment

### File Size Limits
- Open Chat: Depends on message length
- Private Chat: ~50-60% size reduction via GZIP
- Files: Up to 10 KB (with encryption metadata)
- Practical: Keep under 10 KB for reliable transfer

---

## 🔐 Security at a Glance

| Feature | Details |
|---------|---------|
| **Open Chat** | No encryption (plaintext audio) |
| **Private Chat** | AES-256-GCM + GZIP compression |
| **File Transfer (AES)** | AES-256-GCM + FSS1 format |
| **File Transfer (RSA)** | RSA-4096 hybrid encryption |
| **Key Derivation** | PBKDF2 with 600,000 iterations |
| **Hash Verification** | SHA-256 integrity check |
| **Tokens** | 8-digit, ephemeral, session-based |

---

## 📁 Folder Structure

SonarLink creates these folders:

```
.
├─ audio_send/          ← Files to send
├─ audio_received/      ← Files received (encrypted)
├─ audiologs/           ← Audit log
│  └─ sonarlink_audit.log
└─ sonarlink2_0.py      ← Application
```

---

## ❓ Troubleshooting

### "No audio detected"
- Check microphone volume (should be 100%)
- Check system audio settings
- Test microphone with voice recorder first

### "File too large"
- SonarLink supports max 10 KB
- Compress file before sending
- For larger files, use network-based tools

### "Message corrupted"
- Move devices closer
- Reduce background noise
- Try again with slower audio (lower quality setting)

### "Decryption failed"
- Verify password is correct
- Check file wasn't corrupted during transfer
- Try receiving again

---

## 🚀 Next Steps

1. **Try Open Chat** - fastest, no setup
2. **Test File Transfer** - with small test file
3. **Use Private Chat** - for sensitive data
4. **Check Audit Log** - verify all operations

---

## 💡 Pro Tips

- **Plausible deniability**: Audio files look innocent, no visible QR codes
- **Offline capability**: No internet needed, pure sound waves
- **Cross-room transfer**: Works through doorways, not just face-to-face
- **Verifiable**: Audit log provides tamper-proof record

---

## 📚 Learn More

For detailed information:
- **Installation**: See `INSTALL.md`
- **Security Details**: See `SECURITY.md`
- **Full Features**: See `README.md`

---

## ⚡ Lightning Support

Enjoying SonarLink? Support development:

```
Press [6] (Credits) → View QR Code
```

Lightning Network donations help maintain the project!

---

**Ready to use SonarLink?** Start with `python sonarlink2_0.py` 🔊
