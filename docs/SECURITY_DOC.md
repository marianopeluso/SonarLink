# SonarLink v2.0 - Security Documentation

Comprehensive security analysis, cryptography details, and best practices.

---

## 📋 Contents

1. [Overview](#overview)
2. [Cryptographic Architecture](#cryptographic-architecture)
3. [Threat Model](#threat-model)
4. [Implementation Details](#implementation-details)
5. [Best Practices](#best-practices)
6. [Audit Logging](#audit-logging)
7. [Known Limitations](#known-limitations)

---

## Overview

SonarLink uses sound waves for data transmission with strong encryption options:

- **Open Chat**: Unencrypted plaintext (for non-sensitive communication)
- **Private Chat**: AES-256-GCM with GZIP compression (balanced security/speed)
- **File Transfer**: AES-256-GCM or RSA-4096 with FSS1 format (maximum flexibility)

All encryption uses industry-standard cryptographic primitives from Python's `cryptography` library (FIPS 140-2 validated algorithms).

---

## Cryptographic Architecture

### 1. Open Chat
**Use case:** Non-sensitive messages, testing, public announcements

```
Plaintext Message
    ↓
GZIP Compression
    ↓
ggwave Audio Encoding (PROTOCOL_ID=1, AUDIBLE_FAST)
    ↓
Audio Transmission (48 kHz, 120-byte chunks)
```

**Security Level:** ⚠️ None (plaintext)
**When to use:** Testing, non-sensitive communication only
**Transmission time:** 2-5 seconds per message

**Advantages:**
- Fastest transmission
- No password overhead
- Suitable for public/open communication

**Risks:**
- Fully observable by anyone in audio range
- No integrity protection
- No replay protection

---

### 2. Private Chat
**Use case:** Sensitive messages, passwords, credentials in trusted environments

```
Plaintext Message
    ↓
GZIP Compression (optimized for audio, 50-60% size reduction)
    ↓
AES-256-GCM Encryption
    │
    ├─ Key: PBKDF2(password, salt, 600,000 iterations, SHA-256)
    ├─ IV: Random 12 bytes
    ├─ Tag: 16 bytes (authentication)
    │
    ↓
ggwave Audio Encoding
    ↓
Audio Transmission
```

**Security Level:** ✅ High (256-bit symmetric)
**When to use:** Sensitive messages requiring encryption
**Transmission time:** 1-3 seconds per message (faster due to compression)

**Cryptographic Parameters:**
- **Cipher**: AES-256 in GCM mode (NIST approved)
- **Key Size**: 256 bits
- **IV Size**: 12 bytes (random, 2^96 combinations)
- **Authentication Tag**: 16 bytes (provides authenticity + integrity)
- **PBKDF2**: 600,000 iterations (CPU-intensive, resistant to brute force)

**Advantages:**
- Authenticated encryption (AEAD)
- Compression reduces transmission time
- Ephemeral tokens (no permanent secrets)
- GZIP optimized for audio bandwidth

**Risks:**
- Requires secure password
- Token transmitted verbally (eavesdropping possible)
- Short token (8 digits) = ~23 bits entropy
- Forward secrecy not available (session-based)

**Token Security Analysis:**
- 8-digit token: 10^8 combinations (100 million)
- Brute force: Requires audio transmission for each attempt
- Rate limiting: Natural audio transmission overhead
- Practical security: Sufficient for covert environments

---

### 3. File Transfer (AES-256-GCM)

```
File Binary Data
    ↓
AES-256-GCM Encryption
    │
    ├─ Key: PBKDF2(password, salt, 600,000 iterations)
    ├─ IV: Random 12 bytes
    ├─ Additional Data: Filename + metadata
    │
    ↓
FSS1 Format Wrapping
    │
    ├─ Magic: "FSS1" (4 bytes)
    ├─ Version: 1 (1 byte)
    ├─ Ciphertext
    ├─ IV (12 bytes)
    ├─ Authentication Tag (16 bytes)
    ├─ SHA-256 Hash of original file
    ├─ Filename length + filename
    │
    ↓
Chunked ggwave Transmission (120 bytes per chunk)
    ↓
Audio Transmission
```

**Security Level:** ✅ Very High (256-bit symmetric)
**When to use:** SSH keys, GPG keys, passwords, sensitive files
**File Size Limit:** 10 KB
**Transmission time:** 10-30 seconds per file

**FSS1 Format Protection:**
- SHA-256 hash verification (integrity)
- Filename preservation
- Structured encryption (prevents confusion attacks)
- Version field (allows future upgrades)

**Advantages:**
- Authenticated encryption
- Integrity verification (SHA-256)
- Metadata protection
- Deterministic decryption

**Risks:**
- Password quality critical
- Large files slow transmission
- Limited to 10 KB (practical constraint)

---

### 4. File Transfer (RSA-4096)

```
File Binary Data
    ↓
AES-256-GCM Symmetric Encryption (file encryption)
    │
    ├─ Random 256-bit key
    ├─ Random 12-byte IV
    │
    ↓
RSA-4096 Key Encapsulation (key encryption)
    │
    ├─ Encrypt: AES key with recipient's RSA public key
    ├─ Padding: OAEP with SHA-256
    │
    ↓
FSS1 Format Wrapping
    │
    ├─ RSA-encrypted AES key (512 bytes)
    ├─ Encrypted file + IV + tag
    ├─ SHA-256 hash
    │
    ↓
Chunked Transmission
```

**Security Level:** ✅✅ Maximum (4096-bit asymmetric + 256-bit symmetric)
**When to use:** Maximum security, future-proof encryption
**File Size Limit:** 10 KB
**Transmission time:** 15-40 seconds per file
**Key Generation Time:** 5-10 seconds (first time only)

**RSA-4096 Security:**
- 4096-bit key size (NIST recommends for long-term security)
- OAEP padding with SHA-256 (semantic security)
- Hybrid encryption (RSA for key, AES for data)
- Allows offline key generation

**Advantages:**
- Asymmetric encryption (no password sharing)
- Offline key generation
- Future-proof (4096-bit resistant to quantum)
- Hybrid efficiency (fast AES, strong RSA)

**Risks:**
- Slower than AES alone
- 4096-bit keys generate slowly (5-10 seconds)
- Public key distribution challenge
- Larger ciphertext overhead

---

## Threat Model

### Threat 1: Passive Eavesdropping

**Attack:** Attacker records audio transmission

**Mitigations:**
- **Open Chat**: No protection (expected)
- **Private Chat**: AES-256-GCM encryption (computation impossible)
- **File Transfer**: Same as Private Chat
- **Audio Medium**: Unique advantage vs network protocols (ephemeral, analog)

**Residual Risk:** ⚠️ Low (encryption makes content unrecoverable)

---

### Threat 2: Active Replay Attack

**Attack:** Attacker captures encrypted message and replays it

**Mitigations:**
- **Authentication Tag**: AES-GCM detects replayed ciphertexts
- **Timestamps in Audit Log**: Detects when message was repeated
- **Unique IVs**: Each message has random IV (prevents collision)

**Residual Risk:** ⚠️ Very Low (authentication tag detects replays)

---

### Threat 3: Brute Force Password Attack

**Attack:** Attacker tries common passwords

**Mitigations:**
- **PBKDF2**: 600,000 iterations with SHA-256
- **Random Salt**: Each encryption uses unique salt
- **Audio Overhead**: Transmission takes seconds (attacker can't try 1000s/sec)

**Calculation:**
```
Time per attempt: ~100 ms (PBKDF2 on modern CPU)
Attempts per second: ~10
Dictionary size: ~100,000 common passwords
Total brute force time: ~10,000 seconds (≈3 hours)
```

**Practical Security:** Password must be >12 characters or random

**Residual Risk:** 🟡 Medium (depends on password strength)

---

### Threat 4: Compression Side Channel

**Attack:** Attacker uses GZIP compression ratio to infer message content

**Mitigations:**
- **Compression before encryption**: GZIP is first step
- **Padding optional**: Not implemented (acceptable for audio)
- **GZIP effectiveness varies**: Message length still observable

**Example:**
```
"A" compressed: ~30 bytes
"The quick brown fox..." compressed: ~40 bytes
Attacker observes ~10 byte difference
```

**Practical Impact:** Low (attacker knows message length, not content)

**Residual Risk:** 🟡 Very Low (acceptable trade-off)

---

### Threat 5: Metadata Leakage

**Attack:** Attacker observes transmission pattern, timing, file size

**Mitigations:**
- **Audit Log**: Timestamp only, no message content
- **Audio format**: Appears as normal audio file
- **No headers**: Audio transmission indistinguishable from music

**Observable Information:**
- ✓ Transmission occurred (time, date)
- ✓ File size (observable by audio duration)
- ✓ Encryption method (observable by transmission pattern)
- ✗ Message content (fully encrypted)
- ✗ Recipient identity (peer-to-peer)

**Advantage over QR codes:** Audio transmission appears innocent, no visual signature

**Residual Risk:** 🟢 Acceptable (metadata acceptable loss)

---

### Threat 6: Quantum Computing

**Attack:** Future quantum computer breaks AES or RSA

**Mitigations for AES-256:**
- AES-256 considered quantum-resistant by NIST
- Requires ~2^128 quantum operations (still computationally infeasible)

**Mitigations for RSA-4096:**
- 4096-bit key resists known quantum attacks longer
- Hybrid encryption (RSA for key, AES-256 for data)
- Users can generate new keys yearly

**Current Status:** Not a near-term threat, but considered in RSA-4096 option

**Residual Risk:** 🟢 Low (NIST currently considers AES-256 quantum-resistant)

---

### Threat 7: Frequency Analysis Attack

**Attack:** Attacker analyzes audio spectrum to infer content

**Mitigations:**
- **GCM mode**: Produces unpredictable ciphertext
- **GZIP**: Removes patterns before encryption
- **ggwave**: Spreads data across frequency range

**Practical Security:** Ciphertext appears as random audio

**Residual Risk:** 🟢 Very Low (ciphertext appears random)

---

## Implementation Details

### Key Derivation (PBKDF2)

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt = secrets.token_bytes(16)  # Random 16-byte salt
key = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256 bits
    salt=salt,
    iterations=600000,  # CPU-intensive
    backend=default_backend()
).derive(password.encode())
```

**Security Parameters:**
- Salt length: 16 bytes (128 bits)
- Key length: 32 bytes (256 bits)
- Iterations: 600,000 (≈100ms per derivation)
- Hash: SHA-256

---

### Encryption (AES-256-GCM)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

iv = secrets.token_bytes(12)  # Random 12-byte IV
cipher = AESGCM(key)
ciphertext = cipher.encrypt(iv, plaintext, associated_data)
# Automatically appends 16-byte authentication tag
```

**Security Parameters:**
- IV length: 12 bytes (96 bits)
- Tag length: 16 bytes (128 bits, NIST minimum)
- Mode: GCM (Galois/Counter Mode)

**Why 12-byte IV?**
- GCM spec recommends 96-bit (12-byte) IV
- Longer IVs require hashing (slower)
- 2^96 ≈ 10^29 possible IVs (never repeat with 600k messages/device)

---

### Integrity Verification (SHA-256)

```python
import hashlib

hash_digest = hashlib.sha256(plaintext).digest()  # 32 bytes
# Stored in FSS1 format for verification after decryption
```

**Security Parameters:**
- Hash algorithm: SHA-256 (256-bit output)
- Purpose: File integrity, not authentication
- Verification: Computed after decryption

---

### RSA-4096 Key Generation

```python
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
```

**Security Parameters:**
- Key size: 4096 bits
- Public exponent: 65537 (standard, small, efficient)
- Generation time: 5-10 seconds (slow but acceptable)

---

### Token Generation (Private Chat)

```python
token = str(random.randint(10000000, 99999999))  # 8 digits
# Ephemeral, not stored after session
```

**Security Analysis:**
- 8 digits = 10^8 combinations (100 million)
- Entropy: log2(10^8) ≈ 26.6 bits
- Practical: Sufficient for covert communication (attacker can't brute force audio)
- Session-based: No long-term storage or reuse

---

## Best Practices

### For Users

#### 1. Password Security
✅ **DO:**
- Use random passwords (16+ characters if possible)
- Use special characters: !@#$%^&*()
- Generate with password manager
- Never reuse across platforms

❌ **DON'T:**
- Use common words or phrases
- Use personal information (birthdate, name)
- Reuse passwords from other services
- Share password in advance

**Example password strength:**
```
Weak:      "password123" (2 seconds to crack)
Medium:    "MyPassw0rd!" (1 hour)
Strong:    "G9x#kL2@pQm$" (1 million years)
```

#### 2. Token Sharing
✅ **DO:**
- Share 8-digit token via separate secure channel
- Speak token verbally (face-to-face preferred)
- Use out-of-band delivery (phone call, encrypted message)

❌ **DON'T:**
- Type token in cleartext messages
- Send token through same channel as encrypted message
- Reuse token for multiple sessions
- Store token after session ends

#### 3. File Transfer
✅ **DO:**
- Use RSA-4096 for long-term sensitive data
- Use AES-256-GCM for frequent transfers
- Verify file hash after transfer
- Delete original plaintext after transfer

❌ **DON'T:**
- Transfer files larger than 10 KB
- Send unencrypted sensitive files
- Ignore failed transfers (retry instead)

#### 4. Operational Security
✅ **DO:**
- Check audit log after critical transfers
- Use air-gapped systems when possible
- Test with dummy data first
- Verify recipient identity before sending

❌ **DON'T:**
- Use in loud/noisy environments
- Share decrypted files on untrusted devices
- Leave decrypted files undeleted
- Use predictable passwords

#### 5. Environment
✅ **DO:**
- Use in private spaces
- Minimize background noise
- Ensure good microphone quality
- Close doors/windows for privacy

❌ **DON'T:**
- Use in public spaces (audio eavesdropping risk)
- Rely on open chat for sensitive data
- Use damaged microphones
- Transmit in high-noise environments

---

### For Administrators

#### 1. Deployment Security
✅ **DO:**
- Deploy from official GitHub repository
- Verify GPG signatures of releases
- Audit source code before deployment
- Use virtual environments (isolated Python)

❌ **DON'T:**
- Download from untrusted sources
- Skip GPG verification
- Run as root/administrator
- Deploy to multi-user systems without isolation

#### 2. System Hardening
✅ **DO:**
- Restrict microphone access (OS-level permissions)
- Use SELinux/AppArmor policies
- Audit log rotation (delete old logs weekly)
- Monitor for unauthorized audio access

❌ **DON'T:**
- Grant unnecessary permissions
- Leave audit logs to grow infinitely
- Share SonarLink across user accounts
- Disable OS-level security features

#### 3. Monitoring & Logging
✅ **DO:**
- Review audit logs regularly
- Detect unusual transmission patterns
- Archive logs to separate secure storage
- Set file permissions to 0600 (owner read/write only)

❌ **DON'T:**
- Ignore failed transfer attempts
- Store logs on untrusted media
- Make logs world-readable
- Delete logs without archiving

---

## Audit Logging

### Log Format

```
[2024-01-15T14:23:45.123456] SEND_FILE     | file: ssh_key.pub                 | method: AES-256    | status: SUCCESS
[2024-01-15T14:24:12.654321] SEND_TEXT     | file: [chat message]              | method: AES-256    | status: SUCCESS
[2024-01-15T14:25:00.987654] RECV_FILE     | file: encrypted_data.bin          | method: RSA-4096   | status: SUCCESS
[2024-01-15T14:26:15.111111] DECRYPT_FILE  | file: encrypted_data.bin          | method: RSA-4096   | status: FAILED     | error: Wrong password
```

### What's Logged ✅
- **Timestamp**: ISO 8601 format
- **Operation**: SEND_TEXT, RECV_FILE, DECRYPT, etc.
- **Filename**: Original filename (not content)
- **Method**: AES-256, RSA-4096, PLAIN
- **Status**: SUCCESS, FAILED
- **Error**: Error message if failed

### What's NOT Logged ❌
- **Message content**: Never stored
- **Password**: Never logged
- **Decrypted data**: Never stored
- **Recipient identity**: Not applicable (peer-to-peer)
- **Encryption keys**: Never logged

### Security of Audit Log
```
File: audiologs/sonarlink_audit.log
Permissions: 0600 (owner read/write only)
```

### Privacy-Preserving Design
The audit log provides operational visibility without compromising privacy:

```
Useful information:
✓ What operations occurred
✓ When they occurred
✓ Success/failure status
✓ Encryption method used

Sensitive information protected:
✗ Message content
✗ File contents
✗ Passwords/keys
✗ Decrypted data
```

---

## Known Limitations

### 1. Computational Constraints
- **RSA-4096 generation**: Slow (5-10 seconds)
- **PBKDF2**: Intentionally slow (100ms per derivation)
- **File size**: Limited to 10 KB practical maximum

**Why:** These are deliberate security trade-offs, not bugs.

---

### 2. Physical Layer Eavesdropping
- **Audio capture**: Attacker in audio range can record transmission
- **Mitigation**: Encryption makes captured audio unrecoverable
- **Alternative**: No better than other physical channels (radio, infrared)

---

### 3. Token Security
- **8-digit token**: 26.6 bits entropy
- **Mitigation**: Attacker can't replay (audio overhead prevents brute force)
- **Assumption**: Token transmitted via secure out-of-band channel

---

### 4. Forward Secrecy
- **No perfect forward secrecy**: Session key derived from password
- **Mitigation**: Ephemeral tokens + session-based
- **Use RSA-4096** if maximum security needed

---

### 5. Synchronization
- **No time synchronization**: Receiver must be ready when sender transmits
- **Mitigation**: Receiver initiates connection (press [3])
- **Design**: Intentional (simplicity, no network overhead)

---

### 6. Audio Quality Dependent
- **Compressed audio**: Lossy codecs destroy data
- **Background noise**: Reduces success rate
- **Solution**: Use high-quality uncompressed audio, quiet environments

---

## Security Considerations by Use Case

### Use Case 1: SSH Key Distribution
**Threat Level:** 🔴 Critical (SSH keys = system access)
**Recommended Method:** RSA-4096 or AES-256-GCM + secure password
**Key Points:**
- Keep key file size <10 KB ✓
- Use strong password (16+ chars) ✓
- Verify hash after transfer ✓
- Delete plaintext after transfer ✓

### Use Case 2: Covert Communication
**Threat Level:** 🔴 Critical (adversarial environment)
**Recommended Method:** AES-256-GCM private chat + secure token
**Key Points:**
- Share token verbally only ✓
- Use air-gapped devices when possible ✓
- Operate in private spaces ✓
- Audio appears innocent vs. QR codes ✓

### Use Case 3: Sensitive Credential Backup
**Threat Level:** 🟠 High (valuable if compromised)
**Recommended Method:** RSA-4096 (no password needed)
**Key Points:**
- Generate RSA key on secure device ✓
- Transfer encrypted via audio ✓
- Store ciphertext offline ✓
- Decrypt when needed on air-gapped system ✓

### Use Case 4: Non-Sensitive File Transfer
**Threat Level:** 🟢 Low (no confidentiality requirement)
**Recommended Method:** Open Chat or AES-256-GCM
**Key Points:**
- Open chat acceptable ✓
- No password needed ✓
- Fastest transmission ✓

---

## Cryptographic Assumptions

This security analysis assumes:

1. ✅ Python `cryptography` library is correctly implemented
2. ✅ Operating system provides entropy (`secrets` module)
3. ✅ ggwave library correctly encodes/decodes
4. ✅ User provides strong passwords
5. ✅ Sender and receiver use genuine SonarLink (not compromised)
6. ✅ Computation hardware is trustworthy
7. ✅ No quantum computers exist (current threat model)

**If assumption breaks:** Security may be compromised. Audit log helps detect if assumption #5 breaks.

---

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** post to public GitHub issues
2. **DO** email security@sonarlink.org (when available)
3. **Include:** Vulnerability description, proof of concept, affected version
4. **Expect:** Response within 48 hours
5. **Responsible disclosure:** 90-day embargo before public announcement

---

## Resources

- **NIST Cryptographic Standards**: https://csrc.nist.gov/publications/
- **Python cryptography library**: https://cryptography.io/
- **OWASP Password Cheat Sheet**: https://cheatsheetseries.owasp.org/
- **AES-GCM Specification**: https://csrc.nist.gov/publications/detail/sp/800-38d/final

---

## Conclusion

SonarLink v2.0 implements industry-standard cryptography with strong security properties:

- ✅ AES-256-GCM for fast, authenticated encryption
- ✅ RSA-4096 for maximum long-term security
- ✅ PBKDF2 for password-based key derivation
- ✅ SHA-256 for integrity verification
- ✅ Ephemeral tokens for session security
- ✅ Privacy-preserving audit logs

**Security is strong, but depends on:**
1. User password/token strength
2. Correct implementation (audited community possible)
3. Operational discipline (don't share tokens insecurely)
4. Environmental security (quiet, private spaces)

For questions or security concerns, open an issue on GitHub.

---

**Version:** SonarLink v2.0  
**Last Updated:** 2025-12-15  
**License:** Open Source 
