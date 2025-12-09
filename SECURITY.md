# 🔐 SonarLink v2.0 - Security Policy

**SonarLink - Secure audio-based file transfer and encrypted messaging, powered by sound**

---

## Release Verification

All SonarLink v2.0 releases are cryptographically signed with GPG to ensure authenticity and integrity.

### How to Verify a Release

#### Step 1: Import the Public Key (First Time Only)

```bash
# Download the public key
curl -O https://github.com/marianopeluso/sonarlink/raw/main/sonarlink-public-key.asc

# Import it into GPG
gpg --import sonarlink-public-key.asc

# Verify the key fingerprint
gpg --fingerprint mariano@peluso.me
```

**Expected fingerprint:**
```
0FD97EB855F7C5BB1048D424F20494B9FAB53C10
```

#### Step 2: Download the Release Files

```bash
# Download from GitHub Releases
VERSION="2.0"
BASE_URL="https://github.com/marianopeluso/sonarlink/releases/download/v${VERSION}"

# Download archive and signature
curl -LO "${BASE_URL}/sonarlink-v${VERSION}.zip"
curl -LO "${BASE_URL}/sonarlink-v${VERSION}.zip.asc"
curl -LO "${BASE_URL}/sonarlink-v${VERSION}.zip.sha256"
```

#### Step 3: Verify the GPG Signature

```bash
gpg --verify sonarlink-v2.0.zip.asc sonarlink-v2.0.zip
```

**Expected output:**
```
gpg: Signature made [DATE]
gpg:                using RSA key F20494B9FAB53C10
gpg: Good signature from "Mariano Peluso <mariano@peluso.me>"
```

✅ **"Good signature"** means the file is authentic and hasn't been tampered with.

⚠️ If you see `[unknown]` after the name, it's normal - it means you haven't personally verified the key owner's identity. This is acceptable for open-source projects.

❌ **If you see "BAD signature"**, DO NOT use the file. The release may have been compromised.

#### Step 4: Verify the Checksum

```bash
# Verify SHA-256
sha256sum -c sonarlink-v2.0.zip.sha256

# Or manually compare
sha256sum sonarlink-v2.0.zip
cat sonarlink-v2.0.zip.sha256
```

**Expected output:**
```
sonarlink2.0.zip: OK
```

### Windows Users

**Install GPG:**
1. Download Gpg4win: https://www.gpg4win.org/download.html
2. Install with default options

**Verify signature:**
```cmd
gpg --verify sonarlink2.0.zip.asc sonarlink2.0.zip
```

**Verify checksum (without GPG):**
```cmd
certutil -hashfile sonarlink2.0.zip SHA256
```
Compare the output with the hash in `sonarlink2.0.zip.sha256`

### macOS/Linux Users

**Install GPG (if not present):**
```bash
# macOS
brew install gnupg

# Ubuntu/Debian
sudo apt-get install gnupg

# Fedora/RHEL
sudo dnf install gnupg
```

**Verify signature:**
```bash
gpg --verify sonarlink2.0.zip.asc sonarlink2.0.zip
```

---

## Signing Key Details

### Public Key Information

| Property | Value |
|----------|-------|
| **Email** | mariano@peluso.me |
| **Key ID** | F20494B9FAB53C10 |
| **Fingerprint** | 0FD97EB855F7C5BB1048D424F20494B9FAB53C10 |
| **Key Type** | 4096-bit RSA |
| **Valid From** | 17 October 2025 |
| **Usage** | Signing, Encryption, Certifying |
| **Subkey** | 1D883A3031F0BA94 |

### Where to Find the Key

The public key is available at:
- In this repository: [`sonarlink-public-key.asc`](./sonarlink-public-key.asc)
- OpenPGP keyserver: `keys.openpgp.org`
- GitHub user profile: marianopeluso
- With every release on GitHub Releases

### Verify Key Ownership

To verify the key belongs to Mariano Peluso:

1. Check multiple sources (above)
2. Look for key on keyserver with cross-signatures
3. Verify fingerprint matches in multiple places

If fingerprints differ, DO NOT trust the key.

---

## Best Practices for Using SonarLink Securely

### Before Installation

1. ✅ **Verify every release** using GPG signature
2. ✅ **Check SHA-256 checksum** for additional verification
3. ✅ **Use official sources only** (GitHub repository)

### During Operation

1. ✅ **Use strong passwords** (16+ characters, mixed case, digits, symbols)
2. ✅ **Keep audio devices secure** during sensitive transfers
3. ✅ **Verify recipient identity** before sending encrypted files
4. ✅ **Use air-gapped systems** for maximum security
5. ✅ **Operate in private spaces** to prevent eavesdropping

### After Transfer

1. ✅ **Check audit log** for operation records
2. ✅ **Delete plaintext files** after encryption
3. ✅ **Verify file integrity** if possible
4. ✅ **Archive encrypted files** separately from keys

### Regular Maintenance

1. ✅ **Update regularly** to get security patches
2. ✅ **Monitor releases** for security advisories
3. ✅ **Review audit logs** periodically
4. ✅ **Rotate keys** annually for long-term storage

---

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability:

### Responsible Disclosure Process

**DO:**
- ✅ Email **mariano@peluso.me** privately
- ✅ Provide detailed steps to reproduce
- ✅ Include proof-of-concept code if applicable
- ✅ Allow 90 days for fix before public disclosure
- ✅ Sign emails with your GPG key if possible

**DO NOT:**
- ❌ Open a public GitHub issue
- ❌ Post on social media or forums
- ❌ Disclose publicly before we've patched
- ❌ Exploit the vulnerability maliciously
- ❌ Access systems/data you don't own

### Response Timeline

| Timeline | Action |
|----------|--------|
| **Day 1** | Initial acknowledgment (within 24 hours) |
| **Day 7** | Status update and severity assessment |
| **Day 30** | Fix targeted completion date (depends on severity) |
| **Day 90** | Public disclosure (if not patched, we disclose together) |

### Severity Levels

- **Critical**: Remote code execution, key exposure, encryption bypass
- **High**: Authentication bypass, privilege escalation
- **Medium**: Information disclosure, denial of service
- **Low**: Documentation issues, minor usability problems

---

## Supported Versions

| Version | Status | Security Updates | EOL |
|---------|--------|------------------|-----|
| 2.0.x | ✅ Active | Yes | TBD (min 2 years) |
| 1.0.x | ⚠️ Legacy | Limited | Immediate (upgrade to v2.0) |
| < 1.0 | ❌ Unsupported | No | N/A |

**Upgrade path v1.0 → v2.0:**
- v1.0 and v2.0 are NOT compatible (see README.md)
- Decrypt all v1.0 files before upgrading
- Install v2.0 with updated cryptographic standards

---

## Cryptographic Specifications (v2.0)

### AES-256-GCM Encryption

**Used for:** Chat messages and file encryption with passwords

| Parameter | Value |
|-----------|-------|
| **Cipher Mode** | GCM (Galois/Counter Mode) |
| **Key Size** | 256 bits |
| **IV Size** | 12 bytes (random) |
| **Authentication Tag** | 16 bytes (prevents tampering) |
| **Key Derivation** | PBKDF2-SHA256 |
| **Iterations** | 600,000 (~100ms per derivation) |
| **Salt** | 16 bytes (random) |
| **Format** | FSS1 (File Secure Suite v1) |

**Why GCM?** Provides authenticated encryption in a single operation. Unlike v1.0's CFB + HMAC, GCM automatically detects tampering and corruption.

### RSA-4096 Encryption

**Used for:** File encryption with maximum security, asymmetric key encryption

| Parameter | Value |
|-----------|-------|
| **Key Size** | 4096 bits |
| **Padding** | OAEP with MGF1-SHA256 |
| **Hash Algorithm** | SHA-256 |
| **Hybrid Mode** | RSA encrypts AES key, AES encrypts file |
| **Generation Time** | 5-10 seconds (one-time) |
| **Format** | FSS1 (File Secure Suite v1) |

**Why 4096-bit?** Provides 128-bit symmetric equivalent security level. Future-resistant against emerging cryptanalytic techniques.

### SHA-256 Hash Verification

**Used for:** File integrity verification in FSS1 format

| Parameter | Value |
|-----------|-------|
| **Algorithm** | SHA-256 (NIST FIPS 180-4) |
| **Output** | 32 bytes (256 bits) |
| **Purpose** | Detect corruption and tampering |
| **When Used** | File transfer with encryption |

### Random Number Generation

- **Source**: `os.urandom()` (cryptographically secure)
- **Platform**: `/dev/urandom` on Linux/macOS, CNG on Windows
- **Purpose**: IV, salt, token generation
- **Non-blocking**: Suitable for all use cases

### FSS1 Format (File Secure Suite v1)

**Structure:**
```
Magic: "FSS1" (4 bytes)
Version: 1 (1 byte)
Encrypted Data (variable)
IV (12 bytes)
Authentication Tag (16 bytes)
SHA-256 Hash (32 bytes)
Filename Length (2 bytes)
Filename (variable)
```

**Benefits:**
- Format identification (prevents confusion attacks)
- Version field (allows future format upgrades)
- Integrity verification (SHA-256 hash)
- Filename preservation
- Structured metadata

---

## Known Security Considerations

### Audio Transmission

1. **Physical Eavesdropping Risk**
   - Audio can be intercepted by anyone in audio range
   - Use encryption for sensitive data
   - Operate in private spaces for classified information

2. **Encryption Mitigates Risk**
   - Unencrypted audio: Plaintext message visible to eavesdroppers
   - AES-256-GCM encrypted: Audio is unreadable without password
   - RSA-4096 encrypted: Requires private key to decrypt

3. **Environmental Factors**
   - Transmission range: ~3 meters maximum
   - Requires quiet environment (< 40 dB background noise)
   - Subject to acoustic propagation and reflection

### Dependency Vulnerabilities

SonarLink depends on libraries that may have vulnerabilities. Mitigation:

```bash
# Keep dependencies updated
pip install --upgrade -r requirements.txt

# Check for known vulnerabilities
pip install safety
safety check
```

**Critical Dependencies:**
- `cryptography` - Encryption (actively maintained by PyCA)
- `pyaudio` - Audio I/O
- `ggwave-wheels` - Audio modulation (from ggwave project)
- `numpy` - Numerical computing

Monitor for:
- CVE announcements from NIST
- GitHub security advisories
- Dependency alerts

### Export Compliance

This software uses strong cryptography (AES-256, RSA-4096). Some countries restrict export, import, or use of encryption software.

**Your responsibility:** Check local laws before using/distributing SonarLink.

---

## Security Incident Response

### If You Suspect a Breach

1. **Stop using the system** immediately
2. **Gather evidence**:
   - Audit log from `audiologs/sonarlink_audit.log`
   - Any error messages
   - System logs
3. **Report privately** to mariano@peluso.me with:
   - Description of suspicious activity
   - Timeline of events
   - Audit log snippets
   - Your contact information

### If You Lose Your Password

If you encrypt files with a password and forget it:
- **AES-256-GCM**: No recovery without password (by design)
- **RSA-4096**: Recovery possible if private key is backed up

**Prevention:**
- Store passwords in password manager (with master password backup)
- Back up RSA private keys in secure location
- Use passphrases you can remember

---

## Compliance

### Open Source License

SonarLink is released under the MIT License. See [LICENSE](./LICENSE) for full text.

### Standards Compliance

- **NIST FIPS**: Uses FIPS 140-2 validated algorithms (via cryptography library)
- **AES**: FIPS 197 (Advanced Encryption Standard)
- **SHA-256**: FIPS 180-4 (Secure Hash Standard)
- **RSA**: PKCS #1 v2.2 (RSA Cryptography Standard)

### Security Reviews

SonarLink has been:
- ✅ Reviewed for code quality
- ✅ Tested on multiple platforms
- ✅ Verified for cryptographic correctness
- ⏳ Awaiting community security audit

Researchers interested in security audit: please contact us!

---

## Additional Resources

### Documentation
- [README.md](README.md) - Overview and quick start
- [QUICKSTART.md](QUICKSTART.md) - 5-minute guide
- [INSTALL.md](INSTALL.md) - Installation for all platforms
- [CHANGELOG.md](CHANGELOG.md) - What's new in v2.0

### Cryptography References
- [NIST Special Publications](https://csrc.nist.gov/)
- [Python Cryptography Library Docs](https://cryptography.io/)
- [RFC 3394 - AES Key Wrap](https://tools.ietf.org/html/rfc3394)
- [RFC 3610 - AES-CCM](https://tools.ietf.org/html/rfc3610)

### GPG/PGP Resources
- [GNU Privacy Guard Manual](https://www.gnupg.org/documentation/)
- [OpenPGP RFC 4880](https://tools.ietf.org/html/rfc4880)
- [Keybase](https://keybase.io/) - Key verification service

### Security Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Institute Top 25](https://www.sans.org/top25-software-errors/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

---

## Updates & Announcements

Security updates and announcements are posted on:

1. **GitHub Releases** - New versions and security patches
2. **Repository Security Advisories** - Vulnerability disclosures
3. **Commit Messages** - Look for `[SECURITY]` prefix

**Recommended:** Watch this repository on GitHub for notifications.

---

## Version History

| Version | Release Date | Security Status |
|---------|--------------|-----------------|
| v2.0 | December 2025 | ✅ Current (AES-256-GCM, RSA-4096) |
| v1.0 | October 2025 | ⚠️ Legacy (AES-256-CFB, RSA-2048) |

**v1.0 users:** Upgrade to v2.0 for significantly stronger cryptography and bug fixes.

---

## Contact

**Security Issues:** mariano@peluso.me  
**General Questions:** Open an issue on GitHub  
**Donations (Lightning):** See Credits section in application

---

**Last Updated:** December 2025  
**SonarLink Version:** v2.0  
**Policy Version:** 2.0  

*This security policy is subject to change. Check GitHub for latest version.*
