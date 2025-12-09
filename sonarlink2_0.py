#!/usr/bin/env python3
"""
SonarLink v2.0: Send and receive messages and files via ggwave
- Audio frequency 48000 Hz
- Gzip compression
- Optional AES-256-GCM or RSA-4096 encryption (FSS1 format)
- PBKDF2 key derivation
- Encrypted files saved locally before transmission
"""

import os, sys, time, base64, gzip, hashlib, struct, datetime, traceback, threading, getpass, random, secrets, queue
from contextlib import contextmanager

os.environ['ALSA_CARD'] = 'default'
os.environ['JACK_NO_AUDIO_SYNC'] = '1'

try:
    from ctypes import *
    ERROR_HANDLER_FUNC = CFUNCTYPE(None, c_char_p, c_int, c_char_p, c_int, c_char_p)
    def py_error_handler(filename, line, function, err, fmt):
        pass
    c_error_handler = ERROR_HANDLER_FUNC(py_error_handler)
    try:
        asound = cdll.LoadLibrary('libasound.so.2')
        asound.snd_lib_error_set_handler(c_error_handler)
    except (OSError, AttributeError):
        pass
except Exception:
    pass
@contextmanager
def _suppress_import_warnings():
    """Suppress C library warnings only during specific imports"""
    try:
        null_fd = os.open(os.devnull, os.O_RDWR)
        saved_stdout = os.dup(1)
        saved_stderr = os.dup(2)
        os.dup2(null_fd, 1)
        os.dup2(null_fd, 2)
        os.close(null_fd)
        yield
    finally:
        try:
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)
            os.close(saved_stdout)
            os.close(saved_stderr)
        except OSError:
            pass

try:
    with _suppress_import_warnings():
        import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

try:
    import pyaudio
except ImportError:
    print("Error: install pyaudio (pip3 install pyaudio)")
    sys.exit(1)

try:
    import ggwave
except ImportError:
    print("Error: install ggwave (pip3 install ggwave-wheels)")
    sys.exit(1)

import numpy as np

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Cryptography not available: install cryptography")
    HAS_CRYPTO = False
else:
    HAS_CRYPTO = True

SAMPLE_RATE = 48000
CHUNK_SIZE = 4096
VOLUME = 80
PROTOCOL_ID = 1  # GGWAVE_PROTOCOL_AUDIBLE_FAST
MAX_FILE_SIZE = 10 * 1024  # 10 KB limit (messages, keys, passwords)
GGWAVE_MAX_BYTES = 120  # Maximum bytes per ggwave transmission

# FSS1 Encryption
PBKDF2_ITERATIONS = 600000
FSS1_MAGIC = b"FSS1"
FSS1_VERSION = 1
MIN_ENCRYPTED_SIZE = 32

# Directories
# NOTE: For PyInstaller --onefile, use sys.executable to get the exe location
# - With Python: os.path.abspath(__file__) points to the .py file
# - With PyInstaller: sys.executable points to the .exe file
# This ensures folders are always created in the same directory as the program
if getattr(sys, 'frozen', False):
    # Running as exe (PyInstaller)
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running as .py script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'audiologs')
LOG_FILE = os.path.join(LOG_DIR, 'sonarlink_audit.log')
RECEIVED_DIR = os.path.join(BASE_DIR, 'audio_received')
SEND_DIR = os.path.join(BASE_DIR, 'audio_send')

def color_success(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_error(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_warning(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_info(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def color_bright(text):
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def clear_screen():
    # Use ANSI codes that work reliably with PyInstaller exe on Windows
    print('\033[2J\033[H', end='', flush=True)
    # Fallback to os.system for older terminals
    if os.name == 'nt':
        try:
            os.system('cls')
        except:
            pass

def display_header():
    print("=" * 70)
    print(color_bright("         🔊 SonarLink v2.0 - Audio-Based File Transfer 🔊"))
    print("=" * 70)

@contextmanager
def suppress_output():
    """Suppress stdout and stderr at file descriptor level (for C libraries)"""
    try:
        old_stdout = os.dup(1)
        old_stderr = os.dup(2)
        null_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_fd, 1)
        os.dup2(null_fd, 2)
        os.close(null_fd)
        yield
    finally:
        try:
            os.dup2(old_stdout, 1)
            os.dup2(old_stderr, 2)
            os.close(old_stdout)
            os.close(old_stderr)
        except OSError:
            pass

def ensure_log_dir():
    """Create log directory with restricted permissions"""
    try:
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        os.chmod(LOG_DIR, 0o700)
    except Exception as e:
        print(color_warning(f"⚠️  Log directory error: {e}"))

def ensure_received_dir():
    """Create received files directory"""
    try:
        os.makedirs(RECEIVED_DIR, mode=0o700, exist_ok=True)
        os.chmod(RECEIVED_DIR, 0o700)
    except Exception as e:
        print(color_warning(f"⚠️  Received directory error: {e}"))

def ensure_send_dir():
    """Create send files directory"""
    try:
        os.makedirs(SEND_DIR, mode=0o700, exist_ok=True)
        os.chmod(SEND_DIR, 0o700)
    except Exception as e:
        print(color_warning(f"⚠️  Send directory error: {e}"))

def log_operation(operation: str, filename: str, method: str, status: str, additional: str = "", error: str = ""):
    """Log file operations"""
    ensure_log_dir()
    try:
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] {operation:15} | file: {filename:40} | method: {method:10} | status: {status:10}"
        if additional:
            log_entry += f" | {additional}"
        if error:
            log_entry += f" | error: {error}"
        
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry + '\n')
            f.flush()
            try:
                os.fsync(f.fileno())
            except (AttributeError, OSError):
                pass
        try:
            os.chmod(LOG_FILE, 0o600)
        except (AttributeError, OSError):
            pass
    except Exception as e:
        print(color_warning(f"⚠️  Audit log error: {e}"))

def log_exception(operation: str, filename: str, method: str, exception: Exception):
    """Log exceptions"""
    tb_str = traceback.format_exc()[:500]
    log_operation(operation, filename, method, "FAILED", error=str(exception))

def get_audit_log() -> str:
    """Get audit log content"""
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                return f.read()
    except Exception as e:
        print(color_warning(f"⚠️  Cannot read log: {e}"))
    return ""

def clean_path(path: str) -> str:
    """Remove quotes from drag&drop paths (Windows compatibility)"""
    if not path:
        return path
    path = path.strip().strip('"\'').replace('"', '').replace("'", '')
    return path

def calculate_file_hash(data: bytes) -> str:
    """Calculate SHA256 hash of data"""
    return hashlib.sha256(data).hexdigest()

def safe_filename(name: str) -> str:
    r"""Sanitize filename to prevent path traversal attacks
    
    - Removes all path separators (/ and \)
    - Whitelists only alphanumeric, dots, dashes, underscores
    - Returns basename only
    - Falls back to 'file' if name becomes empty
    """
    import re
    # Keep only basename, remove any path separators
    name = os.path.basename(name) if name else ""
    # Whitelist safe characters: letters, digits, dot, dash, underscore
    name = re.sub(r'[^A-Za-z0-9._-]', '_', name)
    if not name or name.startswith('.'):  # Also prevent hidden files
        name = "file"
    return name

def validate_received_path(final_path: str, allowed_dir: str) -> bool:
    """Validate that final_path stays within allowed_dir
    
    Uses absolute path resolution to prevent symlink attacks.
    Returns True if path is safe, False otherwise.
    """
    try:
        final_abs = os.path.abspath(final_path)
        allowed_abs = os.path.abspath(allowed_dir)
        # Ensure the path stays under allowed_dir
        return final_abs.startswith(allowed_abs + os.sep)
    except (OSError, ValueError):
        return False

def validate_password_strength(password: str) -> tuple:
    """
    Validate password strength for AES encryption
    Returns: (is_valid: bool, message: str)
    """
    if not password:
        return False, "Password cannot be empty"
    if len(password) < 8:
        return False, "Password too short (minimum 8 characters)"
    if len(password) > 128:
        return False, "Password too long (maximum 128 characters)"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    score = sum([has_upper, has_lower, has_digit, has_special])
    
    if score < 2:
        return False, "Password too weak (need at least 2 of: uppercase, lowercase, digit, special char)"
    return True, "Password strength: OK"

def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Derive AES key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def prepare_waveform(message: str):
    if not isinstance(message, str):
        message = message.decode('utf-8', errors='ignore')
    raw = ggwave.encode(message, protocolId=PROTOCOL_ID, volume=VOLUME)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    arr = np.asarray(raw, dtype=np.float32).flatten()
    return arr.tobytes()

def tx_message(waveform):
    with suppress_output():
        p = pyaudio.PyAudio()
    try:
        stream = p.open(format=pyaudio.paFloat32, channels=1,
                        rate=SAMPLE_RATE, output=True,
                        frames_per_buffer=CHUNK_SIZE)
        bytes_per_frame = 4
        chunk_bytes = CHUNK_SIZE * bytes_per_frame
        for i in range(0, len(waveform), chunk_bytes):
            stream.write(waveform[i:i+chunk_bytes])
            time.sleep(0.05)
        stream.stop_stream()
        stream.close()
    finally:
        p.terminate()

def aes_encrypt_fss1(data: bytes, password: str) -> bytes:
    """Encrypt with AES-256-GCM using PBKDF2 (FSS1 format for files)"""
    file_hash = calculate_file_hash(data)
    key, salt = derive_key_from_password(password)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, data, None)
    hash_bytes = bytes.fromhex(file_hash)
    
    magic = FSS1_MAGIC
    version = struct.pack('>B', FSS1_VERSION)
    result = magic + version + struct.pack('>I', len(hash_bytes)) + hash_bytes + salt + nonce + ciphertext
    return result

def aes_encrypt_chat(plaintext: str, password: str) -> bytes:
    """Encrypt text message with AES-256-GCM (optimized for chat)
    
    Uses GZIP compression for efficient transmission over audio
    Structure: salt (16) + nonce (12) + ciphertext + authtag
    Total overhead: ~28 bytes (vs 89 bytes with FSS1)
    
    Args:
        plaintext: message text
        password: 8-digit token
    
    Returns:
        encrypted bytes ready for Base64 encoding
    """
    # Compress plaintext with gzip
    compressed = gzip.compress(plaintext.encode("utf-8"), compresslevel=6)
    
    # Derive key from password (token)
    salt = os.urandom(16)
    key, _ = derive_key_from_password(password, salt)
    
    # Encrypt with AES-256-GCM
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, compressed, None)
    
    # Return: salt + nonce + ciphertext (no FSS1 overhead)
    return salt + nonce + ciphertext

def aes_decrypt_chat(encrypted_data: bytes, password: str) -> str:
    """Decrypt text message from AES-256-GCM
    
    Expects: salt (16) + nonce (12) + ciphertext + authtag
    
    Args:
        encrypted_data: encrypted bytes
        password: 8-digit token
    
    Returns:
        decompressed plaintext string
    """
    if len(encrypted_data) < 40:  # 16 (salt) + 12 (nonce) + 12 (min ciphertext)
        raise ValueError("Invalid encrypted data (too short)")
    
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    # Derive key from password
    key, _ = derive_key_from_password(password, salt)
    
    # Decrypt with AES-256-GCM
    cipher = AESGCM(key)
    try:
        compressed = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: wrong token or corrupted message")
    
    # Decompress with gzip
    try:
        plaintext = gzip.decompress(compressed).decode("utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Decompression failed: corrupted message")
    
    return plaintext

def aes_decrypt_fss1(encrypted_data: bytes, password: str) -> tuple:
    """Decrypt AES-256-GCM encrypted data (FSS1 format)
    Returns: (plaintext: bytes, computed_hash: str)"""
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError("Invalid encrypted data (too short)")

    if not encrypted_data.startswith(FSS1_MAGIC):
        raise ValueError("Invalid file format - not FSS1")
    
    version = encrypted_data[4]
    if version != FSS1_VERSION:
        raise ValueError(f"Unsupported version: {version}")

    hash_length = struct.unpack('>I', encrypted_data[5:9])[0]
    if hash_length != 32:
        raise ValueError(f"Invalid hash length: {hash_length}")
    
    min_required = 5 + 4 + hash_length + 16 + 12 + 1
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (too short)")
    
    hash_bytes = encrypted_data[9:9+hash_length]
    salt = encrypted_data[9+hash_length:9+hash_length+16]
    nonce = encrypted_data[9+hash_length+16:9+hash_length+28]
    ciphertext = encrypted_data[9+hash_length+28:]

    key, _ = derive_key_from_password(password, salt)
    
    cipher = AESGCM(key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: wrong password or corrupted file")

    # Verify SHA256 hash
    computed_hash = calculate_file_hash(plaintext)
    stored_hash = hash_bytes.hex()
    if computed_hash != stored_hash:
        raise ValueError("Hash verification failed: file corrupted or tampered")

    return plaintext, computed_hash

# RSA-4096 encryption (FSS1 hybrid)
def rsa_encrypt_fss1(data: bytes, public_key_pem: str) -> bytes:
    """Encrypt with RSA-4096 hybrid (FSS1 format)"""
    file_hash = calculate_file_hash(data)
    aes_key = os.urandom(32)
    salt = os.urandom(16)
    nonce = os.urandom(12)

    cipher = AESGCM(aes_key)
    ciphertext = cipher.encrypt(nonce, data, None)

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    hash_bytes = bytes.fromhex(file_hash)
    key_len = len(encrypted_aes_key).to_bytes(2, 'big')
    
    magic = FSS1_MAGIC
    version = struct.pack('>B', FSS1_VERSION)
    result = (magic + version + struct.pack('>I', len(hash_bytes)) + hash_bytes + 
              key_len + encrypted_aes_key + salt + nonce + ciphertext)
    return result

def rsa_decrypt_fss1(encrypted_data: bytes, private_key_pem: str, private_key_password: str = None) -> tuple:
    """Decrypt RSA-4096 hybrid (FSS1 format)
    Returns: (plaintext: bytes, computed_hash: str)"""
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError("Invalid encrypted data (too short)")

    if not encrypted_data.startswith(FSS1_MAGIC):
        raise ValueError("Invalid file format - not FSS1")
    
    version = encrypted_data[4]
    if version != FSS1_VERSION:
        raise ValueError(f"Unsupported version: {version}")

    hash_length = struct.unpack('>I', encrypted_data[5:9])[0]
    if hash_length != 32:
        raise ValueError(f"Invalid hash length: {hash_length}")
    
    try:
        key_len = int.from_bytes(encrypted_data[9+hash_length:9+hash_length+2], 'big')
    except (struct.error, IndexError):
        raise ValueError("Cannot read key length")
    
    if key_len < 100 or key_len > 1024:
        raise ValueError(f"Invalid RSA key size: {key_len}")
    
    min_required = 5 + 4 + hash_length + 2 + key_len + 16 + 12 + 1
    if len(encrypted_data) < min_required:
        raise ValueError(f"Invalid format (too short)")
    
    encrypted_aes_key = encrypted_data[9+hash_length+2:9+hash_length+2+key_len]
    salt = encrypted_data[9+hash_length+2+key_len:9+hash_length+2+key_len+16]
    nonce = encrypted_data[9+hash_length+2+key_len+16:9+hash_length+2+key_len+28]
    ciphertext = encrypted_data[9+hash_length+2+key_len+28:]

    try:
        if private_key_password:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                private_key_password.encode('utf-8')
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                None
            )
        
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {str(e)}")

    cipher = AESGCM(aes_key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"AES decryption failed: {str(e)}")

    # Verify SHA256 hash
    computed_hash = calculate_file_hash(plaintext)
    stored_hash = encrypted_data[9:9+hash_length].hex()
    if computed_hash != stored_hash:
        raise ValueError("Hash verification failed: file corrupted or tampered")

    return plaintext, computed_hash

def listen_for_messages(stop_event, received_messages, chat_token=None, chat_mode="OPEN", sample_rate=48000, chunk_size=4096, last_sent_state=None):
    """Listen for incoming messages in background thread"""
    if last_sent_state is None:
        last_sent_state = {'last_sent_time': 0}
    p = None
    stream = None
    instance = None
    
    try:
        try:
            with suppress_output():
                p = pyaudio.PyAudio()
                stream = p.open(format=pyaudio.paFloat32, channels=1,
                                rate=sample_rate, input=True,
                                frames_per_buffer=chunk_size,
                                input_device_index=None)
            instance = ggwave.init()
        except Exception as init_error:
            return
        
        while not stop_event.is_set():
            try:
                data = stream.read(chunk_size, exception_on_overflow=False)
                with suppress_output():
                    res = ggwave.decode(instance, data)
                
                if res:
                    text = res.decode("utf-8", errors="ignore")
                    if text and not text.startswith("FILE:") and text != "ENDFILE":
                        if chat_mode == "PRIVATE" and chat_token:
                            try:
                                encrypted = base64.b64decode(text)
                                display_msg = aes_decrypt_chat(encrypted, chat_token)
                                
                                if time.time() - last_sent_state.get('last_sent_time', 0) < 8:
                                    pass
                                else:
                                    received_messages.append(display_msg)
                            except Exception:
                                pass
                        else:
                            if time.time() - last_sent_state.get('last_sent_time', 0) < 3:
                                pass
                            else:
                                display_msg = text
                                received_messages.append(display_msg)
            except IOError:
                continue
            except Exception as e:
                try:
                    log_operation("LISTENER", "ggwave", "decode", "ERROR", error=str(e)[:100])
                except:
                    pass
                continue
    
    finally:
        try:
            if stream:
                try:
                    stream.stop_stream()
                except:
                    pass
                try:
                    stream.close()
                except:
                    pass
            if p:
                try:
                    p.terminate()
                except:
                    pass
            if instance:
                try:
                    ggwave.free(instance)
                except:
                    pass
        except Exception:
            pass

def send_text():
    clear_screen()
    display_header()
    print("\n" + "=" * 70)
    print(color_bright("                      💬 CHAT MODE"))
    print("=" * 70 + "")

    
    print(f"{color_bright('[1]')} 🔓 Open Chat (no encryption)")
    print(f"{color_bright('[2]')} 🔐 Generate Token (create private chat)")
    print(f"{color_bright('[3]')} 🔐 Use Token (join private chat)")
    print()
    
    try:
        choice = input(color_info("Choice (1-3): ")).strip()
    except KeyboardInterrupt:
        print("\n⏹️ Operation cancelled.")
        return
    
    chat_mode = None
    chat_token = None
    
    if choice == "1":
        chat_mode = "OPEN"
        print(f"\n{color_success('🔓 Open Chat Mode - No Encryption')}")
        print(f"\n{color_warning('⚠️  PRIVACY WARNING: Messages are NOT encrypted!')}")
        print(f"   Anyone with a receiver listening on this frequency can read them.")
        print(f"   Only use Open Chat over a secure/isolated audio channel.")
        
        try:
            confirm = input(color_info("Press Enter to continue: ")).strip()
        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return

    elif choice == "2":
        chat_mode = "PRIVATE"
        chat_token = str(random.randint(10000000, 99999999))
        print(f"\n{color_success('🔐 Private Chat Mode - Generated Token')}")
        print(f"\n{color_bright('Token: ')}{color_bright(chat_token)}")

        print(f"{color_warning('⚠️  Share this token with the other party')}")
        print(f"{color_warning('⚠️  Token expires when chat ends')}")
        print(f"{color_warning('⚠️  They should select option [3] to use this token')}")

        try:
            confirm = input(color_info("Press Enter once token has been shared and ready to chat: ")).strip()
        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return
    
    elif choice == "3":
        chat_mode = "PRIVATE"
        try:
            chat_token = input(color_info("Enter 8-digit token: ")).strip()
            if len(chat_token) != 8:
                print(color_error("❌ Invalid token. Must be exactly 8 digits.")
)
                return
            if not chat_token.isdigit():
                print(color_error("❌ Invalid token. Must be numeric digits (0-9) only.")
)
                return
            print(f"\n{color_success('🔐 Private Chat Mode - Using Token')}")
            print(f"{color_info('✅ Token validated')}")

        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return
    
    else:
        print(color_error("❌ Invalid choice."))
        return
    
    _run_chat_session(chat_mode, chat_token)


def _input_thread(input_queue, stop_event):
    """Thread that reads user input and puts it in a queue"""
    while not stop_event.is_set():
        try:
            user_input = input(color_info("📝 Message: "))
            input_queue.put(user_input)
        except EOFError:
            # EOF or Ctrl+D
            break
        except KeyboardInterrupt:
            # Ctrl+C in input - put special signal
            input_queue.put("__CTRL_C__")
        except Exception as e:
            pass


def _run_chat_session(chat_mode, chat_token=None):
    """Run the actual chat session"""
    clear_screen()
    display_header()
    print("\n" + "=" * 70)
    mode_display = "🔓 OPEN CHAT" if chat_mode == "OPEN" else "🔐 PRIVATE CHAT"
    print(color_bright(f"                 {mode_display}"))
    print("=" * 70)
    print(color_info("Type messages and press Enter to send."))
    print(color_info("Listen for incoming messages while typing."))
    print(color_info("Type 'exit' to quit and save."))
    print("=" * 70 + "")

    
    sent_messages = []
    received_messages = []
    message_count = 0
    last_sent_state = {'last_sent_time': 0}  # For echo detection
    messages_printed = 0  # Track how many messages we've already printed
    
    # Log chat start
    log_operation("CHAT_SESSION", "chat_start", chat_mode, "STARTED", additional=f"token: {'*' * 8 if chat_token else 'none'}")
    
    # Start listener thread (pass token for decryption)
    stop_event = threading.Event()
    listener_thread = threading.Thread(
        target=listen_for_messages, 
        args=(stop_event, received_messages, chat_token, chat_mode), 
        kwargs={'last_sent_state': last_sent_state},
        daemon=True
    )
    listener_thread.start()
    
    # Start input thread (non-blocking input)
    input_queue = queue.Queue()
    input_thread = threading.Thread(
        target=_input_thread,
        args=(input_queue, stop_event),
        daemon=True
    )
    input_thread.start()
    
    try:
        while True:
            # Print any new received messages
            while messages_printed < len(received_messages):
                print(f"\n{color_info('💬 Received: ')}{received_messages[messages_printed]}")
                messages_printed += 1
                print(color_info("📝 Message: "), end="", flush=True)
            
            # Check for user input (non-blocking with 100ms timeout)
            try:
                msg = input_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            
            msg = msg.strip()
            
            if msg == "__CTRL_C__":
                print(color_warning("\n⏹️ Type 'exit' to quit chat."))
                print(color_info("📝 Message: "), end="", flush=True)
                continue
            
            if msg.lower() == "exit":
                stop_event.set()
                listener_thread.join(timeout=5)
                print()
                break
            
            if not msg:
                print(color_warning("⚠️  Empty message, try again."))
                print(color_info("📝 Message: "), end="", flush=True)
                continue
            
            try:
                last_sent_state['last_sent_time'] = time.time()
                
                if chat_mode == "PRIVATE" and chat_token:
                    encrypted = aes_encrypt_chat(msg, chat_token)
                    encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
                    tx_message(prepare_waveform(encrypted_b64))
                else:
                    tx_message(prepare_waveform(msg))
                
                message_count += 1
                sent_messages.append(msg)
                print(color_success(f"✅ Sent"))
            except Exception as e:
                print(color_error(f"❌ Error sending message: {e}"))
            
            print(color_info("📝 Message: "), end="", flush=True)
    
    except KeyboardInterrupt:
        # Ctrl+C - close chat but don't exit program
        print(color_warning("\n⏹️ Chat closed by user."))
        stop_event.set()
        listener_thread.join(timeout=5)
        # Fall through to show summary
    
    except Exception as e:
        print(color_error(f"❌ Error: {e}"))
        stop_event.set()
        listener_thread.join(timeout=5)
        return
    
    # Threads already joined during exit above
    
    # Show conversation summary
    if sent_messages or received_messages:
        print("\n" + "=" * 70)
        print(color_bright("CONVERSATION SUMMARY"))
        print("=" * 70)
        
        if sent_messages:
            print(f"\n{color_info('📤 SENT:')}")
            for i, msg in enumerate(sent_messages, 1):
                print(f"  [{i}] {msg}")
        
        if received_messages:
            print(f"\n{color_info('📥 RECEIVED:')}")
            for i, msg in enumerate(received_messages, 1):
                print(f"  [{i}] {msg}")
        
        print("\n" + "=" * 70 + "")

        
        try:
            save_choice = input(color_info("Save conversation to file? (y/N): ")).strip().lower()
            if save_choice == "y":
                # Create conversation file
                ensure_received_dir()
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                mode_name = "open" if chat_mode == "OPEN" else "private"
                conv_filename = os.path.join(RECEIVED_DIR, f"chat_{mode_name}_{timestamp}.txt")
                
                with open(conv_filename, "w") as f:
                    f.write(f"SonarLink Chat Conversation ({mode_name.upper()})")

                    f.write(f"Timestamp: {datetime.datetime.now().isoformat()}")

                    f.write("=" * 70 + "\n")

                    
                    if sent_messages:
                        f.write("SENT MESSAGES:")

                        f.write("-" * 70 + "")

                        for i, msg in enumerate(sent_messages, 1):
                            f.write(f"[{i}] {msg}")

                        f.write("")

                    
                    if received_messages:
                        f.write("RECEIVED MESSAGES:")

                        f.write("-" * 70 + "")

                        for i, msg in enumerate(received_messages, 1):
                            f.write(f"[{i}] {msg}")

                        f.write("")

                    
                    f.write("=" * 70 + "")

                    f.write(f"Total sent: {len(sent_messages)}")

                    f.write(f"Total received: {len(received_messages)}")

                
                print(color_success(f"✅ Conversation saved: {conv_filename}")
)
                log_operation("CHAT_SESSION", "chat_end", chat_mode, "SUCCESS", additional=f"conversation saved, sent: {len(sent_messages)}, received: {len(received_messages)}")
            else:
                # User chose not to save
                log_operation("CHAT_SESSION", "chat_end", chat_mode, "COMPLETED", additional=f"conversation NOT saved, sent: {len(sent_messages)}, received: {len(received_messages)}")
        except KeyboardInterrupt:
            print(color_warning("\n⏹️ Save cancelled.")
)
            log_operation("CHAT_SESSION", "chat_end", chat_mode, "CANCELLED", additional=f"save cancelled, sent: {len(sent_messages)}, received: {len(received_messages)}")
    else:
        print(color_warning("No messages exchanged.")
)
        log_operation("CHAT_SESSION", "chat_end", chat_mode, "NO_MESSAGES")

# Send file (1 file only, max 100KB)
def select_file_from_send_folder():
    """Select a file from audio_send folder"""
    if not os.path.exists(SEND_DIR):
        print(color_error("❌ audio_send folder not found"))
        input(color_info("Press Enter to go back..."))
        return None
    
    files = [f for f in os.listdir(SEND_DIR) if os.path.isfile(os.path.join(SEND_DIR, f))]
    
    if not files:
        print(f"\n{color_warning('📁 audio_send folder is EMPTY')}")
        print(color_warning("No files to send"))
        input(color_info("Press Enter to go back..."))
        return None
    
    files.sort(key=lambda x: os.path.getmtime(os.path.join(SEND_DIR, x)), reverse=True)
    
    while True:
        print(color_info("\n📁 Files in audio_send:"))
        print("─" * 70)
        for i, f in enumerate(files, 1):
            fsize = os.path.getsize(os.path.join(SEND_DIR, f))
            fmtime = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(SEND_DIR, f))).strftime("%Y-%m-%d %H:%M:%S")
            print(f"  [{i}] {f:40} | {fsize:>8} bytes | {fmtime}")
        back_option = len(files) + 1
        print(f"  [{back_option}] 🔙 Back")
        print("─" * 70)
        
        choice = input(color_info("Select file (number): ")).strip()
        
        if not choice:
            continue
        
        if choice == str(back_option):
            return None
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                selected = os.path.join(SEND_DIR, files[idx])
                print(f"\n✅ Selected: {files[idx]}")
                return selected
            else:
                print(color_error("❌ Invalid selection"))
        except ValueError:
            print(color_error("❌ Enter a valid number"))


def send_file():
    while True:  # Loop per inviare più file
        clear_screen()
        display_header()
        print("\n" + "=" * 70)
        print(color_bright("              SEND MESSAGES, KEYS & CREDENTIALS"))
        print("=" * 70)
        
        print(f"\n{color_warning('⚠️  LIMIT: 10 KB max')}")
        print(f"{color_info('💡 Optimized for: text messages, SSH/GPG/PEM keys, passwords, tokens')}")
        print(f"{color_info('💡 Press Ctrl+C anytime to return to main menu')}")

        # STEP 1: Choose file source
        print(f"\n{color_info('📂 STEP 1: Choose file source')}")
        print("=" * 70)
        print(f"{color_bright('[1]')} 📝 Send new file (insert path)")
        print(f"{color_bright('[2]')} 📁 Send from audio_send folder")
        print(f"{color_bright('[3]')} 🔙 Back to Main Menu")
        
        try:
            source_choice = input(color_info("Choice: ")).strip()
        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return
        
        if not source_choice:
            continue
        
        if source_choice == "3":
            return

        # Initialize fpath
        fpath = None
        
        # Get file path - loop until valid file
        while True:
            try:
                if source_choice == "1":
                    fpath = input(color_info("File path: ")).strip()
                    fpath = clean_path(fpath)
                elif source_choice == "2":
                    fpath = select_file_from_send_folder()
                    if fpath is None:
                        break
                else:
                    print(color_error("❌ Invalid choice"))
                    break
            except KeyboardInterrupt:
                print("\n⏹️ Operation cancelled.")
                return

            if not fpath:
                print(color_error("❌ File path required."))
                continue
                
            if not os.path.exists(fpath):
                print(color_error(f"❌ File not found: {fpath}"))
                print(color_info("Please try again or press Ctrl+C to cancel."))
                continue

            file_size = os.path.getsize(fpath)
            if file_size > MAX_FILE_SIZE:
                file_size_kb = file_size / 1024
                max_size_kb = MAX_FILE_SIZE / 1024
                print(f"\n{color_error('❌ FILE TOO LARGE FOR AUDIO TRANSMISSION')}")
                print(f"   File size: {file_size_kb:.2f} KB")
                print(f"   Maximum:   {max_size_kb:.0f} KB")
                print(f"\n{color_warning('⚠️  SonarLink is optimized for:')}")
                print(f"   • Text messages")
                print(f"   • SSH/GPG/PEM keys")
                print(f"   • Passwords & tokens")
                print(f"   • Small documents")
                print(color_warning("⚠️  Please select a smaller file or press Ctrl+C to cancel."))
                continue
            
            # File is valid, proceed
            break

        # If folder was empty, go back to STEP 1
        if not fpath:
            continue

        # STEP 2: Choose encryption method
        print(f"\n{color_info('🔐 STEP 2: Choose encryption method')}")
        print("=" * 70)
        print(f"   File: {color_bright(os.path.basename(fpath))}")
        print(f"   Size: {file_size} bytes")
        print()
        print(f"{color_bright('[1]')} 📤 Unencrypted")
        print(f"{color_warning('       ⚠️  Anyone listening can intercept and read this file')}")
        print(f"{color_bright('[2]')} 🔐 AES-256-GCM (password)")
        print(f"{color_bright('[3]')} 🔒 RSA-4096 (public key)")

        try:
            choice = input(color_info("Choice (1-3): ")).strip()
        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return
        
        if not choice:
            continue
        
        if choice not in ["1", "2", "3"]:
            print(color_error("❌ Invalid choice"))
            continue

        # Read file
        with open(fpath, "rb") as f:
            content = f.read()

        if choice == "1":
            # UNENCRYPTED: File → Gzip → B64
            try:
                content_gzipped = gzip.compress(content)
                encoded = base64.b64encode(content_gzipped).decode("ascii")
                
                # CONFIRMATION STEP before transmission
                print(f"\n{color_bright('FILE READY FOR TRANSMISSION')}")
                print(f"   Filename: {color_info(os.path.basename(fpath))}")
                print(f"   Original size: {file_size} bytes")
                print(f"   Compressed size: {len(content_gzipped)} bytes")
                print(f"   Encoded size: {len(encoded)} chars")
                print(f"   Encryption: {color_warning('NONE (unencrypted)')}")
                print(f"\n{color_warning('⚠️  PRIVACY WARNING: This file is NOT encrypted!')}")
                print(f"   Anyone with a receiver listening on this frequency can intercept it.")
                print(f"   Only send unencrypted files over a secure/isolated audio channel.")
                print(f"\n{color_warning('⚠️  IMPORTANT: Make sure the receiver has started listening!')}")
                print(f"   The receiver should be in Menu 3 (Receive) before you proceed.")
                print("=" * 70)
                
                try:
                    confirm = input(color_info("Start transmission? (y/N): ")).strip().lower()
                    if confirm != "y":
                        print("❌ Transmission cancelled by user.")
                        continue
                except KeyboardInterrupt:
                    print("\n⏹️ Operation cancelled.")
                    return
                
                print(f"\n{color_bright('🔊 TRANSMITTING...')}")
                print("=" * 70)
                
                tx_message(prepare_waveform(f"FILE:{os.path.basename(fpath)}"))
                time.sleep(3)
                chunk_count = 0
                total_chunks = (len(encoded) + GGWAVE_MAX_BYTES - 1) // GGWAVE_MAX_BYTES
                print(f"   📤 Sending {total_chunks} chunks of max {GGWAVE_MAX_BYTES} chars...")
                for i in range(0, len(encoded), GGWAVE_MAX_BYTES):
                    tx_message(prepare_waveform(encoded[i:i+GGWAVE_MAX_BYTES]))
                    time.sleep(1.0)
                    chunk_count += 1
                    print(f"   📊 Sent chunk {chunk_count}/{total_chunks}", end="\r")
                print()
                time.sleep(2)
                tx_message(prepare_waveform("ENDFILE"))
                time.sleep(3)
                print(f"✅ File sent: {os.path.basename(fpath)}")
                log_operation("SEND_FILE", os.path.basename(fpath), "unencrypted", "SUCCESS", additional=f"size: {file_size} bytes")
            except KeyboardInterrupt:
                print("\n⏹️ Transmission interrupted.")
                log_operation("SEND_FILE", os.path.basename(fpath), "unencrypted", "INTERRUPTED")
            except Exception as e:
                print(f"❌ Error: {e}")
                log_exception("SEND_FILE", os.path.basename(fpath), "unencrypted", e)

        elif choice == "2":
            # AES ENCRYPTION (FSS1): File → Encrypt FSS1 → B64
            try:
                # Show password requirements
                print(f"\n{color_info('🔐 PASSWORD REQUIREMENTS:')}")
                print("  • Minimum 8 characters")
                print("  • At least 2 of: uppercase, lowercase, digit, special char")

                
                # Get and validate password with confirmation
                password = None
                max_attempts = 3
                attempt = 0
                
                while not password:
                    attempt += 1
                    
                    # First password input (hidden)
                    pwd1 = getpass.getpass(color_info("AES password: "))
                    
                    if not pwd1:
                        print(color_error("❌ Password required."))
                        continue
                    
                    # Validate password strength
                    is_valid, message = validate_password_strength(pwd1)
                    if not is_valid:
                        print(color_error(f"❌ {message}"))
                        continue
                    
                    # Confirm password (hidden)
                    pwd2 = getpass.getpass(color_info("Confirm password: "))
                    
                    if pwd1 != pwd2:
                        print(color_error("❌ Passwords do not match."))
                        if attempt < max_attempts:
                            print(color_warning(f"⚠️  {max_attempts - attempt} attempt(s) remaining")
)
                        else:
                            print("\n" + "=" * 70)
                            try:
                                retry = input(color_info("Exit to menu or try another file? (E)xit / (T)ry another file: ")).strip().lower()
                                if retry == "e":
                                    return
                                elif retry == "t":
                                    attempt = 0
                                    continue
                                else:
                                    print(color_error("❌ Invalid option. Returning to menu."))
                                    return
                            except KeyboardInterrupt:
                                print("\n⏹️ Operation cancelled.")
                                return
                        continue
                    
                    # Passwords match and are valid
                    password = pwd1
                    print(color_success(f"✅ Password strength: OK")
)
                
                # Encrypt file (not gzipped) with FSS1 format
                encrypted = aes_encrypt_fss1(content, password)
                encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
                
                # Save encrypted file locally in audio_send/ with timestamp
                ensure_send_dir()
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                base_name = os.path.splitext(os.path.basename(fpath))[0]
                enc_fname = os.path.join(SEND_DIR, f"{base_name}_{timestamp}.aes")
                with open(enc_fname, "wb") as f:
                    f.write(encrypted)
                
                # Verify file was saved
                if os.path.exists(enc_fname):
                    print(f"\n{color_success('✅ FILE ENCRYPTED & SAVED')}")
                    print(f"   Location: {enc_fname}")
                    print(f"   Size: {os.path.getsize(enc_fname)} bytes")

                    log_operation("SEND_FILE", os.path.basename(fpath), "AES", "ENCRYPTED", additional=f"encrypted: {enc_fname}")
                else:
                    print(color_error(f"❌ Failed to save encrypted file"))
                    continue
                
                # Send (using filename with timestamp)
                # CONFIRMATION STEP before transmission
                print(f"\n{color_bright('FILE READY FOR TRANSMISSION')}")
                print(f"   Filename: {color_info(os.path.basename(enc_fname))}")
                print(f"   Encrypted size: {os.path.getsize(enc_fname)} bytes")
                print(f"   Encoded size: {len(encrypted_b64)} chars")
                print(f"   Encryption: {color_info('AES-256-GCM + PBKDF2')}")
                print(f"\n{color_warning('⚠️  IMPORTANT: Make sure the receiver has started listening!')}")
                print(f"   The receiver should be in Menu 3 (Receive) before you proceed.")
                print("=" * 70)
                
                try:
                    confirm = input(color_info("Start transmission? (y/N): ")).strip().lower()
                    if confirm != "y":
                        print("❌ Transmission cancelled by user.")
                        continue
                except KeyboardInterrupt:
                    print("\n⏹️ Operation cancelled.")
                    return
                
                print(f"\n{color_bright('🔊 TRANSMITTING...')}")
                print("=" * 70)
                
                tx_message(prepare_waveform(f"FILE:{os.path.basename(enc_fname)}"))
                time.sleep(3)
                chunk_count = 0
                total_chunks = (len(encrypted_b64) + GGWAVE_MAX_BYTES - 1) // GGWAVE_MAX_BYTES
                print(f"   📤 Sending {total_chunks} chunks...")
                for i in range(0, len(encrypted_b64), GGWAVE_MAX_BYTES):
                    tx_message(prepare_waveform(encrypted_b64[i:i+GGWAVE_MAX_BYTES]))
                    time.sleep(1.0)
                    chunk_count += 1
                    print(f"   📊 Sent chunk {chunk_count}/{total_chunks}", end="\r")
                print()
                time.sleep(2)
                tx_message(prepare_waveform("ENDFILE"))
                time.sleep(3)
                print(f"✅ File sent (AES): {os.path.basename(enc_fname)}")
                log_operation("SEND_FILE", os.path.basename(fpath), "AES", "SUCCESS", additional=f"size: {file_size} bytes")
            except KeyboardInterrupt:
                print("\n⏹️ Transmission interrupted.")
                log_operation("SEND_FILE", os.path.basename(fpath), "AES", "INTERRUPTED")
            except Exception as e:
                print(f"❌ Encryption error: {e}")
                log_exception("SEND_FILE", os.path.basename(fpath), "AES", e)

        elif choice == "3":
            # RSA ENCRYPTION (FSS1): File → Encrypt FSS1 → B64
            try:
                pubkey_path = input(color_info("Public key PEM file: ")).strip()
                pubkey_path = clean_path(pubkey_path)
                if not os.path.exists(pubkey_path):
                    print("❌ Public key file not found.")
                    continue
                
                with open(pubkey_path, "r") as f:
                    pubkey_pem = f.read()
                
                # Encrypt file (not gzipped) with FSS1 format
                encrypted = rsa_encrypt_fss1(content, pubkey_pem)
                encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
                
                # Save encrypted file locally in audio_send/ with timestamp
                ensure_send_dir()
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                base_name = os.path.splitext(os.path.basename(fpath))[0]
                enc_fname = os.path.join(SEND_DIR, f"{base_name}_{timestamp}.rsa")
                with open(enc_fname, "wb") as f:
                    f.write(encrypted)
                
                # Verify file was saved
                if os.path.exists(enc_fname):
                    print(f"\n{color_success('✅ FILE ENCRYPTED & SAVED')}")
                    print(f"   Location: {enc_fname}")
                    print(f"   Size: {os.path.getsize(enc_fname)} bytes")

                    log_operation("SEND_FILE", os.path.basename(fpath), "RSA", "ENCRYPTED", additional=f"encrypted: {enc_fname}")
                else:
                    print(color_error(f"❌ Failed to save encrypted file"))
                    continue
                
                # Send (using filename with timestamp)
                # CONFIRMATION STEP before transmission
                print(f"\n{color_bright('FILE READY FOR TRANSMISSION')}")
                print(f"   Filename: {color_info(os.path.basename(enc_fname))}")
                print(f"   Encrypted size: {os.path.getsize(enc_fname)} bytes")
                print(f"   Encoded size: {len(encrypted_b64)} chars")
                print(f"   Encryption: {color_info('RSA-4096 hybrid encryption')}")
                print(f"\n{color_warning('⚠️  IMPORTANT: Make sure the receiver has started listening!')}")
                print(f"   The receiver should be in Menu 3 (Receive) before you proceed.")
                print("=" * 70)
                
                try:
                    confirm = input(color_info("Start transmission? (y/N): ")).strip().lower()
                    if confirm != "y":
                        print("❌ Transmission cancelled by user.")
                        continue
                except KeyboardInterrupt:
                    print("\n⏹️ Operation cancelled.")
                    return
                
                print(f"\n{color_bright('🔊 TRANSMITTING...')}")
                print("=" * 70)
                
                tx_message(prepare_waveform(f"FILE:{os.path.basename(enc_fname)}"))
                time.sleep(3)
                chunk_count = 0
                total_chunks = (len(encrypted_b64) + GGWAVE_MAX_BYTES - 1) // GGWAVE_MAX_BYTES
                print(f"   📤 Sending {total_chunks} chunks...")
                for i in range(0, len(encrypted_b64), GGWAVE_MAX_BYTES):
                    tx_message(prepare_waveform(encrypted_b64[i:i+GGWAVE_MAX_BYTES]))
                    time.sleep(1.0)
                    chunk_count += 1
                    print(f"   📊 Sent chunk {chunk_count}/{total_chunks}", end="\r")
                print()
                time.sleep(2)
                tx_message(prepare_waveform("ENDFILE"))
                time.sleep(3)
                print(f"✅ File sent (RSA): {os.path.basename(enc_fname)}")
                log_operation("SEND_FILE", os.path.basename(fpath), "RSA", "SUCCESS", additional=f"size: {file_size} bytes")
            except KeyboardInterrupt:
                print("\n⏹️ Transmission interrupted.")
                log_operation("SEND_FILE", os.path.basename(fpath), "RSA", "INTERRUPTED")
            except Exception as e:
                print(f"❌ Encryption error: {e}")
                log_exception("SEND_FILE", os.path.basename(fpath), "RSA", e)
        else:
            print(color_error("❌ Invalid option."))
            time.sleep(1)
            continue
        
        # Ask to send another file or return to menu
        print("\n" + "=" * 70)
        try:
            again = input(color_info("Send another file? (y/N): ")).strip().lower()
            if again != "y":
                return
        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return

# Receive messages or files
def receive():
    clear_screen()
    display_header()
    print("\n" + "=" * 70)
    print(color_bright("                 RECEIVE MESSAGES/FILES"))
    print("=" * 70 + "")

    
    try:
        with suppress_output():
            p = pyaudio.PyAudio()
            stream = p.open(format=pyaudio.paFloat32, channels=1,
                            rate=SAMPLE_RATE, input=True,
                        frames_per_buffer=CHUNK_SIZE,
                        input_device_index=None)
    except Exception as e:
        print(color_error(f"❌ Audio error: {e}"))
        return

    instance = ggwave.init()
    print(color_info(f"🎧 Listening at {SAMPLE_RATE} Hz... Ctrl+C to stop.")
)

    buffer = ""
    filename = None
    is_file = False
    files_received = 0
    last_message_time = time.time()
    text_messages = []
    chunks_received = 0

    try:
        while True:
            try:
                data = stream.read(CHUNK_SIZE, exception_on_overflow=False)
            except IOError:
                continue

            # Suppress ggwave debug output
            with suppress_output():
                res = ggwave.decode(instance, data)
            
            if res:
                try:
                    text = res.decode("utf-8", errors="ignore")
                    last_message_time = time.time()

                    if text.startswith("FILE:"):
                        if text_messages:
                            print("\n📨 Text messages received:")
                            for msg in text_messages:
                                print(f"  → {msg}")
                            text_messages = []

                        filename = text[5:].strip()
                        buffer = ""
                        is_file = True
                        chunks_received = 0
                        print(f"📥 Receiving file: {filename}")
                        print(f"   Waiting for data chunks...")
                    elif text == "ENDFILE" and is_file:
                        print(f"\n   ✓ Received ENDFILE signal")
                        print(f"   ✓ Total chunks received: {chunks_received}")
                        print(f"   ✓ Total characters: {len(buffer)}")
                        try:
                            content = base64.b64decode(buffer)
                            print(f"   ✓ Base64 decoded: {len(content)} bytes")
                            
                            # Check if file is encrypted (FSS1 format)
                            is_encrypted = filename.endswith(".aes") or filename.endswith(".rsa")
                            
                            if not is_encrypted:
                                # Unencrypted: decompress gzip
                                content = gzip.decompress(content)
                                print(f"   ✓ Decompressed: {len(content)} bytes")
                            else:
                                # Encrypted FSS1: validate magic byte
                                print(f"   ✓ Encrypted FSS1 format detected")
                                if not content.startswith(b"FSS1"):
                                    raise ValueError("Invalid FSS1 format - file corrupted during transmission")
                                print(f"   ✓ FSS1 magic byte verified")
                            
                            # SECURITY FIX: Sanitize filename to prevent path traversal
                            safe_name = safe_filename(filename)
                            ensure_received_dir()
                            output_filename = os.path.join(RECEIVED_DIR, safe_name)
                            
                            # Validate path is within RECEIVED_DIR (symlink attack prevention)
                            if not validate_received_path(output_filename, RECEIVED_DIR):
                                raise ValueError(f"Invalid destination path: {safe_name}")
                            
                            with open(output_filename, "wb") as f:
                                f.write(content)
                            print(f"✅ File received and saved: {output_filename}")
                            method = "AES" if filename.endswith(".aes") else ("RSA" if filename.endswith(".rsa") else "unencrypted")
                            log_operation("RECV_FILE", filename, method, "SUCCESS", additional=f"size: {len(content)} bytes, path: {output_filename}")
                        except gzip.BadGzipFile:
                            print(f"❌ File corrupted during transmission (bad gzip)")
                            print(f"   Expected more data chunks")
                            safe_name = safe_filename(filename)
                            corrupted_name = os.path.join(RECEIVED_DIR, safe_name + ".corrupted")
                            ensure_received_dir()
                            if not validate_received_path(corrupted_name, RECEIVED_DIR):
                                corrupted_name = os.path.join(RECEIVED_DIR, "corrupted_" + str(int(time.time())))
                            with open(corrupted_name, "wb") as f:
                                f.write(base64.b64decode(buffer))
                            print(f"   Saved corrupted data to: {corrupted_name}")
                            log_operation("RECV_FILE", filename, "unencrypted", "CORRUPTED", additional=f"saved to: {corrupted_name}")
                        except ValueError as e:
                            # FSS1 validation error (encrypted file corrupted)
                            print(f"❌ {e}")
                            safe_name = safe_filename(filename)
                            corrupted_name = os.path.join(RECEIVED_DIR, safe_name + ".corrupted")
                            ensure_received_dir()
                            if not validate_received_path(corrupted_name, RECEIVED_DIR):
                                corrupted_name = os.path.join(RECEIVED_DIR, "corrupted_" + str(int(time.time())))
                            with open(corrupted_name, "wb") as f:
                                f.write(content)
                            print(f"   Saved corrupted data to: {corrupted_name}")
                            method = "AES" if filename.endswith(".aes") else "RSA"
                            log_operation("RECV_FILE", filename, method, "CORRUPTED", additional=f"FSS1 validation failed, saved to: {corrupted_name}")
                        except Exception as e:
                            print(f"❌ Error saving file: {e}")
                            log_exception("RECV_FILE", filename, "unencrypted", e)
                        finally:
                            buffer = ""
                            filename = None
                            is_file = False
                            files_received += 1
                            chunks_received = 0
                    elif is_file:
                        buffer += text
                        chunks_received += 1
                        print(f"   📦 Chunk {chunks_received}: {len(text)} chars (total: {len(buffer)})", end="\r")
                    else:
                        text_messages.append(text)
                        print(f"💬 Message: {text}")

                except Exception as e:
                    print(f"❌ Decoding error: {e}")

            if text_messages and (time.time() - last_message_time > 3):
                print(f"\n✅ Received {len(text_messages)} text message(s)")
                text_messages = []

    except KeyboardInterrupt:
        print("\n⏹️ Reception interrupted by user.")
        if text_messages:
            print(f"\n📨 Final text messages received:")
            for msg in text_messages:
                print(f"  → {msg}")
    finally:
        stream.stop_stream()
        stream.close()
        p.terminate()
        ggwave.free(instance)
        print("✅ Cleanup completed.")

# Decrypt files (max 3 attempts with backoff)
def select_folder():
    """Select a folder to decrypt from"""
    while True:
        try:
            print(f"\n{color_info('📁 Choose folder:')}")
            print("─" * 70)
            print(f"{color_bright('[1]')} 📥 audio_received/ (received files)")
            print(f"{color_bright('[2]')} 📤 audio_send/ (sent files)")
            print(f"{color_bright('[3]')} 📂 Custom path")
            print(f"{color_bright('[4]')} 🔙 Back to Main Menu")
            print("─" * 70)
            
            choice = input(color_info("Choice: ")).strip()
            
            if not choice:
                continue
            
            if choice == "4":
                return None
            elif choice == "1":
                if os.path.exists(RECEIVED_DIR):
                    return RECEIVED_DIR
                else:
                    print(color_error("❌ audio_received folder not found"))
                    continue
            elif choice == "2":
                if os.path.exists(SEND_DIR):
                    return SEND_DIR
                else:
                    print(color_error("❌ audio_send folder not found"))
                    continue
            elif choice == "3":
                path = input(color_info("Enter custom path: ")).strip()
                path = clean_path(path)
                if os.path.exists(path):
                    return path
                else:
                    print(color_error("❌ Path not found"))
                    continue
            else:
                print(color_error("❌ Invalid choice"))
        except KeyboardInterrupt:
            print("\n⏹️ Returning to main menu...")
            return None


def select_file_from_folder(folder_path):
    """Select a file from folder"""
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    
    if not files:
        folder_name = os.path.basename(folder_path)
        print(f"\n{color_warning(f'📁 {folder_name} folder is EMPTY')}")
        print(color_warning("No files to decrypt"))
        try:
            input(color_info("Press Enter to go back..."))
        except KeyboardInterrupt:
            print("\n⏹️ Returning to main menu...")
        return None
    
    # Sort by newest first
    files.sort(key=lambda x: os.path.getmtime(os.path.join(folder_path, x)), reverse=True)
    
    while True:
        try:
            print(color_info("\n📄 Files:"))
            print("─" * 70)
            for i, f in enumerate(files, 1):
                fsize = os.path.getsize(os.path.join(folder_path, f))
                fmtime = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(folder_path, f))).strftime("%Y-%m-%d %H:%M:%S")
                ftype = f.split('.')[-1].upper() if '.' in f else "FILE"
                print(f"  [{i}] {f:40} | {ftype:4} | {fsize:>8} bytes | {fmtime}")
            back_option = len(files) + 1
            print(f"  [{back_option}] 🔙 Back")
            print("─" * 70)
            
            choice = input(color_info("Select file (number): ")).strip()
            
            if not choice:
                continue
            
            if choice == str(back_option):
                return None
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(files):
                    selected = os.path.join(folder_path, files[idx])
                    print(f"\n✅ Selected: {files[idx]}")
                    return selected
                else:
                    print(color_error("❌ Invalid selection"))
            except ValueError:
                print(color_error("❌ Enter a valid number"))
        except KeyboardInterrupt:
            print("\n⏹️ Returning to main menu...")
            return None


def decrypt_file():
    while True:  # Loop per decriptare più file
        clear_screen()
        display_header()
        print("\n" + "=" * 70)
        print(color_bright("                  DECRYPT FILE (.aes / .rsa)"))
        print("=" * 70)
        print(f"{color_info('💡 Press Ctrl+C anytime to return to main menu')}")

        # STEP 1: Choose folder
        folder_path = select_folder()
        if folder_path is None:
            return
        
        # STEP 2: Select file from folder
        fname = select_file_from_folder(folder_path)
        if fname is None:
            continue
        
        try:
            if fname.endswith(".aes"):
                max_attempts = 3
                for attempt in range(1, max_attempts + 1):
                    try:
                        password = getpass.getpass(color_info(f"AES password (attempt {attempt}/{max_attempts}): "))
                        if not password:
                            print("❌ Password required.")
                            continue
                        
                        with open(fname, "rb") as f:
                            encrypted_content = f.read()

                        decrypted_content, file_hash = aes_decrypt_fss1(encrypted_content, password)

                        output_name = fname.replace(".aes", "_dec.bin")
                        with open(output_name, "wb") as f:
                            f.write(decrypted_content)
                        print(f"\n✅ File decrypted and saved: {output_name}")
                        print(f"   Size: {len(decrypted_content)} bytes")
                        print(f"   ✅ Integrity verified (SHA-256)")

                        log_operation("DECRYPT_FILE", os.path.basename(fname), "AES", "SUCCESS", additional=f"output: {output_name}, hash: {file_hash[:16]}...")
                        break

                    except ValueError as e:
                        if attempt < max_attempts:
                            sleep_time = 2 ** attempt
                            print(f"❌ {e}")
                            print(f"⏳ Waiting {sleep_time}s before next attempt...")
                            print(f"⚠️  {max_attempts - attempt} attempt(s) remaining")

                            log_operation("DECRYPT_FILE", os.path.basename(fname), "AES", "FAILED_ATTEMPT", additional=f"attempt {attempt}/{max_attempts}")
                            time.sleep(sleep_time)
                        else:
                            print(f"❌ Maximum password attempts reached.")
                            log_operation("DECRYPT_FILE", os.path.basename(fname), "AES", "FAILED", additional="max attempts reached")

            elif fname.endswith(".rsa"):
                decryption_success = False
                
                while not decryption_success:
                    # Ask for private key path
                    privkey_path = input(color_info("Private key PEM path: ")).strip()
                    privkey_path = clean_path(privkey_path)
                    
                    if not os.path.exists(privkey_path):
                        print("❌ Private key file not found")
                        continue

                    with open(privkey_path, "r") as f:
                        privkey_pem = f.read()

                    # Try password up to 3 times for this key
                    max_password_attempts = 3
                    for pwd_attempt in range(1, max_password_attempts + 1):
                        try:
                            key_password = getpass.getpass(color_info(f"Private key password (attempt {pwd_attempt}/{max_password_attempts}): ")) or None
                            
                            with open(fname, "rb") as f:
                                encrypted_content = f.read()

                            decrypted_content, file_hash = rsa_decrypt_fss1(encrypted_content, privkey_pem, key_password)

                            output_name = fname.replace(".rsa", "_dec.bin")
                            with open(output_name, "wb") as f:
                                f.write(decrypted_content)
                            print(f"\n✅ File decrypted and saved: {output_name}")
                            print(f"   Size: {len(decrypted_content)} bytes")
                            print(f"   ✅ Integrity verified (SHA-256)")

                            log_operation("DECRYPT_FILE", os.path.basename(fname), "RSA", "SUCCESS", additional=f"output: {output_name}, hash: {file_hash[:16]}...")
                            decryption_success = True
                            break

                        except ValueError as e:
                            if pwd_attempt < max_password_attempts:
                                sleep_time = 2 ** pwd_attempt
                                print(f"❌ {e}")
                                print(f"⏳ Waiting {sleep_time}s before next attempt...")
                                print(f"⚠️  {max_password_attempts - pwd_attempt} attempt(s) remaining")

                                log_operation("DECRYPT_FILE", os.path.basename(fname), "RSA", "FAILED_ATTEMPT", additional=f"pwd attempt {pwd_attempt}/{max_password_attempts}")
                                time.sleep(sleep_time)
                            else:
                                print(f"❌ Maximum password attempts reached for this key.")
                                log_operation("DECRYPT_FILE", os.path.basename(fname), "RSA", "FAILED_PWD_ATTEMPTS", additional="max password attempts reached")
                                print(f"\n{color_warning('Try with a different key:')}")

                                break
            else:
                print("❌ Unsupported format (must be .aes or .rsa)")
                continue
            
            # Ask to decrypt another file or exit
            print("=" * 70)
            try:
                again = input(color_info("Decrypt another file? (y/N): ")).strip().lower()
                if again != "y":
                    return
            except KeyboardInterrupt:
                print("\n⏹️ Operation cancelled.")
                return

        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return

# View Audit Log
def prompt_view_audit_log():
    """Display audit log menu"""
    try:
        while True:
            clear_screen()
            display_header()
            print("\n" + "=" * 70)
            print(color_bright("                       AUDIT LOG"))
            print("=" * 70 + "")

            
            log_content = get_audit_log()
            
            if not log_content:
                print(color_warning("⚠️  No audit log found or empty.")
)
            else:
                print(log_content + "")

            
            print("=" * 70)
            print(color_bright("Options:"))
            print("[1] 🔄 Refresh")
            print("[2] 🏠 Back to Main Menu")

            
            try:
                choice = input(color_info("Select option (1-2): ")).strip()
            except KeyboardInterrupt:
                print("\n⏹️ Operation cancelled.")
                return
            
            if choice == "1":
                continue
            elif choice == "2" or choice == "":
                return
            else:
                print(color_error("❌ Invalid option."))
                time.sleep(1)
    
    except Exception as e:
        print(color_error(f"❌ Error: {e}"))
        time.sleep(1)

# Credits
def generate_and_display_lightning_qr(lnurl: str):
    """
    Generate and display Lightning Network QR code in terminal using ASCII art
    
    CRITICAL SECURITY NOTES:
    - Uses qrcode library with print_ascii() for terminal display
    - High error correction ensures payment accuracy
    - lnurl is NOT modified or altered
    - Prints QR code directly to terminal as ASCII characters (¦ and spaces)
    - No file is created, QR is ephemeral (printed to stdout)
    - invert=True improves terminal readability
    
    Args:
        lnurl: Lightning payment address (must be 104 characters)
    
    Returns:
        None (prints to terminal)
    """
    if not HAS_QRCODE:
        print("\n" + "=" * 60)
        print("⚠️  OPTIONAL: QR Code library not installed")
        print("=" * 60)
        print("\nQR codes are optional. To enable them, install:")
        print("  pip install qrcode[pil]")
        print("\nOr with system package manager:")
        print("  apt install python3-qrcode (Debian/Ubuntu)")
        print("  brew install qrcode (macOS)")
        print("\nFor now, Lightning address displayed as text.")
        print("=" * 60 + "")

        print(f"\n{color_warning('⚡ Lightning Address:')}")
        print(f"   {lnurl}")

        return
    
    try:
        # Validate lnurl format
        if not lnurl or len(lnurl) < 50:
            raise ValueError(f"Invalid lnurl: {lnurl}")
        
        # Create QR code with HIGH error correction (critical for payments)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(lnurl)
        qr.make(fit=True)
        
        # Print QR code as ASCII art directly in terminal
        qr.print_ascii(invert=True)
        
    except Exception as e:
        print(color_error(f"❌ Error generating QR code: {e}"))

def prompt_credits():
    while True:
        clear_screen()
        display_header()
        print("\n" + "=" * 70)
        print(color_bright("                         CREDITS"))
        print("=" * 70)
        
        print(f"\n{color_info('📌 PROJECT DESCRIPTION:')}")

        print("""SonarLink v2.0 - Secure Audio Messaging & File Transfer

Open-source solution for sending messages, keys, and data securely over 
sound waves without network connections. Built on Georgi Gerganov's ggwave.

FEATURES:
✅ Open Chat: real-time unencrypted messaging
✅ Private Chat: token-based AES-256 with GZIP compression
✅ File Transfer: up to 10 KB for keys, credentials, passwords
✅ Standalone Encryption/Decryption: AES-256-GCM or RSA-4096
✅ Audit Log: operation tracking with timestamps
✅ Cross-platform: Windows, Linux, macOS

USE CASES:
• Air-gapped secure communication
• SSH/GPG key exchange without network exposure
• Covert messaging with plausible deniability
• Environments where network protocols are restricted

SECURITY:
• Open Chat: unencrypted (plaintext transmission)
• Private Chat: AES-256-GCM + GZIP (optimized for audio, ~50-60% smaller)
• File Transfer: AES-256-GCM or RSA-4096 with FSS1 format (includes hash)
• PBKDF2 key derivation (600,000 iterations)
• Ephemeral private chat tokens (8-digit, session-based)
• No token storage or retention - single-use per session
• Comprehensive audit logging without storing message content

OPEN SOURCE:
SonarLink is freely available under open-source license. All encryption 
formats are fully documented for long-term decryption independence.""")

        
        print(f"\n{color_warning('─' * 70)}")
        print(f"\n{color_info('⚡ SUPPORT & DONATIONS:')}")

        print("If you find SonarLink useful, please consider supporting")
        print("the project with a Lightning Network donation.")

        
        lnurl_address = "lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhwm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq"
        
        print(f"\n{color_warning('⚡ Lightning Address:')}")
        print(f"   {color_info(lnurl_address)}")

        
        print()
        print()
        print(color_bright("Options:"))
        print("[1] 📱 View QR Code")
        print("[2] 🏠 Back to Main Menu")

        
        try:
            choice = input(color_info("Select option (1-2): ")).strip()
        except KeyboardInterrupt:
            print("\n⏹️ Operation cancelled.")
            return
        
        if choice == "1":
            # Show QR code
            while True:
                clear_screen()
                display_header()
                print("\n" + "=" * 70)
                print(color_bright("           ⚡ LIGHTNING NETWORK DONATION QR CODE"))
                print("=" * 70 + "")

                
                if HAS_QRCODE:
                    generate_and_display_lightning_qr(lnurl_address)
                else:
                    print(color_warning("⚠️  qrcode library not installed"))
                    print(f"{color_warning('⚡ Lightning Address:')}")
                    print(f"   {color_info(lnurl_address)}")
                
                print(f"\n{color_warning('⚡ Lightning Address:')}")
                print(f"   {color_info(lnurl_address)}")

                
                print()
                print()
                print(color_bright("Options:"))
                print("[1] 📱 View QR Code")
                print("[2] 🏠 Back")

                
                try:
                    qr_choice = input(color_info("Select option (1-2): ")).strip()
                except KeyboardInterrupt:
                    print("\n⏹️ Operation cancelled.")
                    break
                
                if qr_choice == "1":
                    continue
                elif qr_choice == "2" or qr_choice == "":
                    break
                else:
                    print(color_error("❌ Invalid option."))
                    time.sleep(1)
        
        elif choice == "2" or choice == "":
            return
        else:
            print(color_error("❌ Invalid option."))
            time.sleep(1)

# Main menu
def main():
    # Initialize all directories on startup
    # This ensures audio_received/, audio_send/, and audiologs/ are created
    # in the same folder as the program (important for PyInstaller .exe)
    ensure_log_dir()
    ensure_received_dir()
    ensure_send_dir()
    
    while True:
        clear_screen()
        display_header()
        
        print("\n" + "=" * 70)
        print(color_bright("                         MAIN MENU"))
        print("=" * 70 + "")

        
        print(f"{color_bright('[1]')} 💬 Open Chat")
        print(f"{color_bright('[2]')} 📁 Send file")
        print(f"{color_bright('[3]')} 🎧 Receive messages or files")
        print(f"{color_bright('[4]')} 🔓 Decrypt received file")
        print(f"{color_bright('[5]')} 📊 View Audit Log")
        print(f"{color_bright('[6]')} ℹ️ Credits")
        print(f"{color_bright('[7]')} ❌ Exit")

        
        try:
            choice = input(color_info("Select option (1-7): ")).strip()
        except KeyboardInterrupt:
            print("\n⏹️ Exiting.")
            break
        
        if choice == "1":
            send_text()
        elif choice == "2":
            send_file()
        elif choice == "3":
            receive()
        elif choice == "4":
            decrypt_file()
        elif choice == "5":
            prompt_view_audit_log()
        elif choice == "6":
            prompt_credits()
        elif choice == "7":
            print("\n👋 SonarLink v2.0 closed. Stay secure!")

            break
        else:
            print(color_error("❌ Invalid option."))
            time.sleep(1)

if __name__ == "__main__":
    main()
