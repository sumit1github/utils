#!/usr/bin/env python3
"""
mdcrypt.py - Interactive high-security encrypt / decrypt / change-password tool for .md files.

Features:
- Argon2id KDF (argon2-cffi) with strong defaults
- ChaCha20-Poly1305 AEAD (cryptography) for authenticated encryption
- Interactive menu:
    1) Encrypt  - ask absolute path, password (with confirmation), optional secure-shred of original
    2) Decrypt  - ask absolute path, password; prints pretty Markdown to terminal (uses rich if installed)
    3) Change password - ask absolute path, current password, new password (with confirmation)
- Encrypted file format (binary): MAGIC | 4-byte header len | JSON header | ciphertext
  header contains KDF params, salt and nonce (base64url)
- No plaintext files written on disk during decrypt/change-password (prints to stdout or re-encrypts in-place)
- Atomic writes for re-encrypt/change-password (write to temp then os.replace)

Dependencies:
  pip install cryptography argon2-cffi rich

Usage:
  python mdcrypt.py
  (then follow interactive prompts)

Security notes:
- Use a long, high-entropy passphrase. If password is weak, encryption will be too.
- Secure deletion (--shred) is best-effort and not guaranteed on SSDs, encrypted filesystems, or backups.
- If you lose the password, data is unrecoverable.
"""
from __future__ import annotations
import os
import sys
import json
import struct
import base64
import secrets
import getpass
import tempfile
from typing import Tuple

# External libs
try:
    from argon2.low_level import hash_secret_raw, Type
except Exception:
    print("Missing dependency: argon2-cffi (pip install argon2-cffi)", file=sys.stderr)
    sys.exit(2)

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except Exception:
    print("Missing dependency: cryptography (pip install cryptography)", file=sys.stderr)
    sys.exit(2)

# Optional pretty markdown
try:
    from rich.console import Console
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False

MAGIC = b"MDENC3"                  # magic/version
HEADER_LEN_STRUCT = ">I"           # 4-byte big-endian header length
KEY_LEN = 32                       # 256-bit key
SALT_LEN = 32
NONCE_LEN = 12                     # ChaCha20Poly1305 (was 24 for XChaCha20Poly1305)

# Strong but reasonable defaults; you may increase memory_kib/time for more hardness at cost of CPU/RAM/time.
DEFAULT_ARGON2_TIME = 4            # iterations
DEFAULT_ARGON2_MEMORY_KIB = 131072 # 128 MiB
DEFAULT_ARGON2_PARALLELISM = 4

def _b64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode("ascii")

def _ub64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))

def derive_key_argon2(password: bytes, salt: bytes, time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )

def build_encrypted_blob(plaintext: bytes, password: bytes,
                         time_cost: int = DEFAULT_ARGON2_TIME,
                         memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
                         parallelism: int = DEFAULT_ARGON2_PARALLELISM) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key_argon2(password, salt, time_cost, memory_kib, parallelism)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data=None)

    header = {
        "kdf": "argon2id",
        "time": int(time_cost),
        "memory_kib": int(memory_kib),
        "parallelism": int(parallelism),
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "note": "ChaCha20-Poly1305 with Argon2id params"
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    blob = bytearray()
    blob += MAGIC
    blob += struct.pack(HEADER_LEN_STRUCT, len(header_bytes))
    blob += header_bytes
    blob += ciphertext
    # attempt to zero key (best-effort)
    try:
        for i in range(len(key)):
            key = b'\x00' * len(key)
            break
    except Exception:
        pass
    return bytes(blob)

def parse_encrypted_blob(data: bytes) -> Tuple[dict, bytes]:
    min_len = len(MAGIC) + 4
    if len(data) < min_len:
        raise ValueError("File too short or not a valid encrypted file.")
    if not data.startswith(MAGIC):
        raise ValueError("File magic/version mismatch; not a supported encrypted file.")
    offset = len(MAGIC)
    (hlen,) = struct.unpack(HEADER_LEN_STRUCT, data[offset:offset+4])
    offset += 4
    if len(data) < offset + hlen:
        raise ValueError("Header length inconsistent with file size.")
    header_bytes = data[offset:offset+hlen]
    offset += hlen
    header = json.loads(header_bytes.decode("utf-8"))
    ciphertext = data[offset:]
    return header, ciphertext

def encrypt_file(path: str, password: bytes, shred: bool = False,
                 time_cost: int = DEFAULT_ARGON2_TIME,
                 memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
                 parallelism: int = DEFAULT_ARGON2_PARALLELISM) -> str:
    if not os.path.isabs(path):
        raise ValueError("Please provide an absolute path.")
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        plaintext = f.read()
    blob = build_encrypted_blob(plaintext, password, time_cost, memory_kib, parallelism)
    out_path = path + ".enc"
    # atomic write
    d = os.path.dirname(out_path) or "."
    with tempfile.NamedTemporaryFile(dir=d, delete=False) as tf:
        tf.write(blob)
        tf.flush()
        os.fsync(tf.fileno())
        tmpname = tf.name
    os.replace(tmpname, out_path)
    # shred original if requested
    if shred:
        try:
            secure_overwrite_and_remove(path)
        except Exception as e:
            print(f"Warning: secure deletion failed: {e}", file=sys.stderr)
    return out_path

def decrypt_to_plaintext(path: str, password: bytes) -> bytes:
    if not os.path.isabs(path):
        raise ValueError("Please provide an absolute path.")
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        data = f.read()
    header, ciphertext = parse_encrypted_blob(data)
    if header.get("kdf") != "argon2id":
        raise ValueError("Unsupported KDF in file header.")
    salt = _ub64(header["salt"])
    nonce = _ub64(header["nonce"])
    time_cost = int(header["time"])
    memory_kib = int(header["memory_kib"])
    parallelism = int(header["parallelism"])
    key = derive_key_argon2(password, salt, time_cost, memory_kib, parallelism)
    aead = ChaCha20Poly1305(key)
    try:
        plaintext = aead.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e
    # best-effort zeroing key
    try:
        key = b'\x00' * len(key)
    except Exception:
        pass
    return plaintext

def change_password_inplace(path: str, old_password: bytes, new_password: bytes,
                            time_cost: int = DEFAULT_ARGON2_TIME,
                            memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB,
                            parallelism: int = DEFAULT_ARGON2_PARALLELISM) -> None:
    # decrypt plaintext, re-encrypt with new password and atomically replace file
    plaintext = decrypt_to_plaintext(path, old_password)
    new_blob = build_encrypted_blob(plaintext, new_password, time_cost, memory_kib, parallelism)
    # write to temp file in same dir and replace original
    d = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile(dir=d, delete=False) as tf:
        tf.write(new_blob)
        tf.flush()
        os.fsync(tf.fileno())
        tmpname = tf.name
    os.replace(tmpname, path)

def secure_overwrite_and_remove(path: str, passes: int = 3):
    """
    Best-effort overwrite file with random data multiple times and remove.
    Not guaranteed on SSDs or journaling filesystems.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    length = os.path.getsize(path)
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            remaining = length
            chunk = 64 * 1024
            while remaining > 0:
                to_write = secrets.token_bytes(min(chunk, remaining))
                f.write(to_write)
                remaining -= len(to_write)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        f.truncate(0)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.remove(path)

def prompt_abs_path(prompt_text: str) -> str:
    p = input(prompt_text).strip()
    return os.path.abspath(p)

def prompt_password(confirm: bool = False) -> bytes:
    pw = getpass.getpass("Password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            raise ValueError("Passwords do not match.")
    return pw.encode("utf-8")

def pretty_print_markdown(md_bytes: bytes) -> None:
    try:
        text = md_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # not valid UTF-8: show as binary hex preview
        print("Note: Decrypted content is not UTF-8 text. Showing hex preview (first 1024 bytes):")
        print(f"{20*"="} file content start {20*"="}")
        print(md_bytes[:1024].hex())
        print("============== file content end ===========")
        return
    
    print(f"{20*"="} file content start {20*"="}")
    if RICH_AVAILABLE:
        console.print(Markdown(text))
    else:
        print(text)
    print("============== file content end ===========")

def main_menu():
    print("Welcome, sumit. Select an option:")
    print("  1) Encrypt a .md file")
    print("  2) Decrypt (show contents) an encrypted file")
    print("  3) Change password for an encrypted file (in-place)")
    print("  4) Quit")
    choice = input("Enter 1/2/3/4: ").strip()
    return choice

def main():
    try:
        while True:
            choice = main_menu()
            if choice == "1":
                try:
                    path = prompt_abs_path("Absolute path of .md file to encrypt: ")
                    if not path.lower().endswith(".md"):
                        confirm = input("File does not end with .md. Continue? (y/N): ").strip().lower()
                        if confirm != "y":
                            print("Aborting.")
                            continue
                    password = prompt_password(confirm=True)
                    shred_choice = input("Securely overwrite and remove original after encryption? (y/N): ").strip().lower()
                    shred = shred_choice == "y"
                    out = encrypt_file(path, password, shred=shred)
                    print(f"Encrypted -> {out}")
                except Exception as e:
                    print("Error:", e, file=sys.stderr)
                finally:
                    # attempt to zero password variable
                    try:
                        password = b"\x00" * len(password)
                    except Exception:
                        pass

            elif choice == "2":
                try:
                    path = prompt_abs_path("Absolute path of encrypted file (.enc): ")
                    password = prompt_password(confirm=False)
                    plaintext = decrypt_to_plaintext(path, password)
                    pretty_print_markdown(plaintext)
                except Exception as e:
                    print("Error:", e, file=sys.stderr)
                finally:
                    try:
                        password = b"\x00" * len(password)
                    except Exception:
                        pass

            elif choice == "3":
                try:
                    path = prompt_abs_path("Absolute path of encrypted file (.enc): ")
                    old_pw = prompt_password(confirm=False)
                    new_pw = prompt_password(confirm=True)
                    # re-encrypt in-place
                    change_password_inplace(path, old_pw, new_pw)
                    print("Password successfully changed (file re-encrypted in-place).")
                except Exception as e:
                    print("Error:", e, file=sys.stderr)
                finally:
                    for v in ("old_pw", "new_pw"):
                        try:
                            val = locals().get(v)
                            if isinstance(val, (bytes, bytearray)):
                                if len(val):
                                    val = b"\x00" * len(val)
                        except Exception:
                            pass

            elif choice == "4":
                print("Goodbye.")
                break
            else:
                print("Invalid choice. Try again.")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()


'''
argon2-cffi==25.1.0
argon2-cffi-bindings==25.1.0
cffi==2.0.0
cryptography==46.0.3
pycparser==2.23

'''
