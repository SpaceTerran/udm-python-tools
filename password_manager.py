#!/usr/bin/env python3
"""
Password encryption/decryption utility for UniFi credentials.

This script encrypts and decrypts passwords using a key derived from the system.
The encrypted password is stored in .env.password.encrypted which should be in .gitignore.
"""

import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


def get_encryption_key() -> bytes:
    """
    Derive encryption key from system-specific information.
    Uses a combination of username and home directory for key derivation.
    """
    # Use system-specific information to derive key
    # This ensures the key is consistent on the same machine
    salt = b'unifi_firewall_tool_salt_2024'  # Fixed salt for consistency
    password = f"{os.getenv('USER', 'default')}{os.path.expanduser('~')}".encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def encrypt_password(password: str) -> str:
    """Encrypt a password."""
    key = get_encryption_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a password."""
    key = get_encryption_key()
    fernet = Fernet(key)
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
    decrypted = fernet.decrypt(encrypted_bytes)
    return decrypted.decode()


def get_encrypted_password_file() -> Path:
    """Get the path to the encrypted password file."""
    return Path(__file__).parent / ".env.password.encrypted"


def save_encrypted_password(password: str) -> None:
    """Save encrypted password to file."""
    encrypted = encrypt_password(password)
    file_path = get_encrypted_password_file()
    file_path.write_text(encrypted)
    # Set restrictive permissions (owner read/write only)
    os.chmod(file_path, 0o600)
    print(f"✓ Encrypted password saved to {file_path}")
    print("  File permissions set to 600 (owner read/write only)")


def load_encrypted_password() -> str | None:
    """Load and decrypt password from file."""
    file_path = get_encrypted_password_file()
    if not file_path.exists():
        return None
    try:
        encrypted = file_path.read_text().strip()
        return decrypt_password(encrypted)
    except Exception as e:
        print(f"✗ Error decrypting password: {e}", file=sys.stderr)
        return None


def main():
    """CLI interface for password management."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python password_manager.py encrypt <password>  - Encrypt and save password")
        print("  python password_manager.py decrypt             - Decrypt and display password")
        print("  python password_manager.py test                - Test encryption/decryption")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "encrypt":
        if len(sys.argv) < 3:
            print("✗ Error: Password required", file=sys.stderr)
            print("Usage: python password_manager.py encrypt <password>")
            sys.exit(1)
        password = sys.argv[2]
        save_encrypted_password(password)
        print("✓ Password encrypted and saved successfully")
        print("  Make sure .env.password.encrypted is in .gitignore!")
    
    elif command == "decrypt":
        password = load_encrypted_password()
        if password:
            print(f"Decrypted password: {password}")
        else:
            print("✗ Error: Could not decrypt password", file=sys.stderr)
            sys.exit(1)
    
    elif command == "test":
        test_password = "test_password_123"
        print(f"Testing with password: {test_password}")
        encrypted = encrypt_password(test_password)
        print(f"Encrypted: {encrypted[:50]}...")
        decrypted = decrypt_password(encrypted)
        print(f"Decrypted: {decrypted}")
        if decrypted == test_password:
            print("✓ Encryption/decryption test passed")
        else:
            print("✗ Encryption/decryption test failed", file=sys.stderr)
            sys.exit(1)
    
    else:
        print(f"✗ Unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
