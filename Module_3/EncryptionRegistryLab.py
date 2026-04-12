"""
Secure Programming Lab
Registry-based Encryption Key Storage

Students must implement:
- store_key()
- read_key()
- get_or_create_key()
"""

import winreg
from cryptography.fernet import Fernet

REG_PATH = r"Software\SecureProgrammingLab"
VALUE_NAME = "EncryptionKey"


def _normalize_key_for_registry(key):
    if key is None:
        raise ValueError("key cannot be None")
    if isinstance(key, bytes):
        return key.decode("ascii")
    if isinstance(key, str):
        return key
    raise TypeError("key must be bytes or str")


def _normalize_key_for_fernet(key_value):
    if key_value is None:
        return None
    if isinstance(key_value, bytes):
        return key_value
    if isinstance(key_value, str):
        return key_value.encode("ascii")
    return None


def store_key(key):

    key_str = _normalize_key_for_registry(key)
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        REG_PATH,
        0,
        access=winreg.KEY_SET_VALUE,
    ) as reg_key:
        winreg.SetValueEx(reg_key, VALUE_NAME, 0, winreg.REG_SZ, key_str)


def read_key():

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_PATH,
            0,
            access=winreg.KEY_QUERY_VALUE,
        ) as reg_key:
            value, _value_type = winreg.QueryValueEx(reg_key, VALUE_NAME)
            return _normalize_key_for_fernet(value)
    except FileNotFoundError:
        return None
    except OSError:
        # Covers missing value name or other registry access issues.
        return None


def get_or_create_key():
  
    key = read_key()
    if key is not None:
        return key

    key = Fernet.generate_key()
    store_key(key)
    return key


def encrypt_message(message):
    key = get_or_create_key()
    cipher = Fernet(key)
    return cipher.encrypt(message.encode())


def decrypt_message(ciphertext):
    key = get_or_create_key()
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext).decode()


def main():
    message = input("Enter message: ")

    encrypted = encrypt_message(message)
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(encrypted)
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    main()
