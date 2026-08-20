import os

from cryptography.fernet import Fernet


def get_fernet():
    key = os.getenv("AWS_CRED_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("AWS_CRED_ENCRYPTION_KEY is not set in the environment.")
    return Fernet(key.encode())


def encrypt_value(value: str) -> str:
    if value is None or value == "":
        return ""
    return get_fernet().encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    if not value:
        return ""
    return get_fernet().decrypt(value.encode()).decode()
