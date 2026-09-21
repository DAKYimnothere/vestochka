import base64
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYS_DIR = os.path.join(os.path.dirname(__file__), "local_keys")
if not os.path.exists(KEYS_DIR): os.makedirs(KEYS_DIR)

def _derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))


def generate_and_save_keys(username: str, password: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    private_bytes = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    encrypted = AESGCM(key).encrypt(nonce, private_bytes, username.encode("utf-8"))
    with open(priv_path, "w", encoding="ascii") as f:
        json.dump({"version": 1, "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(encrypted).decode()}, f)
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).hex()

def load_private_key(username: str, password: str):
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    if not os.path.exists(priv_path): return None
    try:
        with open(priv_path, "r", encoding="ascii") as f:
            stored = json.load(f)
        salt = base64.b64decode(stored["salt"])
        nonce = base64.b64decode(stored["nonce"])
        ciphertext = base64.b64decode(stored["ciphertext"])
        private_bytes = AESGCM(_derive_key(password, salt)).decrypt(nonce, ciphertext, username.encode("utf-8"))
        return serialization.load_pem_private_key(private_bytes, password=None)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, InvalidTag):
        return None

def encrypt_message(text: str, recipient_pub_hex: str) -> str:
    recipient_public_key = serialization.load_pem_public_key(bytes.fromhex(recipient_pub_hex))
    return recipient_public_key.encrypt(text.encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).hex()

def decrypt_message(encrypted_hex: str, private_key) -> str:
    return private_key.decrypt(bytes.fromhex(encrypted_hex), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode('utf-8')
