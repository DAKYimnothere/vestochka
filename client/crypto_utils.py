import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEYS_DIR = os.path.join(os.path.dirname(__file__), "local_keys")
if not os.path.exists(KEYS_DIR): os.makedirs(KEYS_DIR)

def generate_and_save_keys(username: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).hex()

def load_private_key(username: str):
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    if not os.path.exists(priv_path): return None
    with open(priv_path, "rb") as f: return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_message(text: str, recipient_pub_hex: str) -> str:
    recipient_public_key = serialization.load_pem_public_key(bytes.fromhex(recipient_pub_hex))
    return recipient_public_key.encrypt(text.encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).hex()

def decrypt_message(encrypted_hex: str, private_key) -> str:
    return private_key.decrypt(bytes.fromhex(encrypted_hex), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode('utf-8')
