import base64
import json
import os
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def send_packet(sock, payload: dict) -> None:
    """Відправляє JSON-пакет із 4-байтовим заголовком довжини."""
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def _recv_exact(sock, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("З'єднання закрито співрозмовником.")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock) -> dict:
    """Приймає один повний JSON-пакет."""
    header = _recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    raw = _recv_exact(sock, length)
    return json.loads(raw.decode("utf-8"))


def generate_rsa_keys():
    """Генерує пару ключів RSA-2048 (private, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_key, public_pem


def rsa_encrypt(public_pem: str, data: bytes) -> str:
    """Шифрує байти відкритим ключем сервера (RSA-OAEP) та повертає base64."""
    public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    cipher = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(cipher).decode("ascii")


def rsa_decrypt(private_key, b64_cipher: str) -> bytes:
    """Розшифровує base64-шифротекст приватним ключем сервера."""
    cipher = base64.b64decode(b64_cipher.encode("ascii"))
    return private_key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def derive_session_key(client_random: bytes, server_random: bytes, premaster: bytes) -> bytes:
    """Виводить 256-бітний сеансовий ключ через HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_random + server_random,
        info=b"rgr-tls-handshake-session-key",
    )
    return hkdf.derive(premaster)


def aes_encrypt(session_key: bytes, text: str) -> dict:
    """Шифрує текст алгоритмом AES-256-GCM із випадковим 12-байтовим nonce."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, text.encode("utf-8"), None)
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def aes_decrypt(session_key: bytes, encrypted: dict) -> str:
    """Розшифровує повідомлення AES-256-GCM та перевіряє його цілісність."""
    nonce = base64.b64decode(encrypted["nonce"].encode("ascii"))
    ciphertext = base64.b64decode(encrypted["ciphertext"].encode("ascii"))
    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")