from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)


def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, msg, None)
    return ciphertext

def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
