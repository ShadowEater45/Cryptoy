from math import (
    gcd,
)

from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int,
)


def keygen() -> dict:
    e = 65537
    p = draw_random_prime()
    q = draw_random_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)
    return {"public_key": (e, n), "private_key": d}

def encrypt(msg: str, public_key: tuple) -> int:
    plaintext = str_to_int(msg)
    if plaintext >= public_key[1]:
        raise ValueError("Message is too large to be encrypted with the given public key")
    return pow_mod(plaintext, public_key[0], public_key[1])

def decrypt(ciphertext: int, key: dict) -> str:
    plaintext = pow_mod(ciphertext, key["private_key"], key["public_key"][1])
    return int_to_str(plaintext)
