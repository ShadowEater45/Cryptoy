from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    permutation = [(a * i + b) % n for i in range(n)]
    return permutation


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    permutation = compute_permutation(a, b, n)
    inverse_permutation = [permutation.index(i) for i in range(n)]
    return inverse_permutation


def encrypt(msg: str, a: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    # permutation = compute_permutation(a, b, 0x110000)
    # encrypted_unicodes = [permutation[i] for i in unicodes]
    encrypted_unicodes = [(a * i + b) % 0x110000 for i in unicodes]
    encrypted_msg = unicodes_to_str(encrypted_unicodes)
    return encrypted_msg


def encrypt_optimized(msg: str, a: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    encrypted_unicodes = [(a * i + b) % 0x110000 for i in unicodes]
    encrypted_msg = unicodes_to_str(encrypted_unicodes)
    return encrypted_msg


def decrypt(msg: str, a: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    # inverse_permutation = compute_inverse_permutation(a, b, 0x110000)
    # decrypted_unicodes = [inverse_permutation[i] for i in unicodes]
    affine_keys = compute_affine_keys(0x110000)
    a_inverse = compute_affine_key_inverse(a, affine_keys, 0x110000)
    decrypted_unicodes = [(a_inverse * (i - b)) % 0x110000 for i in unicodes]
    decrypted_msg = unicodes_to_str(decrypted_unicodes)
    return decrypted_msg


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    decrypted_unicodes = [(a_inverse * (i - b)) % 0x110000 for i in unicodes]
    decrypted_msg = unicodes_to_str(decrypted_unicodes)
    return decrypted_msg


def compute_affine_keys(n: int) -> list[int]:
    affine_keys = [a for a in range(1, n) if gcd(a, n) == 1]
    return affine_keys


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    for a_inverse in affine_keys:
        if (a * a_inverse) % n == 1:
            return a_inverse
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58

    b = 58
    affines_keys = compute_affine_keys(0x110000)

    for a in range(1, 0x110000):
        try:
            a_inverse = compute_affine_key_inverse(a, affines_keys, 0x110000)
        except:
            continue
        decrypted_msg = decrypt_optimized(s, a_inverse, b)
        if "bombe" in decrypted_msg:
            return decrypted_msg, (a, b)

    raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    
    affines_keys = compute_affine_keys(0x110000)

    for a in range(0x110000):
        try:
            a_inverse = compute_affine_key_inverse(a, affines_keys, 0x110000)
        except:
            continue
        for b in range(1, 10001):
            decrypted_msg = decrypt_optimized(s, a_inverse, b)
            if "bombe" in decrypted_msg:
                return decrypted_msg, (a, b)

    raise RuntimeError("Failed to attack")
