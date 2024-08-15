import hashlib
import os
from random import (
    Random,
)

import names


def hash_password(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()


def random_salt() -> str:
    return bytes.hex(os.urandom(32))


def generate_users_and_password_hashes(
    passwords: list[str], count: int = 32
) -> dict[str, str]:
    rng = Random()

    users_and_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _i in range(count)
    }
    return users_and_password_hashes


def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    users_and_passwords = {}
    LUT = {}
    for password in passwords:
        LUT[hash_password(password)] = password
    for user, hash in passwords_database.items():
        users_and_passwords[user] = LUT[hash] 
    return users_and_passwords


def fix(
    passwords: list[str], passwords_database: dict[str, str]
) -> dict[str, dict[str, str]]:
    users = attack(passwords, passwords_database)
    salts = {}
    db = {}
    for user, password in users.items():
        salt = random_salt()
        hash = hash_password(salt + password)
        salts[user] = salt
        db[user] = {"password_hash": hash, "password_salt": salt}
    return db

def authenticate(
    user: str, password: str, new_database: dict[str, dict[str, str]]
) -> bool:
    return user in new_database and hash_password(new_database[user]["password_salt"] + password) == new_database[user]["password_hash"]

