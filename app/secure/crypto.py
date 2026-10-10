"""A02 안전 구현: Argon2id 비밀번호 해시."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHashError


def verify_password(stored_hash: str, candidate: str) -> bool:
    hasher = PasswordHasher()
    try:
        return hasher.verify(stored_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def hash_password(candidate: str) -> str:
    return PasswordHasher().hash(candidate)
