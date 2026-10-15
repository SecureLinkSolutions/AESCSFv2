import pytest

from app.passwords import hash_password, verify_password


def test_hash_and_verify():
    h = hash_password("a long enough password")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "a long enough password")
    assert not verify_password(h, "wrong")


def test_short_password_rejected():
    with pytest.raises(ValueError):
        hash_password("short")


def test_missing_hash_never_verifies():
    assert not verify_password(None, "not-a-real-password")
