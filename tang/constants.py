"""Constants used within the Tang protocol and for handling keys."""

from enum import StrEnum


class KeyOperations(StrEnum):
    """Enumeration of key operations."""

    DERIVE_KEY = "deriveKey"
    SIGN = "sign"
    VERIFY = "verify"
