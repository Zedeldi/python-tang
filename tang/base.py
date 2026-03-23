"""Base module for McCallum-Relyea key exchange peers."""

from Crypto.PublicKey import ECC


class BasePeer:
    """Base class to handle McCallum-Relyea key exchange peers."""

    def __init__(self, key: ECC.EccKey | str = "NIST P-521") -> None:
        """Initialise instance with keys."""
        if isinstance(key, str):
            self.key = self.generate(key)
        else:
            self.key = key

    def generate(self, curve: str | None = None) -> ECC.EccKey:
        """Generate key for current configuration."""
        return ECC.generate(curve=curve or self.key.curve)
