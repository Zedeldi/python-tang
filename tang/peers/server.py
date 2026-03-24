"""Server module for McCallum-Relyea key exchange."""

from Crypto.PublicKey import ECC

from tang.keys import KeyHelper
from tang.peers.base import BasePeer


class Server(BasePeer):
    """Class to handle server methods of McCallum-Relyea key exchange."""

    def advertise(self) -> ECC.EccKey:
        """Return public key of server."""
        return self.key.public_key()

    def exchange(self, public: ECC.EccKey) -> ECC.EccKey:
        """Exchange server private key with specified public key."""
        return KeyHelper.multiply(private=self.key, public=public)
