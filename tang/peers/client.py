"""Client module for McCallum-Relyea key exchange."""

from Crypto.PublicKey import ECC

from tang.keys import KeyHelper
from tang.peers.base import BasePeer
from tang.peers.server import Server


class Client(BasePeer):
    """Class to handle client methods of McCallum-Relyea key exchange."""

    def provision(self, server: Server) -> ECC.EccKey:
        """Get key from exchange of private key and server public key."""
        public = server.advertise()
        return KeyHelper.multiply(private=self.key, public=public)

    def recover(self, server: Server) -> ECC.EccKey:
        """Recover key using ephemeral key for blinding."""
        public = server.advertise()
        ephemeral = self.generate()
        x = KeyHelper.add(self.key.public_key(), ephemeral)
        y = server.exchange(x)
        z = KeyHelper.multiply(private=ephemeral, public=public)
        return KeyHelper.add(y, KeyHelper.invert(z))

    def escrow(self, server: Server) -> ECC.EccKey:
        """Recover key without blinding."""
        return server.exchange(self.key.public_key())
