"""Test basic McCallum-Relyea key exchange."""

from Crypto.PublicKey import ECC

from tang.client import Client
from tang.server import Server


def test_provision(client: Client, server: Server):
    """Test initial key provisioning."""
    key = client.provision(server)
    assert isinstance(key, ECC.EccKey)
    assert not key.has_private()


def test_recover(client: Client, server: Server):
    """Test key recovery with ephemeral key blinding."""
    key = client.provision(server)
    recover = client.recover(server)
    assert key == recover


def test_escrow(client: Client, server: Server):
    """Test recovery via plain escrow."""
    key = client.provision(server)
    escrow = client.escrow(server)
    assert key == escrow
