"""Test key derivation functions."""

import pytest
from Crypto.Hash import SHA256

from tang.keys import KeyHelper
from tang.peers import Client, Server


@pytest.mark.parametrize("key_len", [16, 32, 64])
def test_concatkdf(client: Client, server: Server, key_len: int):
    """Test concatkdf key derivation function."""
    key = client.provision(server)
    secret = KeyHelper.concatkdf(key, key_len=key_len, hashmod=SHA256, alg="A256GCM")
    assert isinstance(secret, bytes)
    assert len(secret) == key_len
