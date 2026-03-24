"""Demonstrate basic McCallum-Relyea key exchange and concatkdf."""

from pprint import pprint

from Crypto.Hash import SHA256

from tang.keys import KeyHelper
from tang.peers import Client, Server


def main():
    """Complete a McCallum-Relyea key exchange and derive secret using concatkdf."""
    server = Server()
    client = Client()
    key = client.provision(server)
    # Discard client private key and binding key
    recover = client.recover(server)
    escrow = client.escrow(server)
    assert key == recover == escrow
    secret = KeyHelper.concatkdf(key, key_len=32, hashmod=SHA256, alg="A256GCM")
    pprint({"client": client.key, "server": server.key, "key": key, "secret": secret})


if __name__ == "__main__":
    main()
