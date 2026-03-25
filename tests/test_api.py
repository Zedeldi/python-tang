"""Test Tang protocol API implementation."""

import json

import pytest
from fastapi.testclient import TestClient
from jose.utils import base64url_decode

from tang.constants import KeyOperations
from tang.keys import KeyHelper
from tang.peers import Client, Server


def _get_keys(payload: str) -> list[dict[str, str]]:
    """Return list of keys from base64-encoded payload."""
    return json.loads(base64url_decode(payload)).get("keys")


def test_advertise(api: TestClient):
    """Test key advertisement."""
    response = api.get("/adv")
    keys = _get_keys(response.json().get("payload"))
    for operation in [KeyOperations.DERIVE_KEY, KeyOperations.VERIFY]:
        assert [key for key in keys if operation in key["key_ops"]]
    assert response.status_code == 200


@pytest.mark.filterwarnings("ignore:.*util.number_to_string.*:DeprecationWarning")
def test_recover(api: TestClient):
    """Test key recovery."""
    client = Client()
    response = api.get("/adv")
    jwks = _get_keys(response.json().get("payload"))
    for jwk in jwks:
        if KeyOperations.DERIVE_KEY in jwk["key_ops"]:
            break
    else:
        raise ValueError("Derive key not found")
    key = KeyHelper.from_jwk(jwk)
    thumbprint = KeyHelper.get_thumbprint(key)
    server = Server(key)
    provisioned = client.provision(server)
    ephemeral = client.generate()
    x = KeyHelper.add(client.key.public_key(), ephemeral)
    response = api.post(f"/rec/{thumbprint}", json=KeyHelper.to_jwk(x).to_dict())
    y = KeyHelper.from_jwk(response.json())
    z = KeyHelper.multiply(private=ephemeral, public=server.key.public_key())
    recovered = KeyHelper.add(y, KeyHelper.invert(z))
    assert provisioned == recovered
