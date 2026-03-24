"""Implement Tang protocol and API."""

import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from jose import jws
from pydantic import BaseModel

from tang.keys import KeyHelper
from tang.server import Server


class JwsModel(BaseModel):
    """Pydantic model for JWS."""

    payload: str
    protected: str
    signature: str


class JwkModel(BaseModel):
    """Pydantic model for JWK."""

    alg: str
    crv: str
    kty: str
    x: str
    y: str


class TangKey(JwkModel):
    """Model to store key information."""

    d: str
    key_ops: list[str]
    path: Path

    @property
    def rotated(self) -> bool:
        """Return whether key has been rotated."""
        return self.path.name.startswith(".")

    def public_key(self) -> dict[str, str]:
        """Return dictionary of public key from self."""
        key = self.dict(exclude={"d", "path"})
        if KeyOps.SIGN in (key_ops := key["key_ops"]):
            key_ops.remove(KeyOps.SIGN)
        return key


class KeyOps(StrEnum):
    """Enumeration of key operations."""

    DERIVE_KEY = "deriveKey"
    SIGN = "sign"
    VERIFY = "verify"


class Tang:
    """Class to handle Tang protocol and server methods."""

    def __init__(self, path: Path | os.PathLike) -> None:
        """Initialise Tang server instance."""
        self.path = Path(path).absolute()

    @property
    def keys(self) -> list[TangKey]:
        """Return list of TangKey instances."""
        keys = []
        for key in Path(self.path).glob("*.jwk"):
            with open(key, "r") as file:
                keys.append(TangKey(path=key, **json.load(file)))
        return keys

    def get_keys_for_use(self, use: str) -> list[TangKey]:
        """Return TangKey instances with specified use."""
        return [key for key in self.keys if use in key.key_ops]

    def get_key_by_thumbprint(self, thumbprint: str) -> TangKey | None:
        """Return TangKey instance by thumbprint or None."""
        keys = self.filter_keys_by_thumbprint(self.keys, thumbprint)
        try:
            return keys[0]
        except IndexError:
            return None

    @staticmethod
    def filter_keys_by_thumbprint(
        keys: list[TangKey], thumbprint: str
    ) -> list[TangKey]:
        """Return list of TangKey instances filtered by thumbprint."""
        return [
            key for key in keys if KeyHelper.get_thumbprint(key.dict()) == thumbprint
        ]

    def sign(self, data: str | dict[str, Any]) -> JwsModel:
        """Sign data and return JwsModel."""
        signing_key = self.get_keys_for_use(KeyOps.SIGN)[0]
        signed = jws.sign(
            data,
            KeyHelper.to_jwk(KeyHelper.from_jwk(signing_key.dict())),
            algorithm="ES512",
        )
        protected, payload, signature = signed.split(".")
        return JwsModel(payload=payload, protected=protected, signature=signature)

    def advertise(self, thumbprint: str | None = None) -> JwsModel | None:
        """Advertise available public keys."""
        keys = self.get_keys_for_use(KeyOps.DERIVE_KEY)
        if thumbprint is not None:
            keys = self.filter_keys_by_thumbprint(keys, thumbprint)
        if not keys:
            return None
        keys += self.get_keys_for_use(KeyOps.VERIFY)
        return self.sign(
            {"keys": [key.public_key() for key in keys if not key.rotated]}
        )

    def recover(self, thumbprint: str, peer: JwkModel) -> JwkModel | None:
        """Return result of exchanging peer key with private key matching thumbprint."""
        key = self.get_key_by_thumbprint(thumbprint)
        if not key:
            return None
        server = Server(KeyHelper.from_jwk(key.dict()))
        exchange = server.exchange(KeyHelper.from_jwk(peer.dict()))
        result = KeyHelper.to_jwk(exchange).to_dict()
        result.update({"alg": "ECMR"})
        return JwkModel(**result)


app = FastAPI()
tang = Tang(Path("keys"))


@app.get("/adv/")
@app.get("/adv/{thumbprint}")
def advertise(thumbprint: str | None = None) -> JwsModel:
    """Advertise available public keys as JWS, optionally filtered by thumbprint."""
    keys = tang.advertise(thumbprint)
    if not keys:
        raise HTTPException(status_code=404, detail="Thumbprint not found")
    return keys


@app.post("/rec/{thumbprint}")
def recover(thumbprint: str, key: JwkModel) -> JwkModel:
    """Recover shared key by exchanging key with private key matching thumbprint."""
    result = tang.recover(thumbprint, key)
    if not result:
        raise HTTPException(status_code=404, detail="Thumbprint not found")
    return result
