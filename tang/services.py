"""Implement Tang protocol backend."""

import json
import os
from pathlib import Path
from typing import Any

from jose import jws

from tang.constants import KeyOperations
from tang.keys import KeyHelper
from tang.models import JwkModel, JwsModel, TangKey
from tang.peers import Server


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

    def get_keys_by_operation(self, operation: KeyOperations) -> list[TangKey]:
        """Return TangKey instances with specified key_ops."""
        return [key for key in self.keys if operation in key.key_ops]

    def get_key_by_thumbprint(self, thumbprint: str) -> TangKey | None:
        """Return TangKey instance by thumbprint or None."""
        keys = self._filter_keys_by_thumbprint(self.keys, thumbprint)
        try:
            return keys[0]
        except IndexError:
            return None

    @staticmethod
    def _filter_keys_by_thumbprint(
        keys: list[TangKey], thumbprint: str
    ) -> list[TangKey]:
        """Return list of TangKey instances filtered by thumbprint."""
        return [
            key for key in keys if KeyHelper.get_thumbprint(key.dict()) == thumbprint
        ]

    def sign(self, data: str | dict[str, Any]) -> JwsModel:
        """Sign data and return JwsModel."""
        signing_key = self.get_keys_by_operation(KeyOperations.SIGN)[0]
        signed = jws.sign(
            data,
            KeyHelper.to_jwk(KeyHelper.from_jwk(signing_key.dict())),
            algorithm="ES512",
        )
        protected, payload, signature = signed.split(".")
        return JwsModel(payload=payload, protected=protected, signature=signature)

    def advertise(self, thumbprint: str | None = None) -> JwsModel | None:
        """Advertise available public keys."""
        keys = self.get_keys_by_operation(KeyOperations.DERIVE_KEY)
        if thumbprint is not None:
            keys = self._filter_keys_by_thumbprint(keys, thumbprint)
        if not keys:
            return None
        keys += self.get_keys_by_operation(KeyOperations.VERIFY)
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
