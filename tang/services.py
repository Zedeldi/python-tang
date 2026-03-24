"""Implement Tang protocol backend."""

import json
import os
from pathlib import Path
from typing import Any

from Crypto.PublicKey import ECC
from jose import jws

from tang.constants import KeyOperations
from tang.keys import KeyHelper
from tang.models import JwkModel, JwsModel, JwsMultiModel, JwsSignature, TangKey
from tang.peers import Server


class Tang:
    """Class to handle Tang protocol and server methods."""

    def __init__(self, path: Path | os.PathLike) -> None:
        """Initialise Tang server instance."""
        self.path = Path(path).absolute()
        self.validate()

    def validate(self) -> None:
        """Validate required keys exist else generate new keys."""
        for operations in (
            [KeyOperations.DERIVE_KEY],
            [KeyOperations.SIGN, KeyOperations.VERIFY],
        ):
            if not self.get_keys_by_operation(operations[0]):
                self.generate(operations=operations)

    def generate(
        self, *, operations: list[KeyOperations], curve: str = "NIST P-521"
    ) -> TangKey:
        """Generate a key with the specified key operations."""
        key = KeyHelper.to_jwk(ECC.generate(curve=curve)).to_dict()
        key.update({"key_ops": operations})
        if KeyOperations.DERIVE_KEY in operations:
            key.update({"alg": "ECMR"})
        thumbprint = KeyHelper.get_thumbprint(key)
        with open(self.path / f"{thumbprint}.jwk", "w") as file:
            file.write(json.dumps(key))
        return key

    @property
    def keys(self) -> list[TangKey]:
        """Return list of TangKey instances."""
        keys = []
        for key in Path(self.path).glob("*.jwk"):
            with open(key, "r") as file:
                keys.append(TangKey(path=key, **json.load(file)))
        return keys

    def get_keys_by_operation(
        self, operation: KeyOperations, include_rotated: bool = False
    ) -> list[TangKey]:
        """Return list of TangKey instances with specified key_ops."""
        return [
            key
            for key in self.keys
            if operation in key.key_ops and (not key.rotated or include_rotated)
        ]

    def get_key_by_thumbprint(self, thumbprint: str) -> TangKey | None:
        """Return TangKey instance with specified thumbprint or None."""
        for key in self.keys:
            if KeyHelper.get_thumbprint(key.dict()) == thumbprint:
                return key
        return None

    @staticmethod
    def _sign(
        data: str | dict[str, Any], keys: list[TangKey]
    ) -> JwsModel | JwsMultiModel:
        """Sign data with specified keys."""
        signatures = []
        for key in keys:
            protected, payload, signature = jws.sign(
                data,
                KeyHelper.to_jwk(KeyHelper.from_jwk(key.dict())),
                algorithm="ES512",
            ).split(".")
            signatures.append(JwsSignature(protected=protected, signature=signature))
        if len(signatures) > 1:
            return JwsMultiModel(payload=payload, signatures=signatures)
        return JwsModel(payload=payload, **signatures[0].dict())

    def sign(
        self, data: str | dict[str, Any], thumbprint: str | None = None
    ) -> JwsModel | JwsMultiModel | None:
        """Sign data and return JwsModel."""
        keys = self.get_keys_by_operation(KeyOperations.SIGN)
        if thumbprint is not None and (key := self.get_key_by_thumbprint(thumbprint)):
            if not key.valid_for(KeyOperations.SIGN):
                return None
            keys.append(key)
        return self._sign(data, keys)

    def advertise(
        self, thumbprint: str | None = None
    ) -> JwsModel | JwsMultiModel | None:
        """Advertise available public keys."""
        keys = self.get_keys_by_operation(KeyOperations.DERIVE_KEY)
        if not keys:
            return None
        keys += self.get_keys_by_operation(KeyOperations.VERIFY)
        return self.sign(
            {"keys": [key.public_key() for key in keys if not key.rotated]},
            thumbprint=thumbprint,
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
