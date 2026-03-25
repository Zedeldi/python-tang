"""Collection of models for the Tang protocol and JOSE."""

from pathlib import Path

from pydantic import BaseModel

from tang.constants import KeyOperations


class BasePayloadModel(BaseModel):
    """Base Pydantic model for a model with a payload."""

    payload: str


class JwsSignature(BaseModel):
    """Base Pydantic model for a model with a JWS signature."""

    protected: str
    signature: str


class JwsModel(BasePayloadModel, JwsSignature):
    """Pydantic model for a JWS with one signature."""


class JwsMultiModel(BasePayloadModel):
    """Pydantic model for a JWS with multiple signatures."""

    signatures: list[JwsSignature]


class JwkModel(BaseModel):
    """Pydantic model for JWK."""

    alg: str
    crv: str
    kty: str
    x: str
    y: str


class TangKey(JwkModel):
    """Model to store key information with helper methods."""

    d: str
    key_ops: list[str]
    path: Path

    @property
    def rotated(self) -> bool:
        """Return whether key has been rotated."""
        return self.path.name.startswith(".")

    def valid_for(self, operation: KeyOperations) -> bool:
        """Return whether key is valid for operation."""
        return operation in self.key_ops

    def public_key(self) -> dict[str, str]:
        """Return dictionary of public key from self."""
        key = self.model_dump(exclude={"d", "path"})
        if KeyOperations.SIGN in (key_ops := key["key_ops"]):
            key_ops.remove(KeyOperations.SIGN)
        return key
