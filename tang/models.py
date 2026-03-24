"""Collection of models for the Tang protocol and JOSE."""

from pathlib import Path

from pydantic import BaseModel

from tang.constants import KeyOperations


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
    """Model to store key information with helper methods."""

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
        if KeyOperations.SIGN in (key_ops := key["key_ops"]):
            key_ops.remove(KeyOperations.SIGN)
        return key
