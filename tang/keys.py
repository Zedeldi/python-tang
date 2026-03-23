"""Provide helper methods to handle cryptographic keys."""

import math
from types import ModuleType
from typing import Literal

from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.PublicKey._curve import _Curve as Curve


def _u32be(value: int) -> bytes:
    return value.to_bytes(length=4, byteorder="big")


class KeyHelper:
    """Helper class to handle keys."""

    @staticmethod
    def from_private(curve: str, d: int) -> ECC.EccKey:
        """Return EccKey instance from private value."""
        return ECC.EccKey(curve=curve, d=d)

    @staticmethod
    def from_point(point: ECC.EccPoint) -> ECC.EccKey:
        """Return EccKey instance from EccPoint."""
        return ECC.EccKey(curve=point.curve, point=point)

    @classmethod
    def multiply(
        cls: type[KeyHelper], *, private: ECC.EccKey, public: ECC.EccKey
    ) -> ECC.EccKey:
        """Multiply public key point by private value."""
        return cls.from_point(public.pointQ * private.d)

    @classmethod
    def add(cls: type[KeyHelper], a: ECC.EccKey, b: ECC.EccKey) -> ECC.EccKey:
        """Add two key points together."""
        return cls.from_point(a.pointQ + b.pointQ)

    @staticmethod
    def to_bytes(key: ECC.EccKey, byteorder: Literal["big", "little"] = "big") -> bytes:
        """Return bytes from point x."""
        point = key.pointQ
        return int(point.x).to_bytes(length=point.size_in_bytes(), byteorder=byteorder)

    @staticmethod
    def get_curve(curve: str) -> Curve:
        """Return Curve instance from name."""
        return ECC._curves[curve]  # type: ignore[return-value]

    @classmethod
    def invert(cls: type[KeyHelper], key: ECC.EccKey) -> ECC.EccKey:
        """Return inverse of an EccPoint."""
        point = key.pointQ
        return cls.from_point(
            point.point_at_infinity()
            if point.is_point_at_infinity()
            else ECC.EccPoint(
                point.x, cls.get_curve(point.curve).p - point.y, curve=point.curve
            )
        )

    @classmethod
    def hkdf(
        cls: type[KeyHelper], key: ECC.EccKey, **kwargs
    ) -> bytes | tuple[bytes, ...]:
        """Derive symmetric key using HKDF from EccKey."""
        return HKDF(master=cls.to_bytes(key), **kwargs)

    @classmethod
    def concatkdf(
        cls: type[KeyHelper],
        key: ECC.EccKey,
        *,
        key_len: int,
        hashmod: ModuleType,
        alg: str,
        apu: bytes = b"",
        apv: bytes = b"",
    ) -> bytes:
        """
        Derive symmetric key using José concatkdf.

        Python implementation of https://github.com/latchset/jose/blob/b58fdb1ac61cf1b7bd8034f07d76ad7f56c0e02a/lib/openssl/ecdhes.c#L50.
        By default, José uses SHA-256 for hashing.
        """
        secret = cls.to_bytes(key)
        info = b"".join(
            map(
                lambda value: _u32be(len(value)) + value,
                [alg.encode("ascii"), apu, apv],
            ),
        ) + _u32be(key_len * 8)
        iterations = math.ceil(key_len / hashmod.digest_size)
        return b"".join(
            hashmod.new(_u32be(counter) + secret + info).digest()
            for counter in range(1, iterations + 1)
        )[:key_len]
