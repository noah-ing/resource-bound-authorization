"""Fixed-algorithm Ed25519 signatures and explicitly encoded keys."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel

from resource_bound_authorization.canonical import canonical_record_bytes
from resource_bound_authorization.errors import AuthorizationError


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_hex(private_key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public_key = (
        private_key.public_key() if isinstance(private_key, Ed25519PrivateKey) else private_key
    )
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def private_key_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


def load_private_key(encoded_private_key: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(encoded_private_key))
    except (ValueError, TypeError) as exception:
        raise AuthorizationError("invalid_private_key") from exception


def sign_record(record: BaseModel, private_key: Ed25519PrivateKey, domain: str) -> str:
    return private_key.sign(canonical_record_bytes(record, domain)).hex()


def verify_record_signature(
    record: BaseModel, signature: str, public_key: str, domain: str
) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(signature), canonical_record_bytes(record, domain)
        )
    except (InvalidSignature, ValueError, TypeError) as exception:
        raise AuthorizationError("signature_verification_failed") from exception
