"""Ephemeral public enrollment and explicitly developmental signed statements.

No private key is committed or deterministically derived. The caller controls
where generated fixtures are stored and must keep private keys out of evidence.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from agent_manifest import Ed25519Signer, generate_ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resource_bound_authorization.verification import (
    DevelopmentAttestation,
    PrincipalRegistration,
    development_attestation_signing_bytes,
    normalize_signed_manifest,
    signed_manifest_digest,
)


@dataclass(frozen=True, slots=True)
class RegistrationFixture:
    """Public registration plus two process-local development signing keys."""

    registration: PrincipalRegistration
    holder_private_key: Ed25519PrivateKey
    attestation_private_key: Ed25519PrivateKey


def _new_manifest_identifier(now: int) -> str:
    """Generate the SDK-required UUIDv7 without requiring Python 3.14."""

    raw = bytearray((now * 1000).to_bytes(6, "big") + secrets.token_bytes(10))
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _artifact_hash(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def generate_registration_fixture(
    principal_identifier: str,
    *,
    now: int | None = None,
) -> RegistrationFixture:
    """Provision a signed manifest and independent holder/attestation keys.

    Hashes describe synthetic development artifacts, not a running model or
    measured workload. The issuer registry is the authority linking the signed
    manifest's principal to the holder and enrolled attestation key.
    """

    issued_at = int(time.time()) if now is None else now
    if type(issued_at) is not int or issued_at < 0:
        raise ValueError("fixture time must be a nonnegative integer")
    moment = datetime.fromtimestamp(issued_at, UTC)
    holder_key = Ed25519PrivateKey.generate()
    attestation_key = Ed25519PrivateKey.generate()
    issuer = "spiffe://resource-bound.test/manifest-authority"
    system_hash = _artifact_hash(b"Synthetic resource authorization development fixture.")
    policy_hash = _artifact_hash(b"Resource-native authorization; deny without verified authority.")
    model_hash = _artifact_hash(b"No model executes in this deterministic development fixture.")
    document = normalize_signed_manifest(
        {
            "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
            "@type": "AgentManifest",
            "manifest_id": _new_manifest_identifier(issued_at),
            "agent_id": principal_identifier,
            "version": "0.1",
            "issued_at": moment,
            "expires_at": moment + timedelta(hours=24),
            "issuer": issuer,
            "artifacts": {
                "system_prompt": {
                    "hash": system_hash,
                    "version": "1",
                    "classification": "internal",
                    "bound_at": moment,
                },
                "policy_bundle": {
                    "hash": policy_hash,
                    "policy_language": "cedar",
                    "version": "1",
                    "enforcement_mode": "enforce",
                    "scope": ["object.read"],
                    "bound_at": moment,
                },
                "model_identity": {
                    "provider": "local-development",
                    "model_id": "synthetic-registration-fixture",
                    "version": "1",
                    "deployment_type": "local",
                    "model_hash": model_hash,
                    "model_attestation_type": "hash-bound",
                    "bound_at": moment,
                },
            },
        }
    )
    manifest_key = generate_ed25519()
    document["signature"] = Ed25519Signer(manifest_key).sign(document)
    document = normalize_signed_manifest(document)
    registration = PrincipalRegistration(
        principal_identifier=principal_identifier,
        signed_manifest=document,
        manifest_digest=signed_manifest_digest(document),
        manifest_issuer=issuer,
        manifest_signing_key_id=manifest_key.key_id,
        manifest_signing_public_key=manifest_key.public_b64url(),
        system_prompt_hash=system_hash,
        policy_bundle_hash=policy_hash,
        model_hash=model_hash,
        identity_public_key=holder_key.public_key().public_bytes_raw().hex(),
        development_attestation_public_key=attestation_key.public_key().public_bytes_raw().hex(),
    )
    return RegistrationFixture(registration, holder_key, attestation_key)


def create_development_attestation(
    fixture: RegistrationFixture,
    challenge: str,
    expires_at: int,
) -> DevelopmentAttestation:
    """Sign a fresh development statement with the enrolled software key."""

    registration = fixture.registration
    statement = DevelopmentAttestation(
        challenge=challenge,
        principal_identifier=registration.principal_identifier,
        holder_public_key=fixture.holder_private_key.public_key().public_bytes_raw().hex(),
        manifest_digest=registration.manifest_digest,
        expires_at=expires_at,
        signature="0" * 128,
    )
    signature = fixture.attestation_private_key.sign(
        development_attestation_signing_bytes(statement)
    ).hex()
    return statement.model_copy(update={"signature": signature})
