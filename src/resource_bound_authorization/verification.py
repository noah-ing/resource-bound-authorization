"""Released manifest verification and explicitly developmental attestation.

Development attestation is an Ed25519 statement from an enrolled software key.
It is not a TPM quote, workload measurement, or proof of key residency. The
issuer must issue and atomically consume the expected challenge separately.
"""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Literal

import rfc8785
from agent_manifest import (
    Manifest,
    OverallResult,
    RevocationStore,
    VerificationContext,
    canonical_hash,
    verify_manifest,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from .models import PrincipalBinding

HexDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ArtifactHash = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
_ATTESTATION_DOMAIN = b"resource-bound-development-attestation/v1\x00"


class PrincipalRegistration(BaseModel):
    """Public enrollment policy loaded by the issuer, never trusted from a caller."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    principal_identifier: str = Field(min_length=1, max_length=256)
    signed_manifest: dict[str, Any]
    manifest_digest: HexDigest
    manifest_issuer: str = Field(min_length=1, max_length=256)
    manifest_signing_key_id: HexDigest
    manifest_signing_public_key: str = Field(min_length=43, max_length=43)
    system_prompt_hash: ArtifactHash
    policy_bundle_hash: ArtifactHash
    model_hash: ArtifactHash
    identity_public_key: HexDigest
    development_attestation_public_key: HexDigest
    max_attestation_ttl_seconds: int = Field(default=120, ge=1, le=300)


class DevelopmentAttestation(BaseModel):
    """Fresh signed enrollment statement with no hardware assurance claim."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["resource-bound-development-attestation/v1"] = (
        "resource-bound-development-attestation/v1"
    )
    assurance: Literal["development"] = "development"
    challenge: str = Field(min_length=1, max_length=256)
    principal_identifier: str = Field(min_length=1, max_length=256)
    holder_public_key: HexDigest
    manifest_digest: HexDigest
    expires_at: int = Field(ge=0)
    signature: str = Field(pattern=r"^[0-9a-f]{128}$")


def normalize_signed_manifest(document: dict[str, Any]) -> dict[str, Any]:
    """Apply the released schema before signing, hashing, and verification."""

    result: dict[str, Any] = Manifest.model_validate(document).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    return result


def signed_manifest_digest(document: dict[str, Any]) -> str:
    """Return the released canonical hash as this project's lowercase hex form."""

    digest = canonical_hash(normalize_signed_manifest(document))
    if not isinstance(digest, str):
        raise ValueError("manifest canonical hash has an invalid type")
    digest = digest.removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("manifest canonical hash is not SHA-256")
    return digest


def verify_registered_manifest(registration: PrincipalRegistration) -> dict[str, Any]:
    """Verify the pinned signed manifest and all enrolled artifact expectations.

    Agent Manifest's verifier evaluates manifest time with its wall clock. The
    explicit ``now`` accepted by the attestation adapter governs its fresh
    development statement; it does not override the dependency's clock.
    """

    policy = PrincipalRegistration.model_validate(registration.model_dump(mode="python"))
    document = normalize_signed_manifest(policy.signed_manifest)
    if document.get("agent_id") != policy.principal_identifier:
        raise ValueError("manifest principal does not match enrollment")
    if document.get("issuer") != policy.manifest_issuer:
        raise ValueError("manifest issuer does not match enrollment")
    if signed_manifest_digest(document) != policy.manifest_digest:
        raise ValueError("signed manifest digest does not match enrollment")
    context = VerificationContext(
        system_prompt_hash=policy.system_prompt_hash,
        policy_bundle_hash=policy.policy_bundle_hash,
        enforcement_mode="enforce",
        model_version=policy.model_hash,
        trusted_keys={policy.manifest_signing_key_id: policy.manifest_signing_public_key},
        trusted_key_issuers={policy.manifest_signing_key_id: [policy.manifest_issuer]},
        strict_artifact_verification=True,
    )
    result = verify_manifest(document, context, RevocationStore())
    if result.result is not OverallResult.VALID or result.signature_verified is not True:
        raise ValueError("released manifest verification did not return a verified VALID result")
    return document


def development_attestation_signing_bytes(evidence: DevelopmentAttestation) -> bytes:
    """Domain-separated canonical bytes covered by the enrolled software key."""

    return _ATTESTATION_DOMAIN + rfc8785.dumps(evidence.model_dump(exclude={"signature"}))


def verify_development_attestation(
    registration: PrincipalRegistration,
    evidence: DevelopmentAttestation,
    *,
    expected_challenge: str,
    now: int,
) -> PrincipalBinding:
    """Return an authenticated fresh binding; challenge consumption is external."""

    if type(now) is not int or now < 0:
        raise ValueError("attestation evaluation time must be a nonnegative integer")
    if type(expected_challenge) is not str or not expected_challenge:
        raise ValueError("expected challenge must be a nonempty string")
    policy = PrincipalRegistration.model_validate(registration.model_dump(mode="python"))
    statement = DevelopmentAttestation.model_validate(evidence.model_dump(mode="python"))
    if statement.challenge != expected_challenge:
        raise ValueError("attestation challenge does not match")
    if statement.principal_identifier != policy.principal_identifier:
        raise ValueError("attestation principal does not match enrollment")
    if statement.holder_public_key != policy.identity_public_key:
        raise ValueError("attestation holder key does not match enrollment")
    if statement.manifest_digest != policy.manifest_digest:
        raise ValueError("attestation manifest does not match enrollment")
    if not now < statement.expires_at <= now + policy.max_attestation_ttl_seconds:
        raise ValueError("attestation validity does not satisfy enrollment policy")
    verify_registered_manifest(policy)
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(policy.development_attestation_public_key)
        ).verify(
            bytes.fromhex(statement.signature), development_attestation_signing_bytes(statement)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("development attestation signature is invalid") from exc
    return PrincipalBinding(
        principal_identifier=policy.principal_identifier,
        manifest_digest=policy.manifest_digest,
        holder_public_key=policy.identity_public_key,
        attestation_digest=hashlib.sha256(rfc8785.dumps(statement.model_dump())).hexdigest(),
        assurance="development",
    )
