"""Fresh quote verification against pre-enrolled synthetic software-TPM trust.

The caller supplies evidence; the issuer supplies the manifest registration,
expected challenge, and TPM trust from its own registry. Quote verification uses
the released Agent Manifest API. Challenge consumption belongs to the issuer.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal

import rfc8785
from agent_manifest import TpmVerificationError, verify_tpm_quote
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, Field

from .models import PrincipalBinding
from .verification import HexDigest, PrincipalRegistration, verify_registered_manifest

_QUALIFYING_DOMAIN = b"resource-bound-authorization/software-tpm-quote/v1\x00"
_CertificatePEM = Annotated[str, Field(min_length=64, max_length=32768)]


class SoftwareTPMTrust(BaseModel):
    """Issuer-owned enrollment; evidence cannot select its own AK or trust root."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    principal_identifier: str = Field(min_length=1, max_length=256)
    holder_public_key: HexDigest
    manifest_digest: HexDigest
    ak_certificate_chain_pem: _CertificatePEM
    trusted_roots_pem: _CertificatePEM
    enrolled_ak_public_key_pem: str = Field(min_length=64, max_length=8192)
    expected_pcr_digest: HexDigest


class _QualifyingClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["resource-bound-software-tpm-attestation/v1"] = (
        "resource-bound-software-tpm-attestation/v1"
    )
    assurance: Literal["software_tpm"] = "software_tpm"
    principal_identifier: str = Field(min_length=1, max_length=256)
    holder_public_key: HexDigest
    manifest_digest: HexDigest
    challenge: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: int = Field(ge=0)


class SoftwareTPMAttestation(_QualifyingClaims):
    """Opaque TPM wire bytes plus the exact request transcript they must bind."""

    quote_hex: str = Field(pattern=r"^(?:[0-9a-f]{2})+$", min_length=2, max_length=32768)
    signature_hex: str = Field(pattern=r"^(?:[0-9a-f]{2})+$", min_length=2, max_length=8192)


def software_tpm_qualifying_data(
    principal_identifier: str,
    holder_public_key: str,
    manifest_digest: str,
    challenge: str,
    expires_at: int,
) -> bytes:
    """Commit the complete strict request transcript into the TPM qualifying data."""

    claims = _QualifyingClaims(
        principal_identifier=principal_identifier,
        holder_public_key=holder_public_key,
        manifest_digest=manifest_digest,
        challenge=challenge,
        expires_at=expires_at,
    )
    return hashlib.sha256(_QUALIFYING_DOMAIN + rfc8785.dumps(claims.model_dump())).digest()


def verify_software_tpm_attestation(
    registration: PrincipalRegistration,
    trust: SoftwareTPMTrust,
    evidence: SoftwareTPMAttestation,
    *,
    expected_challenge: str,
    now: int,
) -> PrincipalBinding:
    """Require manifest verification, enrolled AK trust, and a fresh bound quote.

    The expected PCR digest is appraised by the released quote verifier. This
    adapter does not independently appraise the signed PCR-selection structure,
    holder residency, co-location, workload execution, or hardware provenance.
    """

    if type(now) is not int or now < 0:
        raise ValueError("invalid software TPM evaluation time")
    try:
        verification_time = datetime.fromtimestamp(now, UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError("invalid software TPM evaluation time") from error
    policy = PrincipalRegistration.model_validate(registration.model_dump(mode="python"))
    enrolled = SoftwareTPMTrust.model_validate(trust.model_dump(mode="python"))
    statement = SoftwareTPMAttestation.model_validate(evidence.model_dump(mode="python"))
    if type(expected_challenge) is not str or statement.challenge != expected_challenge:
        raise ValueError("software TPM challenge does not match")
    if not now < statement.expires_at <= now + policy.max_attestation_ttl_seconds:
        raise ValueError("software TPM evidence is outside its permitted validity")
    if (
        statement.principal_identifier != policy.principal_identifier
        or enrolled.principal_identifier != policy.principal_identifier
        or statement.holder_public_key != policy.identity_public_key
        or enrolled.holder_public_key != policy.identity_public_key
        or statement.manifest_digest != policy.manifest_digest
        or enrolled.manifest_digest != policy.manifest_digest
    ):
        raise ValueError("software TPM evidence does not match the registered principal")
    verify_registered_manifest(policy)
    try:
        chain = x509.load_pem_x509_certificates(enrolled.ak_certificate_chain_pem.encode("ascii"))
        public_key = serialization.load_pem_public_key(
            enrolled.enrolled_ak_public_key_pem.encode("ascii")
        )
        enrolled_key = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if (
            not chain
            or chain[0]
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            != enrolled_key
        ):
            raise ValueError("AK certificate does not contain the enrolled public key")
        result = verify_tpm_quote(
            bytes.fromhex(statement.quote_hex),
            bytes.fromhex(statement.signature_hex),
            enrolled.ak_certificate_chain_pem.encode("ascii"),
            trusted_roots_pem=enrolled.trusted_roots_pem.encode("ascii"),
            expected_qualifying_data=software_tpm_qualifying_data(
                statement.principal_identifier,
                statement.holder_public_key,
                statement.manifest_digest,
                statement.challenge,
                statement.expires_at,
            ),
            expected_pcr_digest=bytes.fromhex(enrolled.expected_pcr_digest),
            verification_time=verification_time,
        )
    except (TpmVerificationError, UnicodeError, ValueError, TypeError) as error:
        raise ValueError("software TPM quote or enrolled trust did not verify") from error
    if result is not True:
        raise ValueError("software TPM quote did not verify")
    return PrincipalBinding(
        principal_identifier=policy.principal_identifier,
        manifest_digest=policy.manifest_digest,
        holder_public_key=policy.identity_public_key,
        attestation_digest=hashlib.sha256(rfc8785.dumps(statement.model_dump())).hexdigest(),
        assurance="software_tpm",
    )
