"""Deterministic adapter checks; actual quote verification has a separate simulator test."""

from __future__ import annotations

import copy
import secrets
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from examples.confined_redemption.tpm_registration import _synthetic_certificate_chain
from fixtures.registration import generate_registration_fixture
from resource_bound_authorization import tpm_verification
from resource_bound_authorization.tpm_verification import (
    SoftwareTPMAttestation,
    SoftwareTPMTrust,
    software_tpm_qualifying_data,
    verify_software_tpm_attestation,
)
from resource_bound_authorization.verification import PrincipalRegistration, signed_manifest_digest


@pytest.fixture(scope="module")
def adapter_inputs() -> tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation]:
    registration = generate_registration_fixture("calling_principal").registration
    public_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    chain, roots = _synthetic_certificate_chain(public_pem)
    trust = SoftwareTPMTrust(
        principal_identifier=registration.principal_identifier,
        holder_public_key=registration.identity_public_key,
        manifest_digest=registration.manifest_digest,
        ak_certificate_chain_pem=chain,
        trusted_roots_pem=roots,
        enrolled_ak_public_key_pem=public_pem.decode("ascii"),
        expected_pcr_digest="1" * 64,
    )
    # Deliberately opaque, non-quote unit bytes: the dispatch spy below is explicit.
    evidence = SoftwareTPMAttestation(
        principal_identifier=registration.principal_identifier,
        holder_public_key=registration.identity_public_key,
        manifest_digest=registration.manifest_digest,
        challenge=secrets.token_hex(32),
        expires_at=int(time.time()) + 60,
        quote_hex="0001",
        signature_hex="0002",
    )
    return registration, trust, evidence


def test_adapter_passes_every_expected_binding_to_released_quote_api(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration, trust, evidence = adapter_inputs
    # Deliberately independent of wall time: dropping the injected clock must fail.
    moment = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
    now = int(moment.timestamp())
    evidence = evidence.model_copy(update={"expires_at": now + 60})
    received: dict[str, Any] = {}

    def dispatch_spy(quote: bytes, signature: bytes, chain: bytes, **options: Any) -> bool:
        received.update(quote=quote, signature=signature, chain=chain, **options)
        return True

    monkeypatch.setattr(tpm_verification, "verify_tpm_quote", dispatch_spy)
    binding = verify_software_tpm_attestation(
        registration, trust, evidence, expected_challenge=evidence.challenge, now=now
    )
    assert received["verification_time"] == moment
    assert received["verification_time"].tzinfo is UTC
    assert received["quote"] == bytes.fromhex(evidence.quote_hex)
    assert received["signature"] == bytes.fromhex(evidence.signature_hex)
    assert received["chain"] == trust.ak_certificate_chain_pem.encode()
    assert received["trusted_roots_pem"] == trust.trusted_roots_pem.encode()
    assert received["expected_pcr_digest"] == bytes.fromhex(trust.expected_pcr_digest)
    assert received["expected_qualifying_data"] == software_tpm_qualifying_data(
        evidence.principal_identifier,
        evidence.holder_public_key,
        evidence.manifest_digest,
        evidence.challenge,
        evidence.expires_at,
    )
    assert binding.assurance == "software_tpm"
    assert len(binding.attestation_digest) == 64


@pytest.mark.parametrize("verifier_result", [False, None, 1, "true"])
def test_adapter_requires_the_actual_boolean_true(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation],
    monkeypatch: pytest.MonkeyPatch,
    verifier_result: Any,
) -> None:
    registration, trust, evidence = adapter_inputs
    monkeypatch.setattr(
        tpm_verification, "verify_tpm_quote", lambda *args, **kwargs: verifier_result
    )
    with pytest.raises(ValueError, match="did not verify"):
        verify_software_tpm_attestation(
            registration,
            trust,
            evidence,
            expected_challenge=evidence.challenge,
            now=int(time.time()),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_identifier", "other"),
        ("holder_public_key", "2" * 64),
        ("manifest_digest", "2" * 64),
        ("expires_at", 0),
        ("expires_at", True),
        ("quote_hex", "abc"),
        ("signature_hex", "not-hex"),
        ("assurance", "development"),
    ],
)
def test_malformed_or_substituted_evidence_never_reaches_quote_verification(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: Any,
) -> None:
    registration, trust, evidence = adapter_inputs

    def unexpected_dispatch(*args: Any, **kwargs: Any) -> bool:
        raise AssertionError("invalid evidence reached quote verification")

    monkeypatch.setattr(tpm_verification, "verify_tpm_quote", unexpected_dispatch)
    with pytest.raises(ValueError):
        verify_software_tpm_attestation(
            registration,
            trust,
            evidence.model_copy(update={field: value}),
            expected_challenge=evidence.challenge,
            now=int(time.time()),
        )


@pytest.mark.parametrize("now", [True, -1, 10**100])
def test_invalid_quote_evaluation_time_is_rejected(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation], now: Any
) -> None:
    registration, trust, evidence = adapter_inputs
    with pytest.raises(ValueError, match="evaluation time"):
        verify_software_tpm_attestation(
            registration, trust, evidence, expected_challenge=evidence.challenge, now=now
        )


def test_quote_cannot_substitute_for_signed_manifest_verification(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation],
) -> None:
    registration, trust, evidence = adapter_inputs
    document = copy.deepcopy(registration.signed_manifest)
    document["artifacts"]["model_identity"]["provider"] = "changed-without-signature"
    digest = signed_manifest_digest(document)
    altered_registration = registration.model_copy(
        update={"signed_manifest": document, "manifest_digest": digest}
    )
    with pytest.raises(ValueError, match="VALID"):
        verify_software_tpm_attestation(
            altered_registration,
            trust.model_copy(update={"manifest_digest": digest}),
            evidence.model_copy(update={"manifest_digest": digest}),
            expected_challenge=evidence.challenge,
            now=int(time.time()),
        )


def test_trust_requires_the_enrolled_key_in_the_fixed_leaf_certificate(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation],
) -> None:
    registration, trust, evidence = adapter_inputs
    other_public = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    for changed in (
        trust.model_copy(update={"enrolled_ak_public_key_pem": other_public}),
        trust.model_copy(update={"ak_certificate_chain_pem": "invalid-certificate" * 10}),
        trust.model_copy(update={"principal_identifier": "other"}),
    ):
        with pytest.raises(ValueError):
            verify_software_tpm_attestation(
                registration,
                changed,
                evidence,
                expected_challenge=evidence.challenge,
                now=int(time.time()),
            )


def test_unknown_tpm_evidence_claims_are_rejected(
    adapter_inputs: tuple[PrincipalRegistration, SoftwareTPMTrust, SoftwareTPMAttestation],
) -> None:
    document = adapter_inputs[2].model_dump()
    document["certificate_chain"] = "caller-selected trust is forbidden"
    with pytest.raises(ValueError):
        SoftwareTPMAttestation.model_validate(document)
