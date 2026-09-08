"""Appraise certificate times around one real software-TPM quote.

Reusing this quote isolates certificate appraisal; it does not test acceptance of
replayed challenges. Challenge consumption belongs to the issuer, not this adapter.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from agent_manifest import TpmVerificationError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from examples.confined_redemption.tpm_registration import (
    create_software_tpm_attestation,
    enroll_principal_tpm,
)
from fixtures.registration import generate_registration_fixture
from resource_bound_authorization.tpm_verification import (
    SoftwareTPMAttestation,
    SoftwareTPMTrust,
    verify_software_tpm_attestation,
)
from resource_bound_authorization.verification import PrincipalRegistration

pytestmark = pytest.mark.software_tpm

_EVALUATION_TIME = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
_NOW = int(_EVALUATION_TIME.timestamp())


@dataclass(frozen=True)
class _TPMTimeInputs:
    registration: PrincipalRegistration
    trust: SoftwareTPMTrust
    evidence: SoftwareTPMAttestation
    issuer_key: Ed25519PrivateKey


def _trust_with_period(
    trust: SoftwareTPMTrust,
    issuer_key: Ed25519PrivateKey,
    *,
    certificate_index: int | None = None,
    not_before_offset: int = -3600,
    not_after_offset: int = 3600,
) -> SoftwareTPMTrust:
    """Reissue the enrolled AK chain with intact signatures and matching root trust."""

    certificates = x509.load_pem_x509_certificates(trust.ak_certificate_chain_pem.encode())
    assert len(certificates) == 2
    chain = []
    for index, certificate in enumerate(certificates):
        before, after = (
            (not_before_offset, not_after_offset) if index == certificate_index else (-3600, 3600)
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(certificate.subject)
            .issuer_name(certificate.issuer)
            .public_key(issuer_key.public_key() if index == 1 else certificate.public_key())
            .serial_number(certificate.serial_number)
            .not_valid_before(_EVALUATION_TIME + timedelta(seconds=before))
            .not_valid_after(_EVALUATION_TIME + timedelta(seconds=after))
        )
        for extension in certificate.extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)
        chain.append(
            builder.sign(issuer_key, algorithm=None).public_bytes(serialization.Encoding.PEM)
        )
    # Released verification checks time before signatures. Independently ensure
    # even the denied fixtures retain valid adjacent and self-issued signatures.
    leaf, root = x509.load_pem_x509_certificates(b"".join(chain))
    leaf.verify_directly_issued_by(root)
    root.verify_directly_issued_by(root)
    return trust.model_copy(
        update={
            "ak_certificate_chain_pem": b"".join(chain).decode("ascii"),
            "trusted_roots_pem": chain[-1].decode("ascii"),
        }
    )


@pytest.fixture(scope="module")
def certificate_time_inputs(tmp_path_factory: pytest.TempPathFactory) -> _TPMTimeInputs:
    interface = os.environ.get("RESOURCE_AUTHORIZATION_TPM_INTERFACE")
    if interface is None:
        pytest.skip("RESOURCE_AUTHORIZATION_TPM_INTERFACE is not configured")
    directory = tmp_path_factory.mktemp("tpm-certificate-time")
    lock_path = directory / "tpm.lock"
    lock_path.touch(mode=0o600)
    # Manifest verification retains its real wall clock; only certificate appraisal
    # and quote expiry use the fixed UTC time, deliberately far from the current time.
    registration = generate_registration_fixture("calling_principal").registration
    enrolled = enroll_principal_tpm(registration, directory, interface, lock_path=lock_path)
    evidence = create_software_tpm_attestation(
        registration,
        directory,
        interface,
        secrets.token_hex(32),
        _NOW + 60,
        lock_path=lock_path,
    )
    issuer_key = Ed25519PrivateKey.generate()
    trust = _trust_with_period(enrolled, issuer_key)
    return _TPMTimeInputs(registration, trust, evidence, issuer_key)


@pytest.mark.parametrize("certificate_index", [0, 1], ids=["leaf", "root"])
@pytest.mark.parametrize(
    ("not_before_offset", "not_after_offset"),
    [(-7200, -1), (1, 7200), (-3600, 0)],
    ids=["expired", "not-yet-valid", "exact-notAfter"],
)
def test_real_quote_denies_certificate_outside_validity(
    certificate_time_inputs: _TPMTimeInputs,
    certificate_index: int,
    not_before_offset: int,
    not_after_offset: int,
) -> None:
    inputs = certificate_time_inputs
    # The same quote, AK, PCR digest, claims, and issuer validate with current
    # certificate periods, ruling out unrelated reasons for the denial below.
    binding = verify_software_tpm_attestation(
        inputs.registration,
        inputs.trust,
        inputs.evidence,
        expected_challenge=inputs.evidence.challenge,
        now=_NOW,
    )
    assert binding.assurance == "software_tpm"
    changed = _trust_with_period(
        inputs.trust,
        inputs.issuer_key,
        certificate_index=certificate_index,
        not_before_offset=not_before_offset,
        not_after_offset=not_after_offset,
    )
    with pytest.raises(ValueError, match="quote or enrolled trust did not verify") as failure:
        verify_software_tpm_attestation(
            inputs.registration,
            changed,
            inputs.evidence,
            expected_challenge=inputs.evidence.challenge,
            now=_NOW,
        )
    cause = failure.value.__cause__
    assert isinstance(cause, TpmVerificationError)
    assert f"certificate at position {certificate_index} is outside its validity period" in str(
        cause
    )
    assert f"checked at {_EVALUATION_TIME.isoformat()}" in str(cause)


@pytest.mark.parametrize("certificate_index", [0, 1], ids=["leaf", "root"])
@pytest.mark.parametrize(
    ("not_before_offset", "not_after_offset"),
    [(0, 3600), (-3600, 1)],
    ids=["exact-notBefore", "one-second-before-notAfter"],
)
def test_real_quote_accepts_certificate_inside_validity(
    certificate_time_inputs: _TPMTimeInputs,
    certificate_index: int,
    not_before_offset: int,
    not_after_offset: int,
) -> None:
    inputs = certificate_time_inputs
    trust = _trust_with_period(
        inputs.trust,
        inputs.issuer_key,
        certificate_index=certificate_index,
        not_before_offset=not_before_offset,
        not_after_offset=not_after_offset,
    )
    binding = verify_software_tpm_attestation(
        inputs.registration,
        trust,
        inputs.evidence,
        expected_challenge=inputs.evidence.challenge,
        now=_NOW,
    )
    assert binding.principal_identifier == inputs.registration.principal_identifier
    assert binding.assurance == "software_tpm"
