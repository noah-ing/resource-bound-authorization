"""Enrollment and fresh development evidence require real signature verification."""

from __future__ import annotations

import copy
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from fixtures.registration import (
    RegistrationFixture,
    create_development_attestation,
    generate_registration_fixture,
)
from resource_bound_authorization.verification import (
    DevelopmentAttestation,
    development_attestation_signing_bytes,
    signed_manifest_digest,
    verify_development_attestation,
    verify_registered_manifest,
)


@pytest.fixture
def registration_fixture() -> RegistrationFixture:
    return generate_registration_fixture("calling_principal")


def _statement(fixture: RegistrationFixture, **changes: Any) -> DevelopmentAttestation:
    result = create_development_attestation(fixture, "test-challenge", int(time.time()) + 60)
    return result.model_copy(update=changes)


def _verify(fixture: RegistrationFixture, statement: DevelopmentAttestation) -> Any:
    return verify_development_attestation(
        fixture.registration,
        statement,
        expected_challenge="test-challenge",
        now=int(time.time()),
    )


def test_released_manifest_and_development_signature_return_explicit_assurance(
    registration_fixture: RegistrationFixture,
) -> None:
    binding = _verify(registration_fixture, _statement(registration_fixture))
    policy = registration_fixture.registration
    assert binding.principal_identifier == policy.principal_identifier
    assert binding.holder_public_key == policy.identity_public_key
    assert binding.manifest_digest == policy.manifest_digest
    assert len(binding.attestation_digest) == 64
    assert binding.assurance == "development"


def test_fresh_statements_change_evidence_digest_without_changing_stable_registration(
    registration_fixture: RegistrationFixture,
) -> None:
    now = int(time.time())
    bindings = []
    for challenge in ("first-server-nonce", "second-server-nonce"):
        statement = create_development_attestation(registration_fixture, challenge, now + 60)
        bindings.append(
            verify_development_attestation(
                registration_fixture.registration,
                statement,
                expected_challenge=challenge,
                now=now,
            )
        )
    assert bindings[0].attestation_digest != bindings[1].attestation_digest
    assert bindings[0].model_dump(exclude={"attestation_digest"}) == bindings[1].model_dump(
        exclude={"attestation_digest"}
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("challenge", "different-challenge"),
        ("principal_identifier", "different-principal"),
        ("holder_public_key", "1" * 64),
        ("manifest_digest", "1" * 64),
        ("signature", "0" * 128),
        ("expires_at", 0),
        ("expires_at", True),
        ("assurance", "software_tpm"),
    ],
)
def test_quote_or_manifest_mismatch_rejected(
    registration_fixture: RegistrationFixture, field: str, value: Any
) -> None:
    """The default profile rejects mismatched evidence and manifest bindings."""
    with pytest.raises(ValueError):
        _verify(registration_fixture, _statement(registration_fixture, **{field: value}))


def test_attestation_expiry_is_exclusive_and_future_interval_is_bounded(
    registration_fixture: RegistrationFixture,
) -> None:
    now = int(time.time())
    for expires_at in (now, now + 121):
        statement = create_development_attestation(
            registration_fixture, "test-challenge", expires_at
        )
        with pytest.raises(ValueError, match="validity"):
            verify_development_attestation(
                registration_fixture.registration,
                statement,
                expected_challenge="test-challenge",
                now=now,
            )


def test_valid_signature_from_unenrolled_attestation_key_is_rejected(
    registration_fixture: RegistrationFixture,
) -> None:
    statement = _statement(registration_fixture)
    signature = (
        Ed25519PrivateKey.generate().sign(development_attestation_signing_bytes(statement)).hex()
    )
    with pytest.raises(ValueError, match="signature"):
        _verify(registration_fixture, statement.model_copy(update={"signature": signature}))


def test_enrolled_signer_cannot_change_the_registered_holder(
    registration_fixture: RegistrationFixture,
) -> None:
    other_holder = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    statement = _statement(registration_fixture, holder_public_key=other_holder)
    signature = registration_fixture.attestation_private_key.sign(
        development_attestation_signing_bytes(statement)
    ).hex()
    with pytest.raises(ValueError, match="holder"):
        _verify(registration_fixture, statement.model_copy(update={"signature": signature}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_identifier", "different-principal"),
        ("manifest_issuer", "spiffe://other.test/manifest-authority"),
        ("manifest_digest", "1" * 64),
        ("manifest_signing_key_id", "1" * 64),
        ("system_prompt_hash", "sha256:" + "1" * 64),
        ("policy_bundle_hash", "sha256:" + "1" * 64),
        ("model_hash", "sha256:" + "1" * 64),
    ],
)
def test_registered_manifest_requires_every_enrolled_context_value(
    registration_fixture: RegistrationFixture, field: str, value: str
) -> None:
    changed_policy = registration_fixture.registration.model_copy(update={field: value})
    with pytest.raises(ValueError):
        verify_registered_manifest(changed_policy)


def test_matching_digest_cannot_replace_released_signature_verification(
    registration_fixture: RegistrationFixture,
) -> None:
    document = copy.deepcopy(registration_fixture.registration.signed_manifest)
    document["artifacts"]["model_identity"]["provider"] = "changed-provider"
    changed_policy = registration_fixture.registration.model_copy(
        update={"signed_manifest": document, "manifest_digest": signed_manifest_digest(document)}
    )
    with pytest.raises(ValueError, match="VALID"):
        verify_registered_manifest(changed_policy)


def test_unknown_statement_claims_are_rejected(registration_fixture: RegistrationFixture) -> None:
    document = _statement(registration_fixture).model_dump()
    document["unexpected"] = "not-part-of-the-signed-schema"
    with pytest.raises(ValidationError):
        DevelopmentAttestation.model_validate(document)


def test_fixture_keys_are_ephemeral_and_public_registration_has_no_private_key() -> None:
    first = generate_registration_fixture("calling_principal")
    second = generate_registration_fixture("calling_principal")
    assert first.registration.identity_public_key != second.registration.identity_public_key
    assert (
        first.registration.development_attestation_public_key
        != second.registration.development_attestation_public_key
    )
    assert "private" not in first.registration.model_dump_json()


@pytest.mark.parametrize("now", [-1, True, "0"])
def test_invalid_evaluation_time_is_rejected(
    registration_fixture: RegistrationFixture, now: Any
) -> None:
    with pytest.raises(ValueError, match="time"):
        verify_development_attestation(
            registration_fixture.registration,
            _statement(registration_fixture),
            expected_challenge="test-challenge",
            now=now,
        )
