"""Actual simulator enrollment and repeated quotations from independent role AKs."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from examples.confined_redemption.tpm_registration import (
    create_software_tpm_attestation,
    enroll_principal_tpm,
)
from fixtures.registration import generate_registration_fixture
from resource_bound_authorization.tpm_verification import (
    SoftwareTPMAttestation,
    verify_software_tpm_attestation,
)


@pytest.mark.software_tpm
def test_distinct_readonly_role_contexts_support_serialized_fresh_quotes(tmp_path: Path) -> None:
    interface = os.environ.get("RESOURCE_AUTHORIZATION_TPM_INTERFACE")
    if interface is None:
        pytest.skip("RESOURCE_AUTHORIZATION_TPM_INTERFACE is not configured")
    lock_path = tmp_path / "tpm.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o444)
    roles = ("calling_principal", "delegated_principal")
    registrations = {role: generate_registration_fixture(role).registration for role in roles}
    directories = {role: tmp_path / role for role in roles}
    trusts = {}
    for role in roles:
        directories[role].mkdir(mode=0o700)
        trusts[role] = enroll_principal_tpm(
            registrations[role], directories[role], interface, lock_path=lock_path
        )
    assert (
        trusts[roles[0]].enrolled_ak_public_key_pem != trusts[roles[1]].enrolled_ak_public_key_pem
    )
    context_digests = {}
    for role in roles:
        context = directories[role] / "attestation.context"
        context_digests[role] = hashlib.sha256(context.read_bytes()).hexdigest()
        context.chmod(0o400)
        directories[role].chmod(0o500)

    def quote(role: str) -> SoftwareTPMAttestation:
        now = int(time.time())
        evidence = create_software_tpm_attestation(
            registrations[role],
            directories[role],
            interface,
            secrets.token_hex(32),
            now + 60,
            lock_path=lock_path,
        )
        binding = verify_software_tpm_attestation(
            registrations[role],
            trusts[role],
            evidence,
            expected_challenge=evidence.challenge,
            now=int(time.time()),
        )
        assert binding.principal_identifier == role
        assert binding.assurance == "software_tpm"
        return evidence

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = list(executor.map(quote, roles))
            second = list(executor.map(quote, reversed(roles)))
        assert first[0].quote_hex != second[1].quote_hex
        for role in roles:
            assert (
                hashlib.sha256((directories[role] / "attestation.context").read_bytes()).hexdigest()
                == context_digests[role]
            )
        evidence = first[0]
        different_challenge = secrets.token_hex(32)
        for changed, expected_challenge in (
            (evidence, different_challenge),
            (evidence.model_copy(update={"challenge": different_challenge}), different_challenge),
            (evidence.model_copy(update={"manifest_digest": "1" * 64}), evidence.challenge),
            (
                evidence.model_copy(
                    update={
                        "signature_hex": evidence.signature_hex[:-2]
                        + f"{int(evidence.signature_hex[-2:], 16) ^ 1:02x}"
                    }
                ),
                evidence.challenge,
            ),
        ):
            with pytest.raises(ValueError):
                verify_software_tpm_attestation(
                    registrations[roles[0]],
                    trusts[roles[0]],
                    changed,
                    expected_challenge=expected_challenge,
                    now=int(time.time()),
                )
        wrong_context_evidence = create_software_tpm_attestation(
            registrations[roles[0]],
            directories[roles[1]],
            interface,
            secrets.token_hex(32),
            int(time.time()) + 60,
            lock_path=lock_path,
        )
        with pytest.raises(ValueError):
            verify_software_tpm_attestation(
                registrations[roles[0]],
                trusts[roles[0]],
                wrong_context_evidence,
                expected_challenge=wrong_context_evidence.challenge,
                now=int(time.time()),
            )
    finally:
        for directory in directories.values():
            directory.chmod(0o700)
