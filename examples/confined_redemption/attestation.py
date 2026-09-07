"""Select evidence from the enrollment profile without a development fallback."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

from pydantic import Field

from examples.confined_redemption.registration import (
    load_principal_fixture,
    load_public_registration,
)
from examples.confined_redemption.tpm_registration import create_software_tpm_attestation
from fixtures.registration import create_development_attestation
from resource_bound_authorization.tpm_verification import SoftwareTPMAttestation
from resource_bound_authorization.verification import DevelopmentAttestation

AttestationRecord = Annotated[
    DevelopmentAttestation | SoftwareTPMAttestation, Field(discriminator="assurance")
]


def create_principal_attestation(
    directory: Path, role: str, challenge: str, expires_at: int
) -> DevelopmentAttestation | SoftwareTPMAttestation:
    configuration = load_public_registration(directory)
    if configuration.assurance == "software_tpm":
        interface = os.environ.get("RESOURCE_AUTHORIZATION_TPM_INTERFACE")
        if not interface:
            raise RuntimeError("software_tpm_interface_required")
        return create_software_tpm_attestation(
            configuration.registrations[role],
            directory / role,
            interface,
            challenge,
            expires_at,
            lock_path=directory / "tpm.lock",
        )
    return create_development_attestation(
        load_principal_fixture(directory, role), challenge, expires_at
    )
