"""Fixed, offline-owner-authorized policy for the synthetic reference object."""

from __future__ import annotations

import hashlib
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from resource_bound_authorization.models import PrincipalBinding, ResourcePolicy
from resource_bound_authorization.tpm_verification import SoftwareTPMTrust
from resource_bound_authorization.verification import PrincipalRegistration

OBJECT_IDENTIFIER = "reference_record"
TOOL_NAME = "object.read"
AUDIENCE = "resource_server"
ARGUMENTS = {"record_identifier": OBJECT_IDENTIFIER}
ROLE_IDENTIFIERS = {
    "authorization_server": 10001,
    "resource_server": 10002,
    "authorization_proxy": 10003,
    "calling_principal": 10004,
    "delegated_principal": 10005,
}
PRINCIPAL_ROLES = ("calling_principal", "delegated_principal")
SERVICE_ROLES = (
    "authorization_server",
    "resource_server",
    "authorization_proxy",
    "delegated_principal",
)
DEFAULT_DESTINATIONS = {role: (role, 8000) for role in SERVICE_ROLES}


class PublicConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    issuer_public_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    registrations: dict[str, PrincipalRegistration]
    assurance: Literal["development", "software_tpm"] = "development"
    tpm_trust: dict[str, SoftwareTPMTrust] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_registered_roles(self) -> Self:
        if set(self.registrations) != set(PRINCIPAL_ROLES):
            raise ValueError("exactly_two_registered_principals_required")
        if any(role != entry.principal_identifier for role, entry in self.registrations.items()):
            raise ValueError("registration_role_mismatch")
        if self.assurance == "software_tpm":
            if set(self.tpm_trust) != set(PRINCIPAL_ROLES):
                raise ValueError("exactly_two_tpm_enrollments_required")
            for role, trust in self.tpm_trust.items():
                registration = self.registrations[role]
                if (
                    trust.principal_identifier != role
                    or trust.holder_public_key != registration.identity_public_key
                    or trust.manifest_digest != registration.manifest_digest
                ):
                    raise ValueError("tpm_enrollment_registration_mismatch")
        elif self.tpm_trust:
            raise ValueError("tpm_enrollment_requires_software_tpm_assurance")
        return self


def resource_policy(configuration: PublicConfiguration) -> ResourcePolicy:
    """Enrollment digests are placeholders; issuance authenticates fresh evidence."""

    principals = tuple(
        PrincipalBinding(
            principal_identifier=role,
            manifest_digest=configuration.registrations[role].manifest_digest,
            holder_public_key=configuration.registrations[role].identity_public_key,
            attestation_digest=hashlib.sha256(f"enrollment:{role}".encode()).hexdigest(),
            assurance=configuration.assurance,
        )
        for role in PRINCIPAL_ROLES
    )
    return ResourcePolicy(
        audience=AUDIENCE,
        object_identifier=OBJECT_IDENTIFIER,
        tool_name=TOOL_NAME,
        arguments=ARGUMENTS,
        approved_principals=principals,
        maximum_validity_seconds=60,
        issuer_public_key=configuration.issuer_public_key,
    )
