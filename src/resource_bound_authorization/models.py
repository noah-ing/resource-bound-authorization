"""Strict records for one resource, action, and optional delegation."""

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=256)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
ArgumentName = Annotated[str, Field(min_length=1, max_length=128)]
ArgumentValue = Annotated[str, Field(max_length=4096)]
Arguments = dict[ArgumentName, ArgumentValue]


class Record(BaseModel):
    """Reject unknown fields and coercions in signed record parsing."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def verify_schema_version_type(cls, schema_version: object) -> int:
        # Literal comparison alone otherwise treats True and 1 as equivalent.
        if type(schema_version) is not int or schema_version != 1:
            raise ValueError("unsupported_schema_version")
        return schema_version


class PrincipalBinding(Record):
    principal_identifier: Identifier
    manifest_digest: Digest
    holder_public_key: Digest
    attestation_digest: Digest
    assurance: Literal["development", "software_tpm"]


class IssuancePolicy(Record):
    audience: Identifier
    object_identifier: Identifier
    tool_name: Identifier
    arguments: Arguments = Field(min_length=1, max_length=16)
    approved_principals: tuple[PrincipalBinding, ...] = Field(min_length=2, max_length=2)
    calling_principal_identifier: Identifier = "calling_principal"
    delegated_principal_identifier: Identifier = "delegated_principal"
    maximum_validity_seconds: int = Field(default=300, ge=1, le=3600)

    @model_validator(mode="after")
    def verify_registered_roles(self) -> Self:
        principal_identifiers = {
            principal.principal_identifier for principal in self.approved_principals
        }
        holder_keys = {principal.holder_public_key for principal in self.approved_principals}
        if (
            len(principal_identifiers) != 2
            or len(holder_keys) != 2
            or principal_identifiers
            != {self.calling_principal_identifier, self.delegated_principal_identifier}
        ):
            raise ValueError("two_distinct_registered_principals_required")
        return self


class ResourcePolicy(IssuancePolicy):
    issuer_public_key: Digest


class CapabilityClaims(Record):
    schema_version: Literal[1] = 1
    capability_identifier: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    authorizing_principal: Literal["user"] = "user"
    principal: PrincipalBinding
    permitted_delegation: PrincipalBinding | None = None
    audience: Identifier
    object_identifier: Identifier
    tool_name: Identifier
    argument_digest: Digest
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=1)

    @model_validator(mode="after")
    def verify_validity_interval(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("invalid_validity_interval")
        return self


class SignedCapability(Record):
    claims: CapabilityClaims
    issuer_signature: Signature


class AttenuationClaims(Record):
    schema_version: Literal[1] = 1
    capability_digest: Digest
    delegating_principal_identifier: Identifier
    delegated_principal: PrincipalBinding
    audience: Identifier
    object_identifier: Identifier
    tool_name: Identifier
    argument_digest: Digest
    expires_at: int = Field(ge=1)


class AttenuationRecord(Record):
    claims: AttenuationClaims
    attenuation_signature: Signature


class CapabilityEnvelope(Record):
    capability: SignedCapability
    attenuation_record: AttenuationRecord | None = None


class InvocationClaims(Record):
    schema_version: Literal[1] = 1
    capability_digest: Digest
    principal_identifier: Identifier
    audience: Identifier
    object_identifier: Identifier
    tool_name: Identifier
    arguments: Arguments = Field(min_length=1, max_length=16)


class SignedInvocation(Record):
    claims: InvocationClaims
    possession_signature: Signature


class ResourceRequest(Record):
    capability: CapabilityEnvelope
    invocation: SignedInvocation


class RedemptionRecord(Record):
    capability_identifier: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    principal_identifier: Identifier
    redemption_time: int = Field(ge=0)
    object_identifier: Identifier | None = None
