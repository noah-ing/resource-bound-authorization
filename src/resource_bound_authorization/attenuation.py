"""One signed delegation constrained to the issued resource action."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resource_bound_authorization.canonical import root_capability_digest
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.issuance import resolve_current_time, verify_capability
from resource_bound_authorization.models import (
    AttenuationClaims,
    AttenuationRecord,
    CapabilityEnvelope,
    PrincipalBinding,
    ResourcePolicy,
)
from resource_bound_authorization.signatures import (
    public_key_hex,
    sign_record,
    verify_record_signature,
)


def append_attenuation_record(
    capability: CapabilityEnvelope,
    delegated_principal: PrincipalBinding,
    original_private_key: Ed25519PrivateKey,
    policy: ResourcePolicy,
    *,
    current_time: int | None = None,
) -> CapabilityEnvelope:
    """Record the issuer-approved second principal without broadening authority."""
    if capability.attenuation_record is not None:
        raise AuthorizationError("delegation_limit_exceeded")
    root_claims = verify_capability(
        capability.capability, policy, resolve_current_time(current_time)
    )
    if root_claims.permitted_delegation != delegated_principal:
        raise AuthorizationError("delegated_principal_not_endorsed")
    if public_key_hex(original_private_key) != root_claims.principal.holder_public_key:
        raise AuthorizationError("delegating_key_mismatch")
    claims = AttenuationClaims(
        capability_digest=root_capability_digest(capability.capability),
        delegating_principal_identifier=root_claims.principal.principal_identifier,
        delegated_principal=delegated_principal,
        audience=root_claims.audience,
        object_identifier=root_claims.object_identifier,
        tool_name=root_claims.tool_name,
        argument_digest=root_claims.argument_digest,
        expires_at=root_claims.expires_at,
    )
    return CapabilityEnvelope(
        capability=capability.capability,
        attenuation_record=AttenuationRecord(
            claims=claims,
            attenuation_signature=sign_record(claims, original_private_key, "attenuation"),
        ),
    )


def verify_attenuation_record(capability: CapabilityEnvelope) -> PrincipalBinding:
    """Resolve the effective principal only through a complete signed attenuation."""
    root_claims = capability.capability.claims
    record = capability.attenuation_record
    if record is None:
        return root_claims.principal
    claims = record.claims
    verify_record_signature(
        claims,
        record.attenuation_signature,
        root_claims.principal.holder_public_key,
        "attenuation",
    )
    if (
        claims.capability_digest != root_capability_digest(capability.capability)
        or claims.delegating_principal_identifier != root_claims.principal.principal_identifier
        or claims.delegated_principal != root_claims.permitted_delegation
        or claims.audience != root_claims.audience
        or claims.object_identifier != root_claims.object_identifier
        or claims.tool_name != root_claims.tool_name
        or claims.argument_digest != root_claims.argument_digest
        or claims.expires_at != root_claims.expires_at
    ):
        raise AuthorizationError("attenuation_confinement_mismatch")
    return claims.delegated_principal
