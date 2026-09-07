"""Issuance from independently verified principal bindings and fixed policy."""

import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resource_bound_authorization.audience import verify_audience
from resource_bound_authorization.canonical import canonical_argument_digest
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.models import (
    CapabilityClaims,
    CapabilityEnvelope,
    IssuancePolicy,
    PrincipalBinding,
    ResourcePolicy,
    SignedCapability,
)
from resource_bound_authorization.signatures import sign_record, verify_record_signature


def resolve_current_time(current_time: int | None) -> int:
    resolved_time = int(time.time()) if current_time is None else current_time
    if type(resolved_time) is not int or resolved_time < 0:
        raise AuthorizationError("invalid_current_time")
    return resolved_time


def verify_registered_principal(
    principal: PrincipalBinding, policy: IssuancePolicy, principal_identifier: str
) -> None:
    """Compare stable enrollment fields; fresh evidence is authenticated by issuance."""
    if principal.principal_identifier != principal_identifier:
        raise AuthorizationError("principal_role_mismatch")
    for registered_principal in policy.approved_principals:
        if (
            registered_principal.principal_identifier == principal.principal_identifier
            and registered_principal.manifest_digest == principal.manifest_digest
            and registered_principal.holder_public_key == principal.holder_public_key
            and registered_principal.assurance == principal.assurance
        ):
            return
    raise AuthorizationError("principal_registration_mismatch")


def issue_capability(
    principal: PrincipalBinding,
    issuer_private_key: Ed25519PrivateKey,
    policy: IssuancePolicy,
    *,
    current_time: int | None = None,
    validity_seconds: int = 120,
    delegated_principal: PrincipalBinding | None = None,
) -> CapabilityEnvelope:
    """Sign verified bindings; callers must verify fresh evidence before this boundary."""
    issuance_time = resolve_current_time(current_time)
    verify_registered_principal(principal, policy, policy.calling_principal_identifier)
    if delegated_principal is not None:
        verify_registered_principal(
            delegated_principal, policy, policy.delegated_principal_identifier
        )
    if (
        type(validity_seconds) is not int
        or not 1 <= validity_seconds <= policy.maximum_validity_seconds
    ):
        raise AuthorizationError("invalid_capability_validity")
    claims = CapabilityClaims(
        capability_identifier=uuid.uuid4().hex,
        principal=principal,
        permitted_delegation=delegated_principal,
        audience=policy.audience,
        object_identifier=policy.object_identifier,
        tool_name=policy.tool_name,
        argument_digest=canonical_argument_digest(policy.arguments),
        issued_at=issuance_time,
        expires_at=issuance_time + validity_seconds,
    )
    return CapabilityEnvelope(
        capability=SignedCapability(
            claims=claims,
            issuer_signature=sign_record(claims, issuer_private_key, "issuance"),
        )
    )


def verify_capability(
    capability: SignedCapability, policy: ResourcePolicy, current_time: int
) -> CapabilityClaims:
    """Verify issuer authentication, enrollment, action policy, and validity."""
    claims = capability.claims
    verify_record_signature(
        claims, capability.issuer_signature, policy.issuer_public_key, "issuance"
    )
    verify_audience(claims.audience, policy.audience)
    verify_registered_principal(claims.principal, policy, policy.calling_principal_identifier)
    if claims.permitted_delegation is not None:
        verify_registered_principal(
            claims.permitted_delegation, policy, policy.delegated_principal_identifier
        )
    if (
        claims.object_identifier != policy.object_identifier
        or claims.tool_name != policy.tool_name
        or claims.argument_digest != canonical_argument_digest(policy.arguments)
    ):
        raise AuthorizationError("issuance_policy_mismatch")
    if not claims.issued_at <= current_time < claims.expires_at:
        raise AuthorizationError("capability_expired_or_not_yet_valid")
    if claims.expires_at - claims.issued_at > policy.maximum_validity_seconds:
        raise AuthorizationError("capability_validity_exceeds_policy")
    return claims
