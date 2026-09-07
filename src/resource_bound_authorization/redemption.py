"""Possession-bound verification and persistent at-most-once consumption."""

import hmac
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resource_bound_authorization.attenuation import verify_attenuation_record
from resource_bound_authorization.audience import verify_audience
from resource_bound_authorization.canonical import (
    canonical_argument_digest,
    capability_digest,
)
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.forwarding import reject_forwarded_bearer
from resource_bound_authorization.issuance import resolve_current_time, verify_capability
from resource_bound_authorization.models import (
    CapabilityEnvelope,
    InvocationClaims,
    RedemptionRecord,
    ResourcePolicy,
    ResourceRequest,
    SignedInvocation,
)
from resource_bound_authorization.signatures import (
    public_key_hex,
    sign_record,
    verify_record_signature,
)


class RedemptionStore:
    """One durable database; consumption commits before the resource action begins."""

    def __init__(self, database_path: str | Path) -> None:
        if str(database_path) in {"", ":memory:"}:
            raise AuthorizationError("persistent_redemption_database_required")
        self.database_path = Path(database_path)
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS redemption_records ("
                    "capability_identifier TEXT PRIMARY KEY NOT NULL, "
                    "principal_identifier TEXT NOT NULL, "
                    "redemption_time INTEGER NOT NULL)"
                )
        except (sqlite3.Error, OSError) as exception:
            raise AuthorizationError("redemption_storage_unavailable") from exception

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0, isolation_level=None)
        try:
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def consume(
        self,
        capability_identifier: str,
        principal_identifier: str,
        redemption_time: int,
        *,
        expires_at: int | None = None,
        current_time: int | None = None,
    ) -> RedemptionRecord:
        """Atomically reserve the shared root identifier; storage errors fail closed."""
        record = RedemptionRecord(
            capability_identifier=capability_identifier,
            principal_identifier=principal_identifier,
            redemption_time=redemption_time,
        )
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if expires_at is not None:
                    consumption_time = resolve_current_time(current_time)
                    if not redemption_time <= consumption_time < expires_at:
                        raise AuthorizationError("capability_expired_or_clock_changed")
                    record = RedemptionRecord(
                        capability_identifier=capability_identifier,
                        principal_identifier=principal_identifier,
                        redemption_time=consumption_time,
                    )
                connection.execute(
                    "INSERT INTO redemption_records "
                    "(capability_identifier, principal_identifier, redemption_time) "
                    "VALUES (?, ?, ?)",
                    (
                        record.capability_identifier,
                        record.principal_identifier,
                        record.redemption_time,
                    ),
                )
                connection.execute("COMMIT")
        except sqlite3.IntegrityError as exception:
            raise AuthorizationError("capability_already_redeemed") from exception
        except (sqlite3.Error, OSError) as exception:
            raise AuthorizationError("redemption_storage_unavailable") from exception
        return record


def verify_action_digest(arguments: dict[str, str], expected_digest: str) -> None:
    if not hmac.compare_digest(canonical_argument_digest(arguments), expected_digest):
        raise AuthorizationError("argument_digest_mismatch")


def create_invocation(
    capability: CapabilityEnvelope,
    holder_private_key: Ed25519PrivateKey,
    *,
    arguments: dict[str, str] | None = None,
    object_identifier: str | None = None,
    tool_name: str | None = None,
    audience: str | None = None,
) -> ResourceRequest:
    """Sign invocation context with the effective principal's possession key."""
    effective_principal = verify_attenuation_record(capability)
    if public_key_hex(holder_private_key) != effective_principal.holder_public_key:
        raise AuthorizationError("holder_key_mismatch")
    root_claims = capability.capability.claims
    claims = InvocationClaims(
        capability_digest=capability_digest(capability),
        principal_identifier=effective_principal.principal_identifier,
        audience=root_claims.audience if audience is None else audience,
        object_identifier=(
            root_claims.object_identifier if object_identifier is None else object_identifier
        ),
        tool_name=root_claims.tool_name if tool_name is None else tool_name,
        arguments=(
            {"record_identifier": root_claims.object_identifier}
            if arguments is None
            else dict(arguments)
        ),
    )
    return ResourceRequest(
        capability=capability,
        invocation=SignedInvocation(
            claims=claims,
            possession_signature=sign_record(claims, holder_private_key, "invocation"),
        ),
    )


def redeem_capability(
    request: ResourceRequest,
    policy: ResourcePolicy,
    store: RedemptionStore,
    *,
    headers: Mapping[str, str] | None = None,
    current_time: int | None = None,
) -> RedemptionRecord:
    """Verify every binding, then commit consumption before returning permission."""
    reject_forwarded_bearer(headers)
    redemption_time = resolve_current_time(current_time)
    root_claims = verify_capability(request.capability.capability, policy, redemption_time)
    effective_principal = verify_attenuation_record(request.capability)
    claims = request.invocation.claims
    if claims.principal_identifier != effective_principal.principal_identifier:
        raise AuthorizationError("principal_binding_mismatch")
    verify_record_signature(
        claims,
        request.invocation.possession_signature,
        effective_principal.holder_public_key,
        "invocation",
    )
    if claims.capability_digest != capability_digest(request.capability):
        raise AuthorizationError("invocation_capability_mismatch")
    verify_audience(claims.audience, policy.audience)
    if (
        claims.object_identifier != root_claims.object_identifier
        or claims.tool_name != root_claims.tool_name
    ):
        raise AuthorizationError("action_binding_mismatch")
    verify_action_digest(claims.arguments, root_claims.argument_digest)
    redemption = store.consume(
        root_claims.capability_identifier,
        effective_principal.principal_identifier,
        redemption_time,
        expires_at=root_claims.expires_at,
        current_time=current_time,
    )
    return RedemptionRecord(
        capability_identifier=redemption.capability_identifier,
        principal_identifier=redemption.principal_identifier,
        redemption_time=redemption.redemption_time,
        object_identifier=root_claims.object_identifier,
    )
