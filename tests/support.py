"""Generated registration and dispatch observations for confinement tests."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fixtures.registration import (
    RegistrationFixture,
    create_development_attestation,
    generate_registration_fixture,
)
from resource_bound_authorization.attenuation import append_attenuation_record
from resource_bound_authorization.issuance import issue_capability
from resource_bound_authorization.models import (
    CapabilityClaims,
    CapabilityEnvelope,
    PrincipalBinding,
    RedemptionRecord,
    ResourcePolicy,
    ResourceRequest,
    SignedCapability,
)
from resource_bound_authorization.redemption import RedemptionStore, redeem_capability
from resource_bound_authorization.signatures import public_key_hex, sign_record
from resource_bound_authorization.verification import verify_development_attestation


@dataclass
class AuthorizationHarness:
    """Exercise verified bindings and observe dispatch only after redemption."""

    calling_registration: RegistrationFixture
    delegated_registration: RegistrationFixture
    calling_principal: PrincipalBinding
    delegated_principal: PrincipalBinding
    issuer_private_key: Ed25519PrivateKey
    policy: ResourcePolicy
    store: RedemptionStore
    current_time: int
    handler_invocations: list[RedemptionRecord] = field(default_factory=list)
    invocation_lock: threading.Lock = field(default_factory=threading.Lock)

    def issue(self, *, permit_delegation: bool = True) -> CapabilityEnvelope:
        return issue_capability(
            self.calling_principal,
            self.issuer_private_key,
            self.policy,
            current_time=self.current_time,
            delegated_principal=self.delegated_principal if permit_delegation else None,
        )

    def attenuate(self, capability: CapabilityEnvelope) -> CapabilityEnvelope:
        return append_attenuation_record(
            capability,
            self.delegated_principal,
            self.calling_registration.holder_private_key,
            self.policy,
            current_time=self.current_time,
        )

    def sign_capability(self, claims: CapabilityClaims) -> CapabilityEnvelope:
        """Authenticate deliberately different claims to isolate policy enforcement."""
        return CapabilityEnvelope(
            capability=SignedCapability(
                claims=claims,
                issuer_signature=sign_record(claims, self.issuer_private_key, "issuance"),
            )
        )

    def dispatch(
        self,
        request: ResourceRequest,
        *,
        headers: Mapping[str, str] | None = None,
        current_time: int | None = None,
        store: RedemptionStore | None = None,
    ) -> RedemptionRecord:
        record = redeem_capability(
            request,
            self.policy,
            self.store if store is None else store,
            headers=headers,
            current_time=self.current_time if current_time is None else current_time,
        )
        with self.invocation_lock:
            self.handler_invocations.append(record)
        return record

    def consumption_count(self) -> int:
        with closing(sqlite3.connect(self.store.database_path)) as connection:
            result = connection.execute("SELECT count(*) FROM redemption_records").fetchone()
        assert result is not None
        return int(result[0])


def create_authorization_harness(directory: Path) -> AuthorizationHarness:
    """Use released manifest verification for each generated registered principal."""
    current_time = int(time.time())
    calling_registration = generate_registration_fixture("calling_principal", now=current_time)
    delegated_registration = generate_registration_fixture("delegated_principal", now=current_time)
    principal_bindings = []
    for registration_fixture in (calling_registration, delegated_registration):
        challenge = (
            "confinement-verification-" + registration_fixture.registration.principal_identifier
        )
        evidence = create_development_attestation(
            registration_fixture, challenge, current_time + 60
        )
        principal_bindings.append(
            verify_development_attestation(
                registration_fixture.registration,
                evidence,
                expected_challenge=challenge,
                now=current_time,
            )
        )
    calling_principal, delegated_principal = principal_bindings
    issuer_private_key = Ed25519PrivateKey.generate()
    policy = ResourcePolicy(
        audience="resource_server",
        object_identifier="reference_record",
        tool_name="object.read",
        arguments={"record_identifier": "reference_record"},
        approved_principals=(calling_principal, delegated_principal),
        issuer_public_key=public_key_hex(issuer_private_key),
    )
    return AuthorizationHarness(
        calling_registration=calling_registration,
        delegated_registration=delegated_registration,
        calling_principal=calling_principal,
        delegated_principal=delegated_principal,
        issuer_private_key=issuer_private_key,
        policy=policy,
        store=RedemptionStore(directory / "redemption.sqlite"),
        current_time=current_time,
    )
