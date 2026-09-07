"""Resource enforcement using valid signatures and disposable local fixtures."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resource_bound_authorization.attenuation import append_attenuation_record
from resource_bound_authorization.canonical import capability_digest
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.issuance import issue_capability
from resource_bound_authorization.models import (
    AttenuationRecord,
    CapabilityEnvelope,
    RedemptionRecord,
    ResourceRequest,
    SignedInvocation,
)
from resource_bound_authorization.redemption import RedemptionStore, create_invocation
from resource_bound_authorization.signatures import sign_record
from tests.support import AuthorizationHarness, create_authorization_harness


@pytest.fixture
def authorization_harness(tmp_path: Path) -> AuthorizationHarness:
    return create_authorization_harness(tmp_path)


def test_registered_principal_redeems_exact_action(
    authorization_harness: AuthorizationHarness,
) -> None:
    capability = authorization_harness.issue(permit_delegation=False)
    request = create_invocation(
        capability, authorization_harness.calling_registration.holder_private_key
    )

    record = authorization_harness.dispatch(request)

    assert record.capability_identifier == capability.capability.claims.capability_identifier
    assert record.principal_identifier == "calling_principal"
    assert record.object_identifier == "reference_record"
    assert authorization_harness.handler_invocations == [record]
    assert authorization_harness.consumption_count() == 1


@pytest.mark.parametrize("binding_location", ["capability", "invocation"])
def test_audience_mismatch_rejected(
    authorization_harness: AuthorizationHarness, binding_location: str
) -> None:
    capability = authorization_harness.issue()
    if binding_location == "capability":
        capability = authorization_harness.sign_capability(
            capability.capability.claims.model_copy(update={"audience": "authorization_proxy"})
        )
    request = create_invocation(
        capability,
        authorization_harness.calling_registration.holder_private_key,
        audience="authorization_proxy" if binding_location == "invocation" else None,
    )

    with pytest.raises(AuthorizationError, match="audience_mismatch"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_argument_digest_mismatch_rejected(authorization_harness: AuthorizationHarness) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
        arguments={"record_identifier": "other_record"},
    )

    with pytest.raises(AuthorizationError, match="argument_digest_mismatch"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


@pytest.mark.parametrize(
    ("object_identifier", "tool_name"),
    [("other_record", "object.read"), ("reference_record", "object.update")],
)
def test_object_or_tool_substitution_rejected(
    authorization_harness: AuthorizationHarness, object_identifier: str, tool_name: str
) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
        object_identifier=object_identifier,
        tool_name=tool_name,
    )

    with pytest.raises(AuthorizationError, match="action_binding_mismatch"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_replay_rejected(authorization_harness: AuthorizationHarness) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
    )
    accepted_record = authorization_harness.dispatch(request)

    with pytest.raises(AuthorizationError, match="capability_already_redeemed"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == [accepted_record]
    assert authorization_harness.consumption_count() == 1


def test_second_principal_without_attenuation_rejected(
    authorization_harness: AuthorizationHarness,
) -> None:
    capability = authorization_harness.issue()
    original_request = create_invocation(
        capability, authorization_harness.calling_registration.holder_private_key
    )
    invocation_claims = original_request.invocation.claims.model_copy(
        update={"principal_identifier": "delegated_principal"}
    )
    request = ResourceRequest(
        capability=capability,
        invocation=SignedInvocation(
            claims=invocation_claims,
            possession_signature=sign_record(
                invocation_claims,
                authorization_harness.delegated_registration.holder_private_key,
                "invocation",
            ),
        ),
    )

    with pytest.raises(AuthorizationError, match="principal_binding_mismatch"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


@pytest.mark.parametrize(
    ("object_identifier", "tool_name", "arguments", "expected_code"),
    [
        (
            "other_record",
            "object.read",
            {"record_identifier": "reference_record"},
            "action_binding",
        ),
        (
            "reference_record",
            "object.update",
            {"record_identifier": "reference_record"},
            "action_binding",
        ),
        (
            "reference_record",
            "object.read",
            {"record_identifier": "other_record"},
            "argument_digest",
        ),
    ],
)
def test_attenuated_principal_confined_to_granted_actions(
    authorization_harness: AuthorizationHarness,
    object_identifier: str,
    tool_name: str,
    arguments: dict[str, str],
    expected_code: str,
) -> None:
    capability = authorization_harness.attenuate(authorization_harness.issue())
    permitted_request = create_invocation(
        capability, authorization_harness.delegated_registration.holder_private_key
    )
    accepted_record = authorization_harness.dispatch(permitted_request)
    independent_capability = authorization_harness.attenuate(authorization_harness.issue())
    changed_request = create_invocation(
        independent_capability,
        authorization_harness.delegated_registration.holder_private_key,
        object_identifier=object_identifier,
        tool_name=tool_name,
        arguments=arguments,
    )

    with pytest.raises(AuthorizationError, match=expected_code):
        authorization_harness.dispatch(changed_request)

    assert capability.capability.claims.principal.principal_identifier == "calling_principal"
    assert capability.attenuation_record is not None
    assert accepted_record.principal_identifier == "delegated_principal"
    assert authorization_harness.handler_invocations == [accepted_record]
    assert authorization_harness.consumption_count() == 1


def test_effective_holder_signature_required(authorization_harness: AuthorizationHarness) -> None:
    capability = authorization_harness.attenuate(authorization_harness.issue())
    valid_request = create_invocation(
        capability, authorization_harness.delegated_registration.holder_private_key
    )
    wrong_signature = sign_record(
        valid_request.invocation.claims,
        authorization_harness.calling_registration.holder_private_key,
        "invocation",
    )
    request = valid_request.model_copy(
        update={
            "invocation": valid_request.invocation.model_copy(
                update={"possession_signature": wrong_signature}
            )
        }
    )

    with pytest.raises(AuthorizationError, match="signature_verification_failed"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_removed_attenuation_invalidates_delegated_invocation(
    authorization_harness: AuthorizationHarness,
) -> None:
    capability = authorization_harness.attenuate(authorization_harness.issue())
    request = create_invocation(
        capability, authorization_harness.delegated_registration.holder_private_key
    )
    request = request.model_copy(
        update={"capability": CapabilityEnvelope(capability=capability.capability)}
    )

    with pytest.raises(AuthorizationError, match="principal_binding_mismatch"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


@pytest.mark.parametrize(
    "changed_field", ["audience", "object_identifier", "tool_name", "expires_at"]
)
def test_signed_attenuation_cannot_enlarge_issued_authority(
    authorization_harness: AuthorizationHarness, changed_field: str
) -> None:
    capability = authorization_harness.attenuate(authorization_harness.issue())
    request = create_invocation(
        capability, authorization_harness.delegated_registration.holder_private_key
    )
    assert capability.attenuation_record is not None
    claims = capability.attenuation_record.claims
    changed_value = claims.expires_at + 30 if changed_field == "expires_at" else "other_authority"
    changed_claims = claims.model_copy(update={changed_field: changed_value})
    changed_record = AttenuationRecord(
        claims=changed_claims,
        attenuation_signature=sign_record(
            changed_claims,
            authorization_harness.calling_registration.holder_private_key,
            "attenuation",
        ),
    )
    changed_capability = capability.model_copy(update={"attenuation_record": changed_record})
    invocation_claims = request.invocation.claims.model_copy(
        update={"capability_digest": capability_digest(changed_capability)}
    )
    changed_request = ResourceRequest(
        capability=changed_capability,
        invocation=SignedInvocation(
            claims=invocation_claims,
            possession_signature=sign_record(
                invocation_claims,
                authorization_harness.delegated_registration.holder_private_key,
                "invocation",
            ),
        ),
    )

    with pytest.raises(AuthorizationError, match="attenuation_confinement_mismatch"):
        authorization_harness.dispatch(changed_request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_attenuation_signature_required(authorization_harness: AuthorizationHarness) -> None:
    capability = authorization_harness.attenuate(authorization_harness.issue())
    request = create_invocation(
        capability, authorization_harness.delegated_registration.holder_private_key
    )
    assert capability.attenuation_record is not None
    changed_record = capability.attenuation_record.model_copy(
        update={
            "attenuation_signature": sign_record(
                capability.attenuation_record.claims,
                authorization_harness.delegated_registration.holder_private_key,
                "attenuation",
            )
        }
    )
    changed_request = request.model_copy(
        update={"capability": capability.model_copy(update={"attenuation_record": changed_record})}
    )

    with pytest.raises(AuthorizationError, match="signature_verification_failed"):
        authorization_harness.dispatch(changed_request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_second_attenuation_record_rejected(authorization_harness: AuthorizationHarness) -> None:
    capability = authorization_harness.attenuate(authorization_harness.issue())

    with pytest.raises(AuthorizationError, match="delegation_limit_exceeded"):
        authorization_harness.attenuate(capability)


def test_unpermitted_delegation_rejected(authorization_harness: AuthorizationHarness) -> None:
    capability = authorization_harness.issue(permit_delegation=False)

    with pytest.raises(AuthorizationError, match="delegated_principal_not_endorsed"):
        authorization_harness.attenuate(capability)


def test_unregistered_principal_rejected_at_issuance(
    authorization_harness: AuthorizationHarness,
) -> None:
    changed_principal = authorization_harness.calling_principal.model_copy(
        update={"manifest_digest": "0" * 64}
    )

    with pytest.raises(AuthorizationError, match="principal_registration_mismatch"):
        issue_capability(
            changed_principal,
            authorization_harness.issuer_private_key,
            authorization_harness.policy,
            current_time=authorization_harness.current_time,
        )


def test_unrelated_key_cannot_authorize_attenuation(
    authorization_harness: AuthorizationHarness,
) -> None:
    capability = authorization_harness.issue()

    with pytest.raises(AuthorizationError, match="delegating_key_mismatch"):
        append_attenuation_record(
            capability,
            authorization_harness.delegated_principal,
            Ed25519PrivateKey.generate(),
            authorization_harness.policy,
            current_time=authorization_harness.current_time,
        )


def test_issuer_signature_covers_root_claims(authorization_harness: AuthorizationHarness) -> None:
    capability = authorization_harness.issue()
    changed_claims = capability.capability.claims.model_copy(update={"audience": "other_resource"})
    changed_capability = capability.model_copy(
        update={"capability": capability.capability.model_copy(update={"claims": changed_claims})}
    )
    request = create_invocation(
        changed_capability, authorization_harness.calling_registration.holder_private_key
    )

    with pytest.raises(AuthorizationError, match="signature_verification_failed"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


@pytest.mark.parametrize("time_offset", [-1, 120])
def test_outside_capability_validity_rejected(
    authorization_harness: AuthorizationHarness, time_offset: int
) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
    )

    with pytest.raises(AuthorizationError, match="capability_expired_or_not_yet_valid"):
        authorization_harness.dispatch(
            request, current_time=authorization_harness.current_time + time_offset
        )

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_issuer_signed_excessive_validity_rejected(
    authorization_harness: AuthorizationHarness,
) -> None:
    capability = authorization_harness.issue()
    claims = capability.capability.claims
    capability = authorization_harness.sign_capability(
        claims.model_copy(update={"expires_at": claims.issued_at + 301})
    )
    request = create_invocation(
        capability, authorization_harness.calling_registration.holder_private_key
    )

    with pytest.raises(AuthorizationError, match="capability_validity_exceeds_policy"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


@pytest.mark.parametrize("delegated_first", [False, True])
def test_original_and_delegated_redemption_share_consumption(
    authorization_harness: AuthorizationHarness, delegated_first: bool
) -> None:
    capability = authorization_harness.issue()
    original_request = create_invocation(
        capability, authorization_harness.calling_registration.holder_private_key
    )
    delegated_request = create_invocation(
        authorization_harness.attenuate(capability),
        authorization_harness.delegated_registration.holder_private_key,
    )
    requests = (
        (delegated_request, original_request)
        if delegated_first
        else (original_request, delegated_request)
    )
    accepted_record = authorization_harness.dispatch(requests[0])

    with pytest.raises(AuthorizationError, match="capability_already_redeemed"):
        authorization_harness.dispatch(requests[1])

    assert authorization_harness.handler_invocations == [accepted_record]
    assert authorization_harness.consumption_count() == 1


def test_redemption_at_most_once(authorization_harness: AuthorizationHarness) -> None:
    capability = authorization_harness.issue()
    original_request = create_invocation(
        capability, authorization_harness.calling_registration.holder_private_key
    )
    delegated_request = create_invocation(
        authorization_harness.attenuate(capability),
        authorization_harness.delegated_registration.holder_private_key,
    )
    assert (
        original_request.invocation.possession_signature
        != delegated_request.invocation.possession_signature
    )
    stores = [RedemptionStore(authorization_harness.store.database_path) for _ in range(8)]
    request_barrier = threading.Barrier(len(stores))

    def consume_request(request_index: int) -> RedemptionRecord | str:
        request = original_request if request_index % 2 == 0 else delegated_request
        request_barrier.wait(timeout=10)
        try:
            return authorization_harness.dispatch(request, store=stores[request_index])
        except AuthorizationError as exception:
            return exception.code

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        results = list(executor.map(consume_request, range(len(stores))))

    accepted = [result for result in results if isinstance(result, RedemptionRecord)]
    rejected = [result for result in results if isinstance(result, str)]
    assert len(accepted) == 1
    assert rejected == ["capability_already_redeemed"] * 7
    assert authorization_harness.handler_invocations == accepted
    assert authorization_harness.consumption_count() == 1


def test_consumption_persists_after_database_reopen(
    authorization_harness: AuthorizationHarness,
) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
    )
    accepted_record = authorization_harness.dispatch(request)
    reopened_store = RedemptionStore(authorization_harness.store.database_path)

    with pytest.raises(AuthorizationError, match="capability_already_redeemed"):
        authorization_harness.dispatch(request, store=reopened_store)

    assert authorization_harness.handler_invocations == [accepted_record]
    assert authorization_harness.consumption_count() == 1


def test_database_corruption_rejects_before_dispatch(
    authorization_harness: AuthorizationHarness,
) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
    )
    authorization_harness.store.database_path.write_bytes(b"invalid reference database")

    with pytest.raises(AuthorizationError, match="redemption_storage_unavailable"):
        authorization_harness.dispatch(request)

    assert authorization_harness.handler_invocations == []


@pytest.mark.parametrize("database_path", ["", ":memory:"])
def test_nonpersistent_redemption_database_rejected(database_path: str) -> None:
    with pytest.raises(AuthorizationError, match="persistent_redemption_database_required"):
        RedemptionStore(database_path)
