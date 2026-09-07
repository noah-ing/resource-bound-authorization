"""Inert counterfactual and live MCP confinement, with enforcement always enabled."""

import asyncio
import json
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import httpx2
import mcp_types as protocol
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from examples.confined_redemption.attestation import create_principal_attestation
from examples.confined_redemption.mcp_protocol import AUTHORIZATION_METADATA_KEY, PROTOCOL_VERSION
from examples.confined_redemption.registration import load_role_private
from examples.confined_redemption.service import send_request
from examples.unauthorized_forwarding.demonstration import demonstrate_unauthorized_forwarding
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.models import (
    CapabilityEnvelope,
    ResourceRequest,
    SignedCapability,
)
from resource_bound_authorization.redemption import create_invocation, redeem_capability
from resource_bound_authorization.signatures import load_private_key, sign_record
from tests.support import create_authorization_harness
from tests.test_services import ServiceHarness, reference_services  # noqa: F401


def test_unauthorized_forwarding_demonstration_succeeds_when_confinement_disabled(
    tmp_path: Path,
) -> None:
    result = demonstrate_unauthorized_forwarding()
    assert result["confinement_disabled"] is True
    assert result["confinement_enabled"] is False
    assert result["network_requests"] == "none"
    harness = create_authorization_harness(tmp_path)
    request = create_invocation(
        harness.issue(),
        harness.calling_registration.holder_private_key,
        object_identifier="different_record",
        arguments={"record_identifier": "different_record"},
    )
    with pytest.raises(AuthorizationError):
        redeem_capability(request, harness.policy, harness.store)


@pytest.mark.parametrize("audience_binding", ["capability", "invocation"])
def test_audience_confinement_through_running_proxy(
    reference_services: ServiceHarness,  # noqa: F811 - imported pytest fixture
    monkeypatch: pytest.MonkeyPatch,
    audience_binding: str,
) -> None:
    """Verify both audience checks over real HTTP without replacing authorization."""
    private = load_role_private(reference_services.directory, "calling_principal")
    status, challenge = send_request(
        "authorization_server", "/challenge", {}, destinations=reference_services.destinations
    )
    assert status == 200
    evidence = create_principal_attestation(
        reference_services.directory,
        "calling_principal",
        challenge["challenge"],
        challenge["expires_at"],
    )
    status, issuance = send_request(
        "authorization_server",
        "/issuance",
        {
            "challenge": challenge["challenge"],
            "calling_attestation": evidence.model_dump(mode="json"),
        },
        destinations=reference_services.destinations,
    )
    assert status == 200
    assert issuance["assurance"] == "development"
    capability = CapabilityEnvelope.model_validate(issuance["capability"])
    holder_key = load_private_key(private["holder_private_key"])
    granted = create_invocation(capability, holder_key)
    if audience_binding == "capability":
        # Sign a negative fixture using this test's generated issuer key. This
        # preserves the identifier but is a different authenticated claim record.
        issuer = load_role_private(reference_services.directory, "authorization_server")
        claims = capability.capability.claims.model_copy(update={"audience": "authorization_proxy"})
        mismatched_capability = CapabilityEnvelope(
            capability=SignedCapability(
                claims=claims,
                issuer_signature=sign_record(
                    claims, load_private_key(issuer["issuer_private_key"]), "issuance"
                ),
            )
        )
        # Keep the invocation audience correct to isolate capability verification.
        mismatched = create_invocation(
            mismatched_capability, holder_key, audience=granted.invocation.claims.audience
        )
    else:
        # The issued capability is unchanged; only the signed invocation differs.
        mismatched = create_invocation(capability, holder_key, audience="authorization_proxy")

    resource = reference_services.servers["resource_server"].application
    assert resource.store is not None
    database_path = resource.store.database_path
    capability_identifier = capability.capability.claims.capability_identifier
    observations: list[tuple[dict[str, Any], dict[str, str]]] = []
    resource_handler = resource.handle

    def observe_resource_request(
        method: str, path: str, document: dict[str, Any], headers: Mapping[str, str]
    ) -> tuple[int, dict[str, Any]]:
        if method == "POST" and path == "/mcp" and document.get("method") == "tools/call":
            observations.append((deepcopy(document), dict(headers)))
        return resource_handler(method, path, document, headers)

    # Observation only: every request still reaches the unmodified service handler.
    monkeypatch.setattr(resource, "handle", observe_resource_request)

    def verify_consumption(expected: int) -> None:
        with closing(sqlite3.connect(database_path)) as connection:
            rows = connection.execute(
                "SELECT capability_identifier, principal_identifier FROM redemption_records"
            ).fetchall()
        assert rows == [(capability_identifier, "calling_principal")] * expected
        assert resource.handler_count == expected

    def verify_resource_request(request: ResourceRequest, expected_count: int) -> None:
        assert len(observations) == expected_count
        document, headers = observations[-1]
        assert document["params"]["name"] == "object.read"
        assert document["params"]["arguments"] == {"record_identifier": "reference_record"}
        assert document["params"]["_meta"][AUTHORIZATION_METADATA_KEY] == request.model_dump(
            mode="json"
        )
        assert {name.casefold() for name in headers}.isdisjoint(
            {"authorization", "proxy-authorization"}
        )
        assert private["proxy_bearer_credential"] not in json.dumps(document)

    host, port = reference_services.destinations["authorization_proxy"]

    async def verify_client() -> None:
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + private["proxy_bearer_credential"]},
            trust_env=False,
            timeout=10,
        ) as http_client:
            transport = streamable_http_client(f"http://{host}:{port}/mcp", http_client=http_client)
            async with Client(transport, cache=None) as client:
                assert client.protocol_version == PROTOCOL_VERSION

                async def call(request: ResourceRequest) -> protocol.CallToolResult:
                    return await client.call_tool(
                        "object.read",
                        {"record_identifier": "reference_record"},
                        meta=cast(
                            protocol.RequestParamsMeta,
                            {AUTHORIZATION_METADATA_KEY: request.model_dump(mode="json")},
                        ),
                    )

                verify_consumption(0)
                rejected = await call(mismatched)
                assert rejected.is_error is True
                assert rejected.structured_content == {"error": "audience_mismatch"}
                verify_resource_request(mismatched, 1)
                verify_consumption(0)

                accepted = await call(granted)
                assert accepted.is_error is False
                assert accepted.structured_content["redemption"]["capability_identifier"] == (
                    capability_identifier
                )
                assert accepted.structured_content["redemption"]["principal_identifier"] == (
                    "calling_principal"
                )
                assert accepted.structured_content["result"]["record_identifier"] == (
                    "reference_record"
                )
                verify_resource_request(granted, 2)
                verify_consumption(1)

                repeated = await call(granted)
                assert repeated.is_error is True
                assert repeated.structured_content == {"error": "capability_already_redeemed"}
                verify_resource_request(granted, 3)
                verify_consumption(1)

    asyncio.run(verify_client())
    print(
        json.dumps(
            {
                "phase": "request_confinement_verification",
                "assurance": "development",
                "transport": "mcp_streamable_http",
                "protocol_version": PROTOCOL_VERSION,
                "audience_binding": audience_binding,
                "confinement": "enabled",
                "mismatched_audience": "rejected",
                "consumption_after_rejection": 0,
                "original_granted_request": "accepted",
                "repeat_redemption": "rejected",
                "resource_tool_requests": len(observations),
                "handler_invocations": resource.handler_count,
            },
            sort_keys=True,
        )
    )
