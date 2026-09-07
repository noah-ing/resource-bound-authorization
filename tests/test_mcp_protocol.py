"""SDK interoperability and negative checks for the narrow current MCP profile."""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import httpx2
import mcp_types as protocol
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from examples.confined_redemption.attestation import create_principal_attestation
from examples.confined_redemption.mcp_protocol import (
    AUTHORIZATION_METADATA_KEY,
    PROTOCOL_VERSION,
    create_mcp_request,
    create_mcp_tool_call,
    decode_mcp_tool_result,
    dispatch_mcp_request,
    mcp_request_headers,
)
from examples.confined_redemption.registration import load_role_private
from examples.confined_redemption.service import send_request
from resource_bound_authorization.forwarding import build_forwarding_request
from resource_bound_authorization.models import CapabilityEnvelope, ResourceRequest
from resource_bound_authorization.redemption import create_invocation
from resource_bound_authorization.signatures import load_private_key
from tests.support import AuthorizationHarness, create_authorization_harness
from tests.test_services import ServiceHarness, reference_services  # noqa: F401


@pytest.fixture
def authorization_harness(tmp_path: Path) -> AuthorizationHarness:
    return create_authorization_harness(tmp_path)


def _request(harness: AuthorizationHarness) -> ResourceRequest:
    return create_invocation(harness.issue(), harness.calling_registration.holder_private_key)


def _authorization_metadata(request: ResourceRequest) -> protocol.RequestParamsMeta:
    return cast(
        protocol.RequestParamsMeta,
        {AUTHORIZATION_METADATA_KEY: request.model_dump(mode="json")},
    )


def _execute(harness: AuthorizationHarness, request: ResourceRequest) -> tuple[int, dict[str, Any]]:
    record = harness.dispatch(request)
    return 200, {
        "record_identifier": record.object_identifier,
        "principal_identifier": record.principal_identifier,
    }


def test_released_sdk_client_discovers_lists_and_calls_through_both_mcp_hops(
    authorization_harness: AuthorizationHarness,
) -> None:
    """Exercise the actual SDK HTTP client against both adapters without opening ports."""
    invocation = _request(authorization_harness)
    credential = secrets.token_urlsafe(32)
    observed_methods: list[str] = []
    forwarded_requests: list[tuple[dict[str, str], dict[str, Any]]] = []

    def respond(http_request: httpx2.Request) -> httpx2.Response:
        if http_request.method != "POST":
            return httpx2.Response(405)
        document = json.loads(http_request.content)
        observed_methods.append(document["method"])
        assert http_request.headers["authorization"] == "Bearer " + credential

        def forward(request: ResourceRequest) -> tuple[int, dict[str, Any]]:
            _headers, body = build_forwarding_request(request, http_request.headers)
            downstream = create_mcp_tool_call(ResourceRequest.model_validate_json(body))
            downstream_headers = mcp_request_headers(downstream)
            forwarded_requests.append((downstream_headers, downstream))
            status, response = dispatch_mcp_request(
                downstream,
                lambda verified: _execute(authorization_harness, verified),
                headers=downstream_headers,
            )
            return decode_mcp_tool_result(
                status, response, expected_request_identifier=downstream["id"]
            )

        status, response = dispatch_mcp_request(document, forward, headers=http_request.headers)
        return httpx2.Response(status, json=response)

    async def verify_client() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(respond),
            headers={"Authorization": "Bearer " + credential},
            trust_env=False,
        ) as http_client:
            transport = streamable_http_client(
                "http://authorization-proxy.test/mcp", http_client=http_client
            )
            async with Client(transport, cache=None) as client:
                assert client.protocol_version == PROTOCOL_VERSION
                listing = await client.list_tools()
                assert [tool.name for tool in listing.tools] == ["object.read"]
                result = await client.call_tool(
                    "object.read",
                    {"record_identifier": "reference_record"},
                    meta=_authorization_metadata(invocation),
                )
                assert result.is_error is False
                assert result.structured_content["record_identifier"] == "reference_record"
                repeated = await client.call_tool(
                    "object.read",
                    {"record_identifier": "reference_record"},
                    meta=_authorization_metadata(invocation),
                )
                assert repeated.is_error is True
                assert repeated.structured_content == {"error": "capability_already_redeemed"}

    asyncio.run(verify_client())
    assert observed_methods == ["server/discover", "tools/list", "tools/call", "tools/call"]
    assert len(authorization_harness.handler_invocations) == 1
    assert len(forwarded_requests) == 2
    for headers, document in forwarded_requests:
        assert "authorization" not in {name.casefold() for name in headers}
        assert credential not in json.dumps(document)
        assert document["method"] == "tools/call"


@pytest.mark.parametrize(
    "reference_services",
    ["development", pytest.param("software_tpm", marks=pytest.mark.software_tpm)],
    indirect=True,
)
def test_released_sdk_client_calls_running_proxy_and_resource(
    reference_services: ServiceHarness,  # noqa: F811 - imported pytest fixture
) -> None:
    """Use the released SDK against the actual reference HTTP services on loopback."""
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
    invocation = create_invocation(
        CapabilityEnvelope.model_validate(issuance["capability"]),
        load_private_key(private["holder_private_key"]),
    )
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
                listing = await client.list_tools()
                assert [tool.name for tool in listing.tools] == ["object.read"]
                result = await client.call_tool(
                    "object.read",
                    {"record_identifier": "reference_record"},
                    meta=_authorization_metadata(invocation),
                )
                assert result.is_error is False
                assert result.structured_content["result"]["record_identifier"] == (
                    "reference_record"
                )

    asyncio.run(verify_client())
    assert reference_services.servers["resource_server"].application.handler_count == 1


@pytest.mark.parametrize("identifier", [None, True, 1.5, [], {}, "a" * 257])
def test_invalid_jsonrpc_identifiers_rejected(identifier: Any) -> None:
    request = create_mcp_request("tools/list")
    headers = mcp_request_headers(request)
    request["id"] = identifier
    status, response = dispatch_mcp_request(request, lambda _request: (200, {}), headers=headers)
    assert status == 400
    assert response["error"]["code"] == protocol.INVALID_REQUEST


@pytest.mark.parametrize(
    "method", ["initialize", "notifications/initialized", "notifications/cancelled"]
)
def test_legacy_handshake_and_notifications_are_outside_current_profile(method: str) -> None:
    request = create_mcp_request("tools/list")
    request["method"] = method
    headers = mcp_request_headers(request)
    if method.startswith("notifications/"):
        del request["id"]
    status, _response = dispatch_mcp_request(request, lambda _request: (200, {}), headers=headers)
    assert status in {400, 404}


@pytest.mark.parametrize("header", ["MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"])
def test_mcp_mirrored_header_mismatch_rejected(
    authorization_harness: AuthorizationHarness, header: str
) -> None:
    document = create_mcp_tool_call(_request(authorization_harness))
    headers = mcp_request_headers(document)
    headers[header] = "unregistered_value"
    status, response = dispatch_mcp_request(document, lambda _request: (200, {}), headers=headers)
    assert status == 400
    assert response["error"]["code"] == protocol.HEADER_MISMATCH
    assert authorization_harness.handler_invocations == []


def test_mcp_protocol_version_negotiation_reports_supported_version() -> None:
    document = create_mcp_request("server/discover")
    headers = mcp_request_headers(document)
    document["params"]["_meta"][protocol.PROTOCOL_VERSION_META_KEY] = "2025-11-25"
    headers["MCP-Protocol-Version"] = "2025-11-25"
    status, response = dispatch_mcp_request(document, lambda _request: (200, {}), headers=headers)
    assert status == 400
    assert response["error"]["code"] == protocol.UNSUPPORTED_PROTOCOL_VERSION
    assert response["error"]["data"]["supported"] == [PROTOCOL_VERSION]


@pytest.mark.parametrize(
    "headers", [{"Origin": "https://unregistered.example"}, {"Accept": "application/json"}]
)
def test_mcp_transport_requirements_rejected(headers: Mapping[str, str]) -> None:
    document = create_mcp_request("tools/list")
    status, _response = dispatch_mcp_request(
        document, lambda _request: (200, {}), headers={**mcp_request_headers(document), **headers}
    )
    assert status in {403, 406}


def test_mcp_outer_arguments_must_equal_signed_invocation(
    authorization_harness: AuthorizationHarness,
) -> None:
    document = create_mcp_tool_call(_request(authorization_harness))
    document["params"]["arguments"]["record_identifier"] = "different_record"
    status, response = dispatch_mcp_request(
        document,
        lambda request: _execute(authorization_harness, request),
        headers=mcp_request_headers(document),
    )
    assert decode_mcp_tool_result(status, response) == (
        403,
        {"error": "action_binding_mismatch"},
    )
    assert authorization_harness.handler_invocations == []


def test_mcp_authorization_metadata_is_required(
    authorization_harness: AuthorizationHarness,
) -> None:
    document = create_mcp_tool_call(_request(authorization_harness))
    del document["params"]["_meta"][AUTHORIZATION_METADATA_KEY]
    status, response = dispatch_mcp_request(
        document,
        lambda request: _execute(authorization_harness, request),
        headers=mcp_request_headers(document),
    )
    assert decode_mcp_tool_result(status, response)[0] == 403
    assert authorization_harness.handler_invocations == []


def test_mcp_rejection_does_not_reflect_unknown_callback_error(
    authorization_harness: AuthorizationHarness,
) -> None:
    document = create_mcp_tool_call(_request(authorization_harness))
    credential = secrets.token_urlsafe(32)
    status, response = dispatch_mcp_request(
        document,
        lambda _request: (403, {"error": credential}),
        headers=mcp_request_headers(document),
    )
    assert credential not in json.dumps(response)
    assert decode_mcp_tool_result(status, response) == (
        403,
        {"error": "resource_authorization_rejected"},
    )


def test_mcp_decoder_rejects_non_tool_result() -> None:
    request = create_mcp_request("tools/list")
    status, response = dispatch_mcp_request(
        request, lambda _request: (200, {}), headers=mcp_request_headers(request)
    )
    assert decode_mcp_tool_result(status, response)[0] == 502


def test_mcp_extra_jsonrpc_members_rejected() -> None:
    document = deepcopy(create_mcp_request("tools/list"))
    document["result"] = {}
    status, response = dispatch_mcp_request(
        document, lambda _request: (200, {}), headers=mcp_request_headers(document)
    )
    assert status == 400
    assert response["error"]["code"] == protocol.INVALID_REQUEST


def test_mcp_request_identifiers_are_fresh(authorization_harness: AuthorizationHarness) -> None:
    invocation = _request(authorization_harness)
    request_identifiers = {
        create_mcp_request("tools/list")["id"],
        create_mcp_request("tools/list")["id"],
        create_mcp_tool_call(invocation)["id"],
        create_mcp_tool_call(invocation)["id"],
    }
    assert len(request_identifiers) == 4


def test_mcp_response_identifier_mismatch_rejected(
    authorization_harness: AuthorizationHarness,
) -> None:
    document = create_mcp_tool_call(_request(authorization_harness))
    status, response = dispatch_mcp_request(
        document,
        lambda request: _execute(authorization_harness, request),
        headers=mcp_request_headers(document),
    )
    response["id"] = "different_request"
    assert decode_mcp_tool_result(status, response, expected_request_identifier=document["id"]) == (
        502,
        {"error": "invalid_mcp_resource_response"},
    )
