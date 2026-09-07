"""A narrow MCP 2026-07-28 JSON-response profile with resource-bound authorization.

The released SDK validates protocol records, metadata, and mirrored HTTP headers.
Discovery and listing are public. Tool execution always reaches the supplied
enforcing callback. This module does not implement OAuth, sessions, streaming,
subscriptions, tasks, or earlier initialization-handshake protocol revisions.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Collection, Mapping
from typing import Any

import mcp_types as protocol
from mcp.shared.inbound import (
    ERROR_CODE_HTTP_STATUS,
    InboundLadderRejection,
    classify_inbound_request,
    encode_header_value,
)
from mcp_types.methods import (
    parse_client_request,
    parse_server_result,
    serialize_server_result,
)
from pydantic import ValidationError

from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.models import ResourceRequest

PROTOCOL_VERSION = "2026-07-28"
AUTHORIZATION_METADATA_KEY = "io.github.noah-ing/resource-bound-authorization"
TOOL_NAME = "object.read"
ExecuteResource = Callable[[ResourceRequest], tuple[int, dict[str, Any]]]
_SUPPORTED_METHODS = frozenset({"server/discover", "tools/list", "tools/call"})
_REJECTION_CODES = frozenset(
    {
        "action_binding_mismatch",
        "argument_digest_mismatch",
        "attenuation_confinement_mismatch",
        "audience_mismatch",
        "capability_already_redeemed",
        "capability_expired_or_clock_changed",
        "capability_expired_or_not_yet_valid",
        "capability_validity_exceeds_policy",
        "credential_reflection_rejected",
        "forwarded_bearer_reflection_rejected",
        "forwarded_bearer_rejected",
        "invocation_capability_mismatch",
        "issuance_policy_mismatch",
        "principal_binding_mismatch",
        "principal_registration_mismatch",
        "principal_role_mismatch",
        "proxy_authentication_failed",
        "redemption_storage_unavailable",
        "resource_authorization_rejected",
        "signature_verification_failed",
    }
)


def _metadata() -> dict[str, Any]:
    return {
        protocol.PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION,
        protocol.CLIENT_CAPABILITIES_META_KEY: {},
        protocol.CLIENT_INFO_META_KEY: {
            "name": "resource-bound-authorization",
            "version": "0.1.0",
        },
    }


def create_mcp_request(method: str, request_identifier: int | str | None = None) -> dict[str, Any]:
    """Construct a supported discovery request with current per-request metadata."""
    if method not in {"server/discover", "tools/list"}:
        raise ValueError("unsupported_mcp_discovery_method")
    return protocol.JSONRPCRequest(
        jsonrpc="2.0",
        id=uuid.uuid4().hex if request_identifier is None else request_identifier,
        method=method,
        params={"_meta": _metadata()},
    ).model_dump(mode="json", by_alias=True, exclude_none=True)


def create_mcp_tool_call(
    request: ResourceRequest, request_identifier: int | str | None = None
) -> dict[str, Any]:
    """Carry authorization in namespaced metadata, separately from tool arguments."""
    metadata = _metadata()
    metadata[AUTHORIZATION_METADATA_KEY] = request.model_dump(mode="json")
    parameters = protocol.CallToolRequestParams.model_validate(
        {
            "name": request.invocation.claims.tool_name,
            "arguments": dict(request.invocation.claims.arguments),
            "_meta": metadata,
        },
        by_name=False,
    )
    return protocol.JSONRPCRequest(
        jsonrpc="2.0",
        id=uuid.uuid4().hex if request_identifier is None else request_identifier,
        method="tools/call",
        params=parameters.model_dump(mode="json", by_alias=True, exclude_none=True),
    ).model_dump(mode="json", by_alias=True, exclude_none=True)


def mcp_request_headers(document: dict[str, Any]) -> dict[str, str]:
    """Build only protocol headers; never propagate upstream credentials."""
    request = protocol.JSONRPCRequest.model_validate(document, strict=True)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": request.method,
    }
    if request.method == "tools/call":
        parameters = protocol.CallToolRequestParams.model_validate(request.params, by_name=False)
        headers["Mcp-Name"] = encode_header_value(parameters.name)
    return headers


def _error(
    request_identifier: int | str | None,
    code: int,
    message: str,
    *,
    status: int | None = None,
    details: Any = None,
) -> tuple[int, dict[str, Any]]:
    response = protocol.JSONRPCError(
        jsonrpc="2.0",
        id=request_identifier,
        error=protocol.ErrorData(code=code, message=message, data=details),
    )
    document = response.model_dump(mode="json", by_alias=True, exclude_none=True)
    return ERROR_CODE_HTTP_STATUS.get(code, 200) if status is None else status, document


def _result(
    request: protocol.JSONRPCRequest, result: protocol.Result
) -> tuple[int, dict[str, Any]]:
    document = serialize_server_result(
        request.method,
        PROTOCOL_VERSION,
        result.model_dump(mode="json", by_alias=True, exclude_none=True),
    )
    return 200, protocol.JSONRPCResponse(jsonrpc="2.0", id=request.id, result=document).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )


def _tool_rejection(request: protocol.JSONRPCRequest, code: object) -> tuple[int, dict[str, Any]]:
    rejection_code = (
        code
        if isinstance(code, str) and code in _REJECTION_CODES
        else ("resource_authorization_rejected")
    )
    return _result(
        request,
        protocol.CallToolResult(
            content=[protocol.TextContent(text="Resource authorization rejected.")],
            structured_content={"error": rejection_code},
            is_error=True,
        ),
    )


def dispatch_mcp_request(
    document: dict[str, Any],
    execute: ExecuteResource,
    *,
    headers: Mapping[str, str],
    allowed_origins: Collection[str] = (),
) -> tuple[int, dict[str, Any]]:
    """Validate current MCP requests and bind tool calls to the signed invocation."""
    normalized_headers = {name.casefold(): value for name, value in headers.items()}
    if len(normalized_headers) != len(headers):
        return _error(None, protocol.HEADER_MISMATCH, "Invalid request headers")
    if "origin" in normalized_headers and normalized_headers["origin"] not in allowed_origins:
        return _error(None, protocol.INVALID_REQUEST, "Origin rejected", status=403)
    accepted_media = {
        entry.split(";", maxsplit=1)[0].strip()
        for entry in normalized_headers.get("accept", "").split(",")
    }
    if not {"application/json", "text/event-stream"}.issubset(accepted_media):
        return _error(None, protocol.INVALID_REQUEST, "Unsupported response media", status=406)
    try:
        if set(document) - {"jsonrpc", "id", "method", "params"}:
            raise ValueError("unsupported_jsonrpc_members")
        request = protocol.JSONRPCRequest.model_validate(document, strict=True)
        if isinstance(request.id, str) and len(request.id) > 256:
            raise ValueError("request_identifier_too_long")
    except (ValueError, TypeError):
        return _error(None, protocol.INVALID_REQUEST, "Invalid JSON-RPC request")
    classification = classify_inbound_request(
        document,
        headers=normalized_headers,
        supported_modern_versions=(PROTOCOL_VERSION,),
    )
    if isinstance(classification, InboundLadderRejection):
        # SDK messages name protocol fields, not credential or signature material.
        return _error(
            request.id,
            classification.code,
            "MCP request metadata rejected",
            details=(
                classification.data
                if classification.code == protocol.UNSUPPORTED_PROTOCOL_VERSION
                else None
            ),
        )
    if request.method not in _SUPPORTED_METHODS:
        return _error(request.id, protocol.METHOD_NOT_FOUND, "Method not found")
    try:
        protocol.ClientCapabilities.model_validate(classification.client_capabilities, strict=True)
        if classification.client_info is not None:
            protocol.Implementation.model_validate(classification.client_info, strict=True)
        parsed_request = parse_client_request(request.method, PROTOCOL_VERSION, request.params)
    except (ValueError, TypeError, KeyError):
        return _error(request.id, protocol.INVALID_PARAMS, "Invalid method parameters")
    if request.method == "server/discover":
        return _result(
            request,
            protocol.DiscoverResult(
                supported_versions=[PROTOCOL_VERSION],
                capabilities=protocol.ServerCapabilities(tools=protocol.ToolsCapability()),
                ttl_ms=0,
                cache_scope="public",
            ),
        )
    if request.method == "tools/list":
        if isinstance(parsed_request, protocol.ListToolsRequest) and (
            parsed_request.params is not None and parsed_request.params.cursor is not None
        ):
            return _error(request.id, protocol.INVALID_PARAMS, "Pagination is not available")
        return _result(
            request,
            protocol.ListToolsResult(
                tools=[
                    protocol.Tool(
                        name=TOOL_NAME,
                        description="Read the single synthetic object after capability redemption.",
                        input_schema={
                            "type": "object",
                            "properties": {"record_identifier": {"type": "string"}},
                            "required": ["record_identifier"],
                            "additionalProperties": False,
                        },
                    )
                ],
                ttl_ms=0,
                cache_scope="public",
            ),
        )
    if not isinstance(parsed_request, protocol.CallToolRequest):
        return _error(request.id, protocol.INVALID_PARAMS, "Invalid tool request")
    parameters = parsed_request.params
    if (
        parameters.name != TOOL_NAME
        or parameters.task is not None
        or parameters.input_responses is not None
        or parameters.request_state is not None
    ):
        return _error(request.id, protocol.INVALID_PARAMS, "Unsupported tool parameters")
    try:
        metadata = parameters.meta or {}
        authorization_request = ResourceRequest.model_validate(
            metadata.get(AUTHORIZATION_METADATA_KEY)
        )
    except (ValueError, TypeError):
        return _tool_rejection(request, "resource_authorization_rejected")
    if (
        parameters.name != authorization_request.invocation.claims.tool_name
        or parameters.arguments != authorization_request.invocation.claims.arguments
    ):
        return _tool_rejection(request, "action_binding_mismatch")
    try:
        status, execution_result = execute(authorization_request)
    except AuthorizationError as rejection:
        return _tool_rejection(request, rejection.code)
    if status != 200:
        return _tool_rejection(request, execution_result.get("error"))
    return _result(
        request,
        protocol.CallToolResult(
            content=[protocol.TextContent(text=json.dumps(execution_result, sort_keys=True))],
            structured_content=execution_result,
            is_error=False,
        ),
    )


def decode_mcp_tool_result(
    status: int,
    document: dict[str, Any],
    *,
    expected_request_identifier: int | str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Validate the released result schema and expose only the resource result or rejection."""
    if status != 200:
        return status, {"error": "mcp_transport_rejected"}
    try:
        if set(document) - {"jsonrpc", "id", "result"}:
            raise ValueError("invalid_mcp_response_members")
        response = protocol.JSONRPCResponse.model_validate(document, strict=True)
        if expected_request_identifier is not None and response.id != expected_request_identifier:
            raise ValueError("mcp_response_identifier_mismatch")
        result = parse_server_result("tools/call", PROTOCOL_VERSION, response.result)
        if not isinstance(result, protocol.CallToolResult):
            raise ValueError("unsupported_mcp_result")
        content = result.structured_content
        if not isinstance(content, dict):
            raise ValueError("structured_resource_result_required")
        if result.is_error:
            code = content.get("error")
            return 403, {
                "error": code
                if isinstance(code, str) and code in _REJECTION_CODES
                else "resource_authorization_rejected"
            }
        return 200, content
    except (ValidationError, ValueError, TypeError, KeyError):
        return 502, {"error": "invalid_mcp_resource_response"}
