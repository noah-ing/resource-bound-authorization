"""Exercise direct, rejected, and explicitly delegated synthetic resource calls."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from examples.confined_redemption.attestation import create_principal_attestation
from examples.confined_redemption.configuration import resource_policy
from examples.confined_redemption.mcp_protocol import (
    create_mcp_request,
    create_mcp_tool_call,
    decode_mcp_tool_result,
    mcp_request_headers,
)
from examples.confined_redemption.registration import (
    load_principal_fixture,
    load_public_registration,
    load_role_private,
)
from examples.confined_redemption.service import DestinationMap, send_request
from fixtures.registration import create_development_attestation
from resource_bound_authorization.attenuation import append_attenuation_record
from resource_bound_authorization.models import CapabilityEnvelope, ResourceRequest
from resource_bound_authorization.redemption import create_invocation


def _expect(status: int, expected: int, event: str) -> None:
    if status != expected:
        raise RuntimeError(f"unexpected_result_for_{event}")


def run_procedure(directory: Path, *, destinations: DestinationMap | None = None) -> dict[str, Any]:
    fixture = load_principal_fixture(directory, "calling_principal")
    private = load_role_private(directory, "calling_principal")
    policy = resource_policy(load_public_registration(directory))
    assurance = load_public_registration(directory).assurance
    headers = {"Authorization": "Bearer " + private["proxy_bearer_credential"]}
    events: list[dict[str, str]] = []

    def request(
        server: str, path: str, body: dict[str, Any] | None, authenticated: bool = False
    ) -> tuple[int, dict[str, Any]]:
        if body is not None and (
            (server == "authorization_proxy" and path == "/forwarding")
            or (server == "resource_server" and path == "/redemption")
        ):
            document = create_mcp_tool_call(ResourceRequest.model_validate(body))
            status, response = send_request(
                server,
                "/mcp",
                document,
                {**mcp_request_headers(document), **(headers if authenticated else {})},
                destinations=destinations,
            )
            return decode_mcp_tool_result(
                status, response, expected_request_identifier=document["id"]
            )
        return send_request(
            server, path, body, headers if authenticated else None, destinations=destinations
        )

    def obtain_capability(
        *, delegation: bool = False, verify_rejections: bool = False
    ) -> CapabilityEnvelope:
        status, challenge = request("authorization_server", "/challenge", {})
        _expect(status, 200, "challenge")
        statement = create_principal_attestation(
            directory, "calling_principal", challenge["challenge"], challenge["expires_at"]
        )
        document: dict[str, Any] = {
            "challenge": challenge["challenge"],
            "calling_attestation": statement.model_dump(mode="json"),
        }
        if verify_rejections:
            changed_statement = statement.model_dump(mode="json")
            changed_statement["manifest_digest"] = "0" * 64
            status, _ = request(
                "authorization_server",
                "/issuance",
                {**document, "calling_attestation": changed_statement},
            )
            _expect(status, 400, "manifest_binding_rejection")
            events.append({"request": "mismatched_manifest_evidence", "result": "rejected"})
            if assurance == "software_tpm":
                development = create_development_attestation(
                    fixture, challenge["challenge"], challenge["expires_at"]
                )
                status, _ = request(
                    "authorization_server",
                    "/issuance",
                    {**document, "calling_attestation": development.model_dump(mode="json")},
                )
                _expect(status, 403, "development_assurance_rejection")
                events.append({"request": "development_assurance_downgrade", "result": "rejected"})
        if delegation:
            status, response = request("delegated_principal", "/attestation", challenge)
            _expect(status, 200, "delegate_attestation")
            document["delegated_attestation"] = response["attestation"]
        status, response = request("authorization_server", "/issuance", document)
        _expect(status, 200, "issuance")
        result = CapabilityEnvelope.model_validate(response["capability"])
        if (
            response.get("assurance") != assurance
            or result.capability.claims.principal.assurance != assurance
        ):
            raise RuntimeError("issued_capability_assurance_mismatch")
        if delegation and (
            result.capability.claims.permitted_delegation is None
            or result.capability.claims.permitted_delegation.assurance != assurance
        ):
            raise RuntimeError("delegated_capability_assurance_mismatch")
        return result

    status, baseline = request("resource_server", "/verification", None)
    _expect(status, 200, "initial_handler_count")
    for method in ("server/discover", "tools/list"):
        document = create_mcp_request(method)
        status, response = send_request(
            "authorization_proxy",
            "/mcp",
            document,
            mcp_request_headers(document),
            destinations=destinations,
        )
        _expect(status, 200, method)
        if "result" not in response or "error" in response:
            raise RuntimeError("mcp_discovery_failed")
    capability = obtain_capability(verify_rejections=True)
    changed = create_invocation(
        capability, fixture.holder_private_key, arguments={"record_identifier": "different_record"}
    ).model_dump(mode="json")
    status, _ = request("authorization_proxy", "/forwarding", changed, True)
    _expect(status, 403, "first_changed_arguments")
    events.append({"request": "changed_arguments", "result": "rejected"})
    status, after_rejection = request("resource_server", "/verification", None)
    _expect(status, 200, "handler_count_after_rejection")
    if after_rejection != baseline:
        raise RuntimeError("rejected_request_invoked_handler")
    invocation = create_invocation(capability, fixture.holder_private_key).model_dump(mode="json")
    status, _ = request("authorization_proxy", "/forwarding", invocation, True)
    _expect(status, 200, "direct_redemption")
    events.append({"request": "original_granted_arguments", "result": "accepted"})
    status, response = request("authorization_proxy", "/forwarding", invocation, True)
    _expect(status, 403, "repeat_redemption")
    events.append({"request": "repeat_redemption", "result": "rejected"})
    if response.get("error") != "capability_already_redeemed":
        raise RuntimeError("unexpected_repeat_rejection")
    capability = obtain_capability()
    changed = create_invocation(
        capability, fixture.holder_private_key, arguments={"record_identifier": "different_record"}
    ).model_dump(mode="json")
    status, _ = request("authorization_proxy", "/forwarding", changed, True)
    _expect(status, 403, "changed_arguments")
    correct = create_invocation(capability, fixture.holder_private_key).model_dump(mode="json")
    status, _ = request("resource_server", "/redemption", correct, True)
    _expect(status, 403, "resource_bearer_rejection")
    status, _ = request("authorization_proxy", "/forwarding", correct, True)
    _expect(status, 200, "original_after_rejection")
    capability = obtain_capability(delegation=True)
    delegated = capability.capability.claims.permitted_delegation
    if delegated is None:
        raise RuntimeError("issuer_did_not_endorse_delegate")
    attenuated = append_attenuation_record(
        capability, delegated, fixture.holder_private_key, policy
    )
    status, _ = request("delegated_principal", "/redemption", attenuated.model_dump(mode="json"))
    _expect(status, 200, "delegated_redemption")
    events.append({"request": "explicitly_attenuated_delegation", "result": "accepted"})
    status, final = request("resource_server", "/verification", None)
    _expect(status, 200, "final_handler_count")
    if final["handler_invocations"] - baseline["handler_invocations"] != 3:
        raise RuntimeError("unexpected_handler_invocation_count")
    return {
        "phase": "confined_redemption",
        "assurance": assurance,
        "transport": "mcp_streamable_http",
        "protocol_version": "2026-07-28",
        "caller_and_delegate_assurance": assurance,
        "events": events,
        "direct_redemption": "accepted",
        "repeat_redemption": "rejected",
        "changed_arguments": "rejected",
        "resource_bearer": "rejected",
        "original_after_rejection": "accepted",
        "delegated_redemption": "accepted",
        "handler_invocations": 3,
    }


def main() -> None:
    directory = Path(os.environ.get("RESOURCE_AUTHORIZATION_REGISTRATION", "/registration"))
    print(json.dumps(run_procedure(directory), sort_keys=True))


if __name__ == "__main__":
    main()
