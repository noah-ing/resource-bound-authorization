"""Exercise direct, rejected, and explicitly delegated synthetic resource calls."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from examples.confined_redemption.configuration import resource_policy
from examples.confined_redemption.registration import (
    load_principal_fixture,
    load_public_registration,
    load_role_private,
)
from examples.confined_redemption.service import DestinationMap, send_request
from fixtures.registration import create_development_attestation
from resource_bound_authorization.attenuation import append_attenuation_record
from resource_bound_authorization.models import CapabilityEnvelope
from resource_bound_authorization.redemption import create_invocation


def _expect(status: int, expected: int, event: str) -> None:
    if status != expected:
        raise RuntimeError(f"unexpected_result_for_{event}")


def run_procedure(directory: Path, *, destinations: DestinationMap | None = None) -> dict[str, Any]:
    fixture = load_principal_fixture(directory, "calling_principal")
    private = load_role_private(directory, "calling_principal")
    policy = resource_policy(load_public_registration(directory))
    headers = {"Authorization": "Bearer " + private["proxy_bearer_credential"]}

    def request(
        server: str, path: str, body: dict[str, Any] | None, authenticated: bool = False
    ) -> tuple[int, dict[str, Any]]:
        return send_request(
            server, path, body, headers if authenticated else None, destinations=destinations
        )

    def obtain_capability(*, delegation: bool = False) -> CapabilityEnvelope:
        status, challenge = request("authorization_server", "/challenge", {})
        _expect(status, 200, "challenge")
        statement = create_development_attestation(
            fixture, challenge["challenge"], challenge["expires_at"]
        )
        document: dict[str, Any] = {
            "challenge": challenge["challenge"],
            "calling_attestation": statement.model_dump(mode="json"),
        }
        if delegation:
            status, response = request("delegated_principal", "/attestation", challenge)
            _expect(status, 200, "delegate_attestation")
            document["delegated_attestation"] = response["attestation"]
        status, response = request("authorization_server", "/issuance", document)
        _expect(status, 200, "issuance")
        return CapabilityEnvelope.model_validate(response["capability"])

    status, baseline = request("resource_server", "/verification", None)
    _expect(status, 200, "initial_handler_count")
    capability = obtain_capability()
    invocation = create_invocation(capability, fixture.holder_private_key).model_dump(mode="json")
    status, _ = request("authorization_proxy", "/forwarding", invocation, True)
    _expect(status, 200, "direct_redemption")
    status, response = request("authorization_proxy", "/forwarding", invocation, True)
    _expect(status, 403, "repeat_redemption")
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
    status, final = request("resource_server", "/verification", None)
    _expect(status, 200, "final_handler_count")
    if final["handler_invocations"] - baseline["handler_invocations"] != 3:
        raise RuntimeError("unexpected_handler_invocation_count")
    return {
        "phase": "confined_redemption",
        "assurance": "development",
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
