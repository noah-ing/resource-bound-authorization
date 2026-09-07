"""Inbound credential exclusion and resource-native forwarding rejection."""

from pathlib import Path

import pytest

from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.forwarding import (
    build_forwarding_request,
    reject_forwarded_bearer,
)
from resource_bound_authorization.models import ResourceRequest
from resource_bound_authorization.redemption import create_invocation
from tests.support import AuthorizationHarness, create_authorization_harness


@pytest.fixture
def authorization_harness(tmp_path: Path) -> AuthorizationHarness:
    return create_authorization_harness(tmp_path)


@pytest.mark.parametrize(
    "header_name", ["Authorization", "authorization", "AUTHORIZATION", "Proxy-Authorization"]
)
def test_token_forwarding_rejected(
    authorization_harness: AuthorizationHarness, header_name: str
) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
    )

    with pytest.raises(AuthorizationError, match="forwarded_bearer_rejected"):
        authorization_harness.dispatch(
            request, headers={header_name: "Bearer synthetic-reference-credential"}
        )

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0
    accepted_record = authorization_harness.dispatch(request)
    assert authorization_harness.handler_invocations == [accepted_record]


@pytest.mark.parametrize(
    "header_value", ["", "Basic synthetic-reference", "Bearer synthetic-reference"]
)
def test_authorization_header_rejected_independent_of_scheme(header_value: str) -> None:
    with pytest.raises(AuthorizationError, match="forwarded_bearer_rejected"):
        reject_forwarded_bearer({"Authorization": header_value})


def test_proxy_constructs_only_capability_transport(
    authorization_harness: AuthorizationHarness,
) -> None:
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
    )
    inbound_headers = {
        "Authorization": "Bearer synthetic-inbound-reference",
        "Proxy-Authorization": "Bearer synthetic-proxy-reference",
        "Cookie": "synthetic-cookie-reference",
        "X-Principal": "untrusted-principal-reference",
    }

    downstream_headers, downstream_body = build_forwarding_request(request, inbound_headers)

    assert downstream_headers == {"Content-Type": "application/json"}
    assert ResourceRequest.model_validate_json(downstream_body) == request
    assert all(value.encode() not in downstream_body for value in inbound_headers.values())
    assert inbound_headers["Authorization"] == "Bearer synthetic-inbound-reference"
    accepted_record = authorization_harness.dispatch(request, headers=downstream_headers)
    assert authorization_harness.handler_invocations == [accepted_record]


@pytest.mark.parametrize("header_name", ["Authorization", "Proxy-Authorization"])
@pytest.mark.parametrize("reflection_location", ["argument_value", "argument_name"])
def test_proxy_rejects_known_credential_in_arguments(
    authorization_harness: AuthorizationHarness, header_name: str, reflection_location: str
) -> None:
    credential = "synthetic-reflected-credential"
    arguments = (
        {"record_identifier": "reference-" + credential}
        if reflection_location == "argument_value"
        else {"record_identifier": "reference_record", credential: "reference_value"}
    )
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
        arguments=arguments,
    )

    with pytest.raises(AuthorizationError, match="forwarded_bearer_reflection_rejected"):
        build_forwarding_request(request, {header_name: "Bearer " + credential})

    assert authorization_harness.handler_invocations == []
    assert authorization_harness.consumption_count() == 0


def test_proxy_rejects_unicode_escaped_credential_equivalence(
    authorization_harness: AuthorizationHarness,
) -> None:
    credential = "synthetic-reference-credential"
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
        arguments={"record_identifier": credential},
    )
    encoded_request = request.model_dump_json().replace(
        credential, "\\u0073ynthetic-reference-credential"
    )
    decoded_request = ResourceRequest.model_validate_json(encoded_request)
    assert decoded_request == request

    with pytest.raises(AuthorizationError, match="forwarded_bearer_reflection_rejected"):
        build_forwarding_request(decoded_request, {"Authorization": "Bearer " + credential})

    assert authorization_harness.handler_invocations == []


def test_proxy_rejects_credential_requiring_json_string_escaping(
    authorization_harness: AuthorizationHarness,
) -> None:
    credential = 'synthetic-"reference"-credential'
    request = create_invocation(
        authorization_harness.issue(),
        authorization_harness.calling_registration.holder_private_key,
        arguments={"record_identifier": credential},
    )
    assert credential.encode() not in request.model_dump_json().encode()

    with pytest.raises(AuthorizationError, match="forwarded_bearer_reflection_rejected"):
        build_forwarding_request(request, {"Authorization": "Bearer " + credential})

    assert authorization_harness.handler_invocations == []
