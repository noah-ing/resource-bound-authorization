"""The counterfactual stays inert and its corresponding real action is rejected."""

from pathlib import Path

import pytest

from examples.unauthorized_forwarding.demonstration import demonstrate_unauthorized_forwarding
from resource_bound_authorization.errors import AuthorizationError
from resource_bound_authorization.redemption import create_invocation, redeem_capability
from tests.support import create_authorization_harness


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
