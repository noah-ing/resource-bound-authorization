"""The optional profile requires an actual simulator and released quote verifier."""

import os

import pytest

from examples.confined_redemption.software_tpm_verification import verify_software_tpm_profile


@pytest.mark.software_tpm
def test_real_software_tpm_quote_drives_direct_core_redemption() -> None:
    interface = os.environ.get("RESOURCE_AUTHORIZATION_TPM_INTERFACE")
    if interface is None:
        pytest.skip("RESOURCE_AUTHORIZATION_TPM_INTERFACE is not configured")
    result = verify_software_tpm_profile(interface)
    assert result["manifest_verified"] is True
    assert result["quote_verified"] is True
    assert result["assurance"] == "software_tpm"
    assert result["synthetic_enrollment"] is True
    assert result["redemption"] == "accepted"
    assert result["repeat_redemption"] == "rejected"
    assert result["http_services_integrated"] is False
