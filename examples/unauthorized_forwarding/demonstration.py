"""Inert decision model: a transferable identifier alone cannot confine use.

This procedure compares synthetic records. It contains no bearer token, network
client, vulnerable endpoint, or adapter to a released service. The disabled
predicate exists only in this educational model, outside the installed package.
"""

from __future__ import annotations

import json
from pathlib import Path


def evaluate_synthetic_record(
    grant: dict[str, str], request: dict[str, str], *, confinement_enabled: bool
) -> bool:
    """Evaluate an abstract record, never a token or executable resource action."""
    if not confinement_enabled:
        return True
    return grant == request


def demonstrate_unauthorized_forwarding() -> dict[str, str | bool]:
    fixture_path = Path(__file__).resolve().parents[2] / "fixtures/unauthorized_forwarding.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    unconstrained_result = evaluate_synthetic_record(
        fixture["grant"], fixture["request"], confinement_enabled=False
    )
    confined_result = evaluate_synthetic_record(
        fixture["grant"], fixture["request"], confinement_enabled=True
    )
    if not unconstrained_result or confined_result:
        raise RuntimeError("synthetic_authorization_model_failed")
    return {
        "phase": "unauthorized_forwarding",
        "evidence": "inert_synthetic_decision_model",
        "confinement_disabled": unconstrained_result,
        "confinement_enabled": confined_result,
        "network_requests": "none",
        "resource_actions": "none",
    }


if __name__ == "__main__":
    print(json.dumps(demonstrate_unauthorized_forwarding(), sort_keys=True))
