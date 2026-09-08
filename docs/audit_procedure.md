# Audit procedure

## Assurance target

Review whether HTTP issuance verifies the registered caller and delegate quotes, and whether MCP resource calls enforce the capability's audience, object, action, principal, attenuation, and invocation proof before atomic redemption and handler dispatch. Distinguish the recommended software-TPM procedure, development request-confinement tests, and inert counterfactual model.

Read [scope](scope.md) and the [threat model](threat_model.md) first. A passing command supports only the commit and configuration actually checked. Record the commit identifier, environment, commands, and results with any review report.

## Source review

| Source | Review question |
| --- | --- |
| `src/resource_bound_authorization/issuance.py` | Does issuance require the accepted manifest and principal binding before signing the complete capability? |
| `src/resource_bound_authorization/verification.py` | Are signatures and evidence verified against configured keys, with a visible development-profile boundary? |
| `src/resource_bound_authorization/tpm_verification.py` | Does quote verification use the issuer's enrolled AK, chain, root, PCR digest, challenge, and complete principal binding? |
| `src/resource_bound_authorization/audience.py` | Is the intended resource enforced independently of the proxy address? |
| `src/resource_bound_authorization/attenuation.py` | Does the original principal authorize only the permitted delegate and issued action? |
| `src/resource_bound_authorization/redemption.py` | Are all checks completed and the root identifier consumed atomically before handler invocation? |
| `src/resource_bound_authorization/forwarding.py` | Are inbound credentials omitted and known reflected values rejected before the checked record is forwarded? |
| `examples/unauthorized_forwarding/` | Does the counterfactual model only evaluate synthetic records, without network requests or resource actions? |
| `tests/test_demonstration.py` | Do real MCP calls traverse the proxy and resource with enforcement unchanged, isolating each audience check before consumption and dispatch? |
| `examples/confined_redemption/service.py` | Does the HTTP resource route verify and consume before handler dispatch, independently of proxy checks? |
| `examples/confined_redemption/mcp_protocol.py` | Are protocol metadata and headers validated, outer tool arguments matched to the signed invocation, and responses correlated to fresh request identifiers? |
| `examples/confined_redemption/attestation.py` | Does enrollment determine the evidence profile, without a development fallback? |
| `examples/confined_redemption/registration.py` | Are fresh private records assigned to distinct role users, with existing enrollment protected from overwrite? |
| `examples/confined_redemption/tpm_registration.py` | Are separate AK contexts enrolled for each principal, private and read-only during quotation, with serialized simulator access? |
| `fixtures/` | Are private keys generated for the procedure, and are records explicitly synthetic? |
| `compose.yaml` | Are service ports unpublished, the network internal, and running services confined to distinct users with capabilities dropped? |
| `.github/workflows/verification.yml` | Does CI execute the documented verification commands and report failures? |

Follow the handler call site as well as the verifier. A correct verifier is insufficient if another service route reaches the protected operation without it. Follow the complete signed record to ensure the audience, object, action, principal, permitted delegation, and validity fields are authenticated rather than accepted from unsigned context.

## Required regression evidence

| Test | Required observation |
| --- | --- |
| `test_audience_mismatch_rejected` | A capability naming another resource cannot dispatch the handler. |
| `test_audience_confinement_through_running_proxy` | The released client receives `audience_mismatch` through real proxy/resource HTTP, with zero consumption and handler count; the valid original succeeds once and replay fails. Both capability and invocation audience are checked independently. |
| `test_token_forwarding_rejected` | The protected resource rejects the bearer-header channel; proxy tests confirm omission downstream and rejection of known reflected credentials. |
| `test_argument_digest_mismatch_rejected` | Substituted arguments do not satisfy the capability's signed action. |
| `test_replay_rejected` | A previously consumed capability cannot dispatch again. |
| `test_second_principal_without_attenuation_rejected` | A second principal cannot redeem without authorized signed attenuation. |
| `test_attenuated_principal_confined_to_granted_actions` | Valid delegation preserves the issued resource and action restrictions. |
| `test_redemption_at_most_once` | Concurrent valid requests sharing the root identifier produce at most one accepted consumption and handler invocation. |
| `test_unauthorized_forwarding_demonstration_succeeds_when_confinement_disabled` | The abstract counterfactual predicate has its documented outcome; no running service disables confinement. |
| `test_quote_or_manifest_mismatch_rejected` | Evidence or manifest substitution is rejected; the default evidence under this required test name is a development record, not a TPM quote. |

For each rejection, inspect the dispatch or handler-count assertion rather than relying only on an error message. Replay tests should use a validly issued capability. Concurrency evidence should cover independently valid invocation proofs sharing one root identifier, including direct and delegated redemption where supported.

`test_software_tpm_http_issuance_and_mcp_delegation` requires a real simulator and exercises actual HTTP issuance, both principal quotes, MCP calls through proxy and resource, explicit attenuation, and assurance-downgrade rejection. `test_released_sdk_client_calls_running_proxy_and_resource` is parameterized for development and software-TPM enrollment and uses the released SDK over real loopback HTTP. `tests/test_tpm_enrollment.py` checks separate keys, read-only contexts, concurrent serialized quotation, and rejected mismatched evidence. The lower-level direct-core quote regression remains supplemental.

Tests marked `software_tpm` are skipped without `RESOURCE_AUTHORIZATION_TPM_INTERFACE`. An ordinary host-suite pass does not establish that those paths ran. Inspect handler-count assertions and the evidence profile, not only success labels or mocked verification.

### Certificate evaluation time

The adapter unit test in `tests/test_tpm_verification.py` explicitly checks the exact UTC `verification_time` forwarded to Agent Manifest. Its dispatch spy establishes argument forwarding, not quote verification.

`tests/test_tpm_certificate_time.py` separately uses an actual simulator quote through `verify_software_tpm_attestation()` and the released verifier. At an injected UTC instant, it isolates the leaf and terminal root: expired, not-yet-valid, and exact-`notAfter` certificates must be rejected; exact-`notBefore` and just-before-`notAfter` controls must be accepted. The other certificate remains current, the enrolled AK and configured root match, and adjacent signatures remain valid. The same quote is reused across certificate-policy fixtures, not redeemed repeatedly or presented as fresh evidence for another challenge.

These tests exercise Agent Manifest `0.12.0`'s inclusive `notBefore` and exclusive `notAfter` behavior, including its terminal-root time check. The fixed time applies to TPM certificate appraisal and evidence freshness; signed-manifest verification remains a separate wall-clock check. The two-certificate synthetic profile does not establish general PKIX validation, physical enrollment, or intermediate-chain coverage. No production verification behavior or assurance claim is changed by these regressions.

## Local verification

Use the committed dependency lock:

```sh
uv sync --extra verification --frozen
uv run --frozen coverage run -m pytest -m 'not software_tpm'
uv run --frozen coverage report
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy src examples fixtures scripts
uv run --frozen bandit -q -r src examples fixtures scripts
uv run --frozen pip-audit --skip-editable
uv build
uv run --frozen python scripts/verify_distribution.py
```

The host environment supports Python 3.12 or 3.13. Coverage measures both statements and branch opportunities over the library; its configured threshold applies to the combined percentage, not an independent branch-only floor. Refer to `pyproject.toml` for the enforced threshold.

The test suite checks behavior. Ruff checks formatting and selected static rules; mypy checks the configured type boundary; Bandit checks selected security patterns. None is a proof of correctness. `pip-audit` depends on the current advisory service and can produce a different result for the same locked environment later.

## Compose procedure

Start from a clean checkout:

```sh
docker compose config --quiet
docker compose build authorization_server
docker compose --profile software_tpm up -d --wait software_tpm
```

For the full CI audit, run standalone simulator tests **before** demonstration enrollment. Their fixtures reset PCR state and must not run against an already enrolled demonstration:

```sh
docker compose --profile software_tpm run --rm --no-deps \
  calling_principal python -m pytest -q -p no:cacheprovider -m software_tpm
```

Enroll fresh keys, then run both phases:

```sh
docker compose run --rm --no-deps --user 0 --cap-add CHOWN --cap-add FOWNER \
  authorization_server python -m examples.confined_redemption.registration \
  --directory /registration --software-tpm-interface swtpm:host=software_tpm,port=2321
docker compose run --rm --no-deps calling_principal \
  python -m examples.unauthorized_forwarding.demonstration
docker compose run --rm --no-deps calling_principal \
  python -m pytest -q -s -p no:cacheprovider tests/test_demonstration.py
docker compose --profile software_tpm up --abort-on-container-exit --exit-code-from calling_principal
```

Registration creates disposable holder and issuer keys, signed manifests, separate simulator AK contexts, and synthetic certificate enrollment. Root and the added ownership capabilities are limited to that one-shot command; running services use separate IDs and drop all capabilities. Registration refuses existing enrollment. Phase A runs the abstract decision predicate and a separate request-confinement regression. Phase B verifies caller and delegate quotes at HTTP issuance and exercises both MCP network hops.

Inspect command exit statuses and assertions. The Phase A predicate expects abstract acceptance when disabled and rejection when record equality is required. Its request regression starts fresh reference services on loopback inside the test container and obtains a development-attested capability through HTTP issuance. It sends signed audience-mismatch fixtures through the real proxy and observes the downstream MCP requests. In each case, the exact audience error occurs with zero SQLite rows and zero handler invocations, followed by valid acceptance and replay rejection. It expects three tests to pass and two JSON reports with `assurance: development`, `confinement: enabled`, `resource_tool_requests: 3`, and `handler_invocations: 1`. The test services use temporary registration and storage, independently of the Compose enrollment and simulator.

Review the two signed contexts separately. For capability-audience verification, only root audience claims change and are signed with the generated fixture issuer key; the invocation audience stays correct. This negative fixture shares the original identifier but is not the original claim record. For invocation-audience verification, the issued capability stays unchanged. The request observer always delegates to the original resource handler. No authorization check is replaced or disabled. The downstream bearer assertion applies to the known registered credential, not general credential provenance.

Phase B rejects mismatched manifest evidence and a development-assurance downgrade, then rejects changed arguments without invoking the handler. The original valid request succeeds, replay fails, and explicitly attenuated delegation succeeds. The output identifies `software_tpm` assurance for both principals, MCP protocol `2026-07-28`, and three authorized handler invocations. It also checks resource-bearer rejection. An image build or health response is not evidence that this procedure passed.

The quote verifier checks the expected composite PCR digest and qualifying data under the enrolled AK. This does not establish independent PCR-selection appraisal, physical TPM provenance, key residency, or manifest execution. The MCP SDK checks establish the implemented transport and tool profile, not OAuth or full MCP conformance.

Clean up only this disposable reference state:

```sh
docker compose --profile software_tpm down --volumes
```

The recommended Phase B command stops the simulator when the caller exits. Stopping or recreating that disposable simulator can invalidate saved contexts. For another run, use the scoped cleanup and repeat the full preparation and enrollment procedure. An ordinary stop preserves registration files and consumption state, but not guaranteed usable TPM contexts. Deleting consumption state does not preserve replay protection under old trusted keys; the clean demonstration instead generates new keys.

The Dockerfile pins the Python base image by digest and installs the committed Python lock. Debian packages resolve from the configured distribution repositories, and the version-pinned `uv` bootstrap is downloaded during the build. The procedure does not claim byte-identical images.

## Evidence and publication

An audit record should identify the commit, dependency lock, evidence profile, commands, failures or skips, and whether Compose ran. Distinguish source review, mocked verifier tests, real SDK loopback tests, actual quote tests, and the complete Compose procedure. The lower-level isolated helper alone does not establish HTTP or delegation integration; require the integrated test and phase output for those claims.

Inspect distributable files for generated keys, local databases, private reports, unpublished security findings, and unrelated workspace material. Only synthetic fixture descriptions and the intended reference source belong in the public repository. A dependency's presence is not evidence of an upstream vulnerability, a remediation claim, or endorsement.

## Interpretation

A passing integrated run supports enrolled software-TPM evidence at HTTP issuance and MCP resource-side confinement and atomic consumption. It does not prove manifest execution, physical hardware identity, complete MCP/OAuth conformance, or business completion after consumption. Phase A's model establishes only internal consistency; its live regression establishes audience rejection, valid acceptance, and replay rejection under unchanged enforcement. Neither establishes successful unauthorized forwarding. Explicit development runs retain development assurance regardless of other tests passing.
