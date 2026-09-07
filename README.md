# Resource-Bound Authorization

This independent reference implementation confines use of one issued capability to one resource audience, one object, the `object.read` tool, and an exact argument digest. In the recommended Compose procedure, the HTTP authorization server verifies a signed Agent Manifest and a genuine software-TPM quote for each participating principal before issuance. MCP tool calls pass through the proxy to the resource, which verifies the issuer signature, principal binding, any signed attenuation, and effective holder proof; it consumes the root capability identifier atomically before invoking the handler. The proxy omits inbound bearer credentials and rejects known credential reflection; the resource rejects bearer headers on redemption.

## Scope

This is a reference implementation, not a product, identity provider, production gateway, marketplace, or GoldKey. It has one grant type, one synthetic object, one resource, one proxy, and at most one delegation hop. It does not establish principal execution, key residency, workload integrity, general bearer-token provenance, or exactly-once business execution. See the [scope](docs/scope.md) and [threat model](docs/threat_model.md).

## Related work

[attested-capability-broker](https://github.com/noah-ing/attested-capability-broker) studies attested capability issuance; this repository studies confinement at the resource when a capability is used through a proxy or by a permitted second principal.

Released [Agent Manifest](https://github.com/agentrust-io/agent-manifest) `0.12.0` verifies signed manifests and TPM quotes. The [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) `2.1.1` and locked `mcp-types==2.1.1` supply protocol validation and client interoperability. The local capability, attenuation, and invocation-proof formats remain reference protocols. Dependency names identify composition, not affiliation, endorsement, or an upstream defect.

The proxy and resource expose `/mcp` with MCP `2026-07-28` `server/discover`, `tools/list`, and `tools/call`, using single JSON responses over Streamable HTTP. The signed authorization record travels in namespaced request metadata, separately from the exact tool arguments. Issuance and delegation coordination use bounded HTTP JSON. OAuth, authorization-code flows, DCR, and complete MCP conformance are outside this adapter's claim; see [scope](docs/scope.md).

## Reproduction procedure

Requirements: Docker Engine with Compose v2. The procedure requires no TPM hardware, cloud account, public endpoint, or existing credentials. Run these commands from a clean checkout:

```sh
docker compose config --quiet
docker compose build authorization_server
docker compose --profile software_tpm up -d --wait software_tpm
docker compose run --rm --no-deps --user 0 --cap-add CHOWN --cap-add FOWNER \
  authorization_server python -m examples.confined_redemption.registration \
  --directory /registration --software-tpm-interface swtpm:host=software_tpm,port=2321
```

Run Phase A, the inert decision model and live request-confinement regression:

```sh
docker compose run --rm --no-deps calling_principal \
  python -m examples.unauthorized_forwarding.demonstration
docker compose run --rm --no-deps calling_principal \
  python -m pytest -q -s -p no:cacheprovider tests/test_demonstration.py
```

Run Phase B, confined redemption:

```sh
docker compose --profile software_tpm up --abort-on-container-exit --exit-code-from calling_principal
```

Registration enrolls a separate simulator attestation key for the caller and delegate under synthetic certificate authorities. The issuer selects the enrolled key and expected PCR digest from its registry. Both principals must supply fresh quotes bound to the issuance challenge, manifest digest, holder key, and expiry. This establishes neither physical hardware provenance nor holder-key residency or manifest execution.

Clean up the disposable reference state afterward:

```sh
docker compose --profile software_tpm down --volumes
```

Registration generates fresh keys and assigns each service's private records to its own user ID. The one-shot initialization receives only the extra `CHOWN` and `FOWNER` capabilities needed to establish ownership; running services drop all capabilities. Registration refuses to overwrite existing enrollment.

Stopping or recreating the disposable simulator can invalidate saved attestation-key contexts, including after Phase B stops its containers. For another run, perform the cleanup above, then repeat the complete preparation procedure. Ordinary shutdown preserves registration files and SQLite state but does not promise usable simulator contexts. Preserve the consumption store for as long as its keys and capabilities are accepted. The Compose network is internal, publishes no host ports, and uses HTTP without TLS for local verification.

An explicit development enrollment remains available for host tests: omit `--software-tpm-interface` when provisioning a fresh registration. It uses signed Ed25519 evidence and reports `assurance: development`. A software-TPM enrollment rejects that evidence and never falls back to it when the simulator is absent.

For source review and Python verification:

```sh
uv sync --extra verification --frozen
uv run --frozen coverage run -m pytest -m 'not software_tpm'
uv run --frozen coverage report
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy src examples fixtures scripts
uv run --frozen bandit -q -r src examples fixtures scripts
uv run --frozen pip-audit --skip-editable
```

The [audit procedure](docs/audit_procedure.md) explains what each check can establish. These commands are a procedure, not a claim that a particular machine or commit has passed them. Advisory scanning depends on the current advisory database.

## Phase A: forwarding model and request confinement

The first command evaluates an abstract predicate over synthetic grant and request records. With confinement disabled, the predicate accepts the record; with confinement enabled, it requires the records to match and rejects the differing request. The expected output has `confinement_disabled: true` and `confinement_enabled: false`. This model performs no network requests or resource actions. All running services retain their confinement checks.

The regression test named `test_unauthorized_forwarding_demonstration_succeeds_when_confinement_disabled` checks the counterfactual fixture's expected decision. Its name refers to the fixture's modeled policy, not a service configuration that disables enforcement. A passing fixture check establishes only that the illustration remains internally consistent.

The second command starts the real reference HTTP services on loopback inside the test container, using independent temporary development enrollment. The released MCP client sends `tools/call` through `authorization_proxy` to `resource_server`. Two cases isolate capability-audience and invocation-audience verification. Each sends a correctly signed negative fixture first, asserts `audience_mismatch`, and observes zero handler invocations and zero consumption rows. The original valid request then succeeds, and replay is rejected with exactly one handler invocation and one consumed identifier. The resource observation also verifies that the proxy's registered bearer is absent from downstream headers and body.

The invocation case preserves the issued capability unchanged. The capability case uses the fixture issuer key to sign a different audience while preserving the identifier; its invocation audience remains correct so the root-audience check is tested independently. This is test-generated authorization material, not a facility exposed by the issuance service. Both cases report `assurance: development` and `confinement: enabled`. They use no simulator and do not alter the Compose enrollment.

This is a live confinement regression, not successful unauthorized forwarding or a runnable disabled-policy comparison. Phase A does not reproduce an upstream vulnerability or an OAuth grant-confusion case.

## Phase B: confined redemption

The authorization server verifies the configured signed Agent Manifest and enrolled software-TPM quote before issuing an Ed25519-signed capability. It appraises both caller and delegate quotes when delegation is requested, then atomically consumes the fresh issuance challenge. The signed capability fixes the resource audience, object, tool, argument digest, original principal, and any permitted delegate. A second principal requires a signed attenuation record from the original principal and cannot enlarge the issued authority. The effective holder signs the invocation.

Both network hops use MCP `tools/call`. The adapter checks that the outer tool name and arguments match the signed invocation carried in `params._meta["io.github.noah-ing/resource-bound-authorization"]`. The resource then verifies the capability bindings and consumes the root identifier in an SQLite transaction before dispatching `object.read`. Direct and attenuated use share that identifier. Independent valid proofs cannot redeem the same capability twice.

The authorization proxy authenticates its registered bearer credential, constructs the downstream request without it, and rejects that known credential reflected in the outgoing serialized body or decoded string fields. The resource rejects `Authorization` and `Proxy-Authorization` headers and accepts only the reference capability with a valid invocation proof. This checks known credential reflection, not general token provenance.

A process failure after the spend commit can consume a capability without completing the handler or returning a result. At-most-once redemption therefore does not imply exactly-once execution or guaranteed completion.

The procedure first rejects mismatched manifest evidence, a development-assurance downgrade, and changed arguments, and verifies that the handler count remains unchanged. The original granted arguments then succeed; repeat redemption is rejected. Explicit delegated redemption succeeds after both quotes and the attenuation record are verified. The final output reports three authorized handler invocations, `assurance: software_tpm`, and `protocol_version: 2026-07-28`. The audit also exercises the released MCP client against the running proxy and resource.

## Deferred work

Payments, token commerce, multi-cloud federation, a general policy language, and a public authorization service are explicitly deferred. OAuth and DCR integration, physical TPM enrollment, production transport and key management, additional delegation hops, and operational recovery also remain outside this reference. Phase A combines an inert counterfactual with live enforcement tests; it does not include a runnable weak proxy. See [scope](docs/scope.md) for the assurance boundary and dependency substitutions.

## Security reporting and license

Follow the [security policy](SECURITY.md) for private reporting. This repository uses the [MIT license](LICENSE), consistent with attested-capability-broker.
