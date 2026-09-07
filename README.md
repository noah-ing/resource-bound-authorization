# Resource-Bound Authorization

This independent reference implementation confines use of one issued capability to one resource audience, one object, the `object.read` tool, and an exact argument digest. The resource server requires an issuer signature, a verified principal binding, any permitted second principal recorded by signed attenuation, and proof of possession by the effective holder; it consumes the root capability identifier atomically before invoking the handler. The proxy omits inbound bearer credentials and rejects their known value reflected in the outbound record; the resource rejects authorization headers. The default HTTP path uses an ephemeral development attestation record plus released Agent Manifest verification, not a TPM quote or hardware-rooted identity. An optional, isolated core procedure verifies a genuine software-TPM quote.

## Scope

This is a reference implementation, not a product, identity provider, production gateway, marketplace, or GoldKey. It has one grant type, one synthetic object, one resource, one proxy, and at most one delegation hop. It does not establish principal execution, key residency, workload integrity, general bearer-token provenance, or exactly-once business execution. See the [scope](docs/scope.md) and [threat model](docs/threat_model.md).

## Related work

[attested-capability-broker](https://github.com/noah-ing/attested-capability-broker) studies attested capability issuance; this repository studies confinement at the resource when a capability is used through a proxy or by a permitted second principal.

Released [Agent Manifest](https://github.com/agentrust-io/agent-manifest) `0.12.0` verifies the signed manifest. The local capability, attenuation, and invocation-proof formats are reference protocols. Dependency names identify composition, not affiliation, endorsement, or a claim about an upstream defect.

The service adapter exposes bounded HTTP JSON requests at `/issuance`, `/forwarding`, and `/redemption` for the single tool. It does not implement a complete MCP transport or OAuth authorization flow.

## Reproduction procedure

Requirements: Docker Engine with Compose v2. The procedure requires no TPM hardware, cloud account, public endpoint, or existing credentials. Run these commands from a clean checkout:

```sh
docker compose config --quiet
docker compose build authorization_server
docker compose run --rm --no-deps --user 0 --cap-add CHOWN --cap-add FOWNER \
  authorization_server python -m examples.confined_redemption.registration \
  --directory /registration
```

Run Phase A, the inert decision model:

```sh
docker compose run --rm --no-deps calling_principal \
  python -m examples.unauthorized_forwarding.demonstration
```

Run Phase B, confined redemption:

```sh
docker compose up --abort-on-container-exit --exit-code-from calling_principal
```

Optionally verify a genuine software-TPM quote through direct core issuance and redemption:

```sh
docker compose --profile software_tpm up -d --wait software_tpm
docker compose --profile software_tpm run --rm --no-deps \
  -e RESOURCE_AUTHORIZATION_TPM_INTERFACE=swtpm:host=software_tpm,port=2321 \
  calling_principal python -m examples.confined_redemption.software_tpm_verification
```

The optional procedure uses synthetic attestation-key enrollment. It does not integrate TPM evidence into the HTTP services or exercise TPM-backed delegation. The [scope](docs/scope.md) specifies its separate assurance boundary.

Clean up the disposable reference state afterward:

```sh
docker compose --profile software_tpm down --volumes
```

Registration generates fresh keys and assigns each service's private records to its own user ID. The one-shot initialization receives only the extra `CHOWN` and `FOWNER` capabilities needed to establish ownership; running services drop all capabilities. Registration refuses to overwrite existing enrollment.

An ordinary stop or `docker compose down` preserves enrollment and the SQLite consumption store. The cleanup above deletes this reference's generated enrollment and consumption volumes; provisioning the next run creates new keys. Preserve the store for as long as its corresponding keys and capabilities are accepted. The Compose network is internal, publishes no host ports, and uses HTTP without TLS for local verification.

For source review and Python verification:

```sh
uv sync --extra verification --frozen
uv run --frozen coverage run -m pytest -m 'not software_tpm'
uv run --frozen coverage report
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen bandit -q -r src
uv run --frozen pip-audit
```

The [audit procedure](docs/audit_procedure.md) explains what each check can establish. These commands are a procedure, not a claim that a particular machine or commit has passed them. Advisory scanning depends on the current advisory database.

## Phase A: unauthorized forwarding demonstration

The first phase evaluates an abstract predicate over synthetic grant and request records. With confinement disabled, the predicate accepts the record; with confinement enabled, it requires the records to match and rejects the differing request. The expected output has `confinement_disabled: true` and `confinement_enabled: false`. It performs no network requests or resource actions, exposes no insecure service, and does not reproduce an upstream vulnerability. All running services retain their confinement checks.

The regression test named `test_unauthorized_forwarding_demonstration_succeeds_when_confinement_disabled` checks the counterfactual fixture's expected decision. Its name refers to the fixture's modeled policy, not a service configuration that disables enforcement. A passing fixture check establishes only that the illustration remains internally consistent.

## Phase B: confined redemption

The authorization server verifies the configured signed Agent Manifest and development attestation binding before issuing an Ed25519-signed capability. The signed capability fixes the resource audience, object, tool, argument digest, original principal, and any permitted delegate. A second principal requires a signed attenuation record from the original principal and cannot enlarge the issued authority. The effective holder signs the invocation.

The resource server verifies those bindings and consumes the root capability identifier in an SQLite transaction before dispatching `object.read`. Direct use and attenuated use share the same spend identifier. Independent valid proofs cannot redeem the same capability twice.

The authorization proxy authenticates its registered bearer credential, constructs the downstream request without it, and rejects that known credential reflected in the outgoing serialized body or decoded string fields. The resource rejects `Authorization` and `Proxy-Authorization` headers and accepts only the reference capability with a valid invocation proof. This checks known credential reflection, not general token provenance.

A process failure after the spend commit can consume a capability without completing the handler or returning a result. At-most-once redemption therefore does not imply exactly-once execution or guaranteed completion.

The procedure expects direct and permitted delegated redemption to succeed, repeat redemption and changed arguments to be rejected, a bearer header at the resource to be rejected, and a valid request after those pre-consumption rejections to remain usable. It verifies three handler invocations and prints `assurance: development`.

## Deferred work

Payments, token commerce, multi-cloud federation, a general policy language, and a public authorization service are explicitly deferred. Hardware TPM enrollment, TPM integration into the HTTP and delegation paths, production transport and key management, additional delegation hops, and operational recovery also remain outside this reference implementation. See [scope](docs/scope.md) for the assurance boundary and dependency substitutions.

## Security reporting and license

Follow the [security policy](SECURITY.md) for private reporting. This repository uses the [MIT license](LICENSE), consistent with attested-capability-broker.
