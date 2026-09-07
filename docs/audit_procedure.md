# Audit procedure

## Assurance target

Review whether the resource enforces the capability's audience, object, action, principal, attenuation, and invocation-proof requirements before handler dispatch, and whether competing uses consume the root capability identifier at most once. Distinguish the default development HTTP path, the inert counterfactual decision model, and the optional isolated software-TPM core procedure.

Read [scope](scope.md) and the [threat model](threat_model.md) first. A passing command supports only the commit and configuration actually checked. Record the commit identifier, environment, commands, and results with any review report.

## Source review

| Source | Review question |
| --- | --- |
| `src/resource_bound_authorization/issuance.py` | Does issuance require the accepted manifest and principal binding before signing the complete capability? |
| `src/resource_bound_authorization/verification.py` | Are signatures and evidence verified against configured keys, with a visible development-profile boundary? |
| `src/resource_bound_authorization/audience.py` | Is the intended resource enforced independently of the proxy address? |
| `src/resource_bound_authorization/attenuation.py` | Does the original principal authorize only the permitted delegate and issued action? |
| `src/resource_bound_authorization/redemption.py` | Are all checks completed and the root identifier consumed atomically before handler invocation? |
| `src/resource_bound_authorization/forwarding.py` | Are inbound credentials omitted and known reflected values rejected before the checked record is forwarded? |
| `examples/unauthorized_forwarding/` | Does Phase A only evaluate a predicate over synthetic records, without network requests or resource actions? |
| `examples/confined_redemption/service.py` | Does the HTTP resource route verify and consume before handler dispatch, independently of proxy checks? |
| `examples/confined_redemption/registration.py` | Are fresh private records assigned to distinct role users, with existing enrollment protected from overwrite? |
| `examples/confined_redemption/software_tpm_verification.py` | Does the optional direct-core path use a genuine quote and the released verifier, with its synthetic-enrollment limits explicit? |
| `fixtures/` | Are private keys generated for the procedure, and are records explicitly synthetic? |
| `compose.yaml` | Are service ports unpublished, the network internal, and running services confined to distinct users with capabilities dropped? |
| `.github/workflows/verification.yml` | Does CI execute the documented verification commands and report failures? |

Follow the handler call site as well as the verifier. A correct verifier is insufficient if another service route reaches the protected operation without it. Follow the complete signed record to ensure the audience, object, action, principal, permitted delegation, and validity fields are authenticated rather than accepted from unsigned context.

## Required regression evidence

| Test | Required observation |
| --- | --- |
| `test_audience_mismatch_rejected` | A capability naming another resource cannot dispatch the handler. |
| `test_token_forwarding_rejected` | The protected resource rejects the bearer-header channel; proxy tests confirm omission downstream and rejection of known reflected credentials. |
| `test_argument_digest_mismatch_rejected` | Substituted arguments do not satisfy the capability's signed action. |
| `test_replay_rejected` | A previously consumed capability cannot dispatch again. |
| `test_second_principal_without_attenuation_rejected` | A second principal cannot redeem without authorized signed attenuation. |
| `test_attenuated_principal_confined_to_granted_actions` | Valid delegation preserves the issued resource and action restrictions. |
| `test_redemption_at_most_once` | Concurrent valid requests sharing the root identifier produce at most one accepted consumption and handler invocation. |
| `test_unauthorized_forwarding_demonstration_succeeds_when_confinement_disabled` | The abstract counterfactual predicate has its documented outcome; no running service disables confinement. |
| `test_quote_or_manifest_mismatch_rejected` | Evidence or manifest substitution is rejected; the default evidence under this required test name is a development record, not a TPM quote. |

For each rejection, inspect the dispatch or handler-count assertion rather than relying only on an error message. Replay tests should use a validly issued capability. Concurrency evidence should cover independently valid invocation proofs sharing one root identifier, including direct and delegated redemption where supported.

The optional `test_real_software_tpm_quote_drives_direct_core_redemption` requires a real simulator interface. It is skipped when `RESOURCE_AUTHORIZATION_TPM_INTERFACE` is absent. An ordinary host-suite pass therefore does not establish execution of the software-TPM path.

## Local verification

Use the committed dependency lock:

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

The host environment supports Python 3.12 or 3.13. Coverage measures both statements and branch opportunities over the library; its configured threshold applies to the combined percentage, not an independent branch-only floor. Refer to `pyproject.toml` for the enforced threshold.

The test suite checks behavior. Ruff checks formatting and selected static rules; mypy checks the configured type boundary; Bandit checks selected security patterns. None is a proof of correctness. `pip-audit` depends on the current advisory service and can produce a different result for the same locked environment later.

## Compose procedure

Start from a clean checkout:

```sh
docker compose config --quiet
docker compose build authorization_server
docker compose run --rm --no-deps --user 0 --cap-add CHOWN --cap-add FOWNER \
  authorization_server python -m examples.confined_redemption.registration \
  --directory /registration
docker compose run --rm --no-deps calling_principal \
  python -m examples.unauthorized_forwarding.demonstration
docker compose up --abort-on-container-exit --exit-code-from calling_principal
```

The registration command creates disposable private keys and signed fixture records. Root and the two added ownership capabilities are limited to that one-shot command; running services have separate user IDs and all capabilities dropped. Registration refuses to overwrite existing enrollment. Phase A evaluates only an abstract decision predicate. Phase B exercises the running authorization, proxy, resource, and delegated-principal paths.

Inspect command exit statuses and phase assertions. Phase A expects acceptance under its disabled predicate and rejection when record equality is required. Phase B expects three handler invocations from the permitted calls, while repeat use, changed arguments, and bearer headers at the resource are rejected. Do not treat a successful image build or an HTTP health response as evidence that the confinement procedure passed.

Run the optional software-TPM procedure separately:

```sh
docker compose --profile software_tpm up -d --wait software_tpm
docker compose --profile software_tpm run --rm --no-deps \
  -e RESOURCE_AUTHORIZATION_TPM_INTERFACE=swtpm:host=software_tpm,port=2321 \
  calling_principal python -m examples.confined_redemption.software_tpm_verification
```

The expected result identifies `isolated_software_tpm_core_redemption`, verified manifest and quote, synthetic enrollment, accepted direct redemption, rejected repeat redemption, and `http_services_integrated: false`. The procedure generates a fresh simulator AK and synthetic chain, commits its principal and holder binding to the quote's qualifying data, and uses the released quote verifier. It checks an expected composite PCR digest; it does not independently appraise PCR-selection policy. TPM evidence is not integrated into HTTP issuance or delegated redemption.

Clean up only this disposable reference state:

```sh
docker compose --profile software_tpm down --volumes
```

An ordinary stop or `docker compose down` preserves the registration and consumption volumes. The command with `--volumes` deletes both for this reference, and the next provisioning creates new keys. Database deletion is permitted for the disposable procedure; it does not preserve replay protection under old trusted keys.

The Dockerfile pins the Python base image by digest and installs the committed Python lock. Debian packages resolve from the configured distribution repositories, and the version-pinned `uv` bootstrap is downloaded during the build. The procedure does not claim byte-identical images.

## Evidence and publication

An audit record should identify the commit, dependency lock, evidence profile, commands completed, observed failures or skips, and whether Compose ran. Distinguish source review, unit tests, HTTP service integration, and the optional genuine-quote core procedure. Do not infer execution of an unrun path from successful compilation or mocks. A genuine quote in the isolated helper does not upgrade the HTTP path's assurance label.

Inspect distributable files for generated keys, local databases, private reports, unpublished security findings, and unrelated workspace material. Only synthetic fixture descriptions and the intended reference source belong in the public repository. A dependency's presence is not evidence of an upstream vulnerability, a remediation claim, or endorsement.

## Interpretation

A passing confined-redemption run supports the configured resource's enforcement and atomic-consumption boundary. It does not upgrade the HTTP development evidence to a TPM quote, prove execution of a manifest, establish hardware-backed identity, or guarantee business completion after consumption. The first phase establishes only the consistency of its abstract synthetic illustration. A passing optional software-TPM procedure supports only its documented synthetic-enrollment and direct-core quote-verification boundary.
