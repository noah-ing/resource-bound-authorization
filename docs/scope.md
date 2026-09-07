# Scope

## Implemented reference boundary

The repository confines one locally issued capability to one resource audience, one synthetic object, the `object.read` tool, and the digest of its exact arguments. It records the original principal and permits at most one signed attenuation to a second principal. The resource verifies holder possession and atomically consumes the root capability identifier before dispatch.

The authorization proxy authenticates its registered bearer credential, omits inbound authorization headers, and rejects the known inbound credential reflected in the serialized outbound body or decoded string fields, including object member names. The resource independently rejects `Authorization` and `Proxy-Authorization` headers. These checks do not establish general credential provenance or identify arbitrary unknown or transformed credentials.

There is one grant type, one resource, one proxy, and one delegation hop. The reference's capability, attenuation, and invocation-proof records are local formats, not standardized OAuth or MCP extensions.

The proxy and resource implement a narrow MCP `2026-07-28` Streamable HTTP profile at `/mcp`: `server/discover`, `tools/list`, and `tools/call`, each with a single JSON response. Released `mcp==2.1.1` and locked `mcp-types==2.1.1` validate protocol records, per-request metadata, and mirrored HTTP headers. The adapter checks the outer tool name and arguments against the signed invocation in `params._meta["io.github.noah-ing/resource-bound-authorization"]`. Both network hops use that protocol. The released SDK client is tested against running proxy and resource services.

This is transport and tool interoperability with a reference authorization extension, not complete MCP conformance. It excludes OAuth 2.1, authorization-code flows, DCR, client-ID registration failures, tasks, subscriptions, streaming responses, sessions, and earlier protocol handshakes. Issuance, challenges, and delegation coordination retain bounded local HTTP JSON endpoints. See the [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28).

## Attestation and principal registration

The recommended Compose procedure provisions `assurance="software_tpm"`. Enrollment pins the signed manifest digest, signer, issuer, artifact expectations, holder key, and a separate simulator attestation key for each principal. It also pins each key's synthetic certificate chain, trust root, and expected composite PCR digest. The issuer chooses that trust from its registry; request evidence cannot replace it. Released Agent Manifest `0.12.0` verifies the configured manifest and quote.

Each quote binds the fresh server challenge, principal identifier, holder public key, manifest digest, and expiry. HTTP issuance verifies both caller and delegate evidence when delegation is requested. It then rechecks freshness under the challenge lock, consumes the challenge once, and caps capability validity by the evidence expiry. The signed capability and attenuation preserve both verified principal bindings through resource-side redemption.

The signed capability's `authorizing_principal` value `user` is a fixed synthetic fixture label. It does not authenticate an end user or implement a user-consent ceremony. The authenticated actors in this reference are the two registered principal keys and the configured issuers.

For host tests, explicit `assurance="development"` enrollment uses an ephemeral Ed25519-signed attestation record. It produces no TPM quote and establishes no TPM measurements or attestation-key enrollment. A passing development-profile test must not be described as hardware or software-TPM attestation. Software-TPM enrollment rejects development evidence; a missing simulator interface causes failure, not a fallback.

Development enrollment does not disable capability signatures, manifest verification, attenuation, holder proofs, audience enforcement, or the redemption store.

## Software-TPM assurance boundary

The `software_tpm` Compose profile provides a disposable simulator. Registration creates separate caller and delegate attestation keys in it, with synthetic test-CA enrollment. Each role reads only its own saved context; a shared read-only lock serializes simulator context operations. Quote artifacts are temporary. Released Agent Manifest verification checks the enrolled chain/root, quote signature, expected composite PCR digest, and qualifying data during HTTP issuance.

The integrated procedure exercises both direct and delegated MCP redemption with `software_tpm` bindings. A separate lower-level helper, `examples.confined_redemption.software_tpm_verification`, remains a direct-core regression with its own enrollment; it does not supply the integrated procedure's evidence. Standalone TPM tests reset simulator PCR state and must run before demonstration enrollment, as CI does.

The simulator and synthetic enrollment establish no manufacturer enrollment or hardware endorsement chain. They establish no holder-key residency, holder and TPM co-location, physical hardware provenance, manifest execution, runtime integrity, or independent PCR-selection appraisal. The expected composite PCR digest is checked; this is not a claim that the reference appraises all PCR-selection policy semantics.

## Released dependency composition

| Component | Use in this reference | Boundary |
| --- | --- | --- |
| Agent Manifest `0.12.0` | Verify signed manifests and enrolled software-TPM quotes during HTTP issuance | Uses released verifiers; no vendored replacement |
| MCP SDK `2.1.1` / `mcp-types==2.1.1` | Validate current protocol records and test SDK client interoperability | Narrow JSON-response transport profile; local authorization extension |
| Local development attestation | Authenticate the fixture's principal and manifest binding | Ephemeral signed record; no TPM quote or hardware provenance |
| `software_tpm` Compose procedure | Verify real caller and delegate quotes, then exercise MCP redemption | Synthetic enrollment; no physical hardware provenance |
| Local capability and attenuation records | Bind audience, object, action, and principal authority | Reference protocol; no cA2A interoperability claim |
| Local issuance and coordination protocol | Supply challenges, issue capabilities, and request delegation | No OAuth, DCR, or production gateway claim |

cA2A and cMCP are not dependencies of this implementation. The released cA2A `0.2.0` delegation credential used by the prior broker has no audience field, so this reference does not claim that credential natively carries this repository's audience requirement. This reference keeps its explicit audience, action, and attenuation requirements in a narrow local format. The service adapter does not assert cMCP interoperability. These are composition boundaries, not assertions that those projects are defective.

## Demonstration limits

Phase A evaluates an abstract predicate over synthetic grant and request records. The disabled predicate accepts; the enabled predicate requires equality and rejects the differing request. This is a counterfactual decision model with no network activity or resource action. It is not a runnable vulnerable service or a reproduction of an upstream vulnerability.

Phase B uses the running services with confinement enabled. Generated registration keys and one synthetic object are sufficient for the procedure. No private AgenTrust security material, unpublished advisory detail, operational credential, or third-party test target belongs in this repository.

## Redemption limits

The SQLite store enforces at-most-once consumption of the root capability identifier. Direct and attenuated uses share that identifier. Persistence and integrity of the store are required for that property across requests and process restarts.

A crash after consumption can prevent the handler from completing or returning a result. The reference does not offer exactly-once effects, guaranteed completion, distributed consensus, rollback-resistant storage, or recovery that restores a consumed capability. Normal service stops preserve the consumption store. Removing this project's registration and redemption volumes resets only the disposable demonstration; the next registration creates new keys. Clearing consumption state while retaining accepted issuer keys and capabilities would invalidate the replay-protection assumption.

## Deployment limits

Compose provides an internal network without published host ports. Its HTTP service traffic is unencrypted. Each service runs under a distinct user ID with all capabilities dropped and a read-only container filesystem. Generated private registration files belong to their role's user; public registration is shared. The one-shot initialization runs as root with only the added `CHOWN` and `FOWNER` capabilities to establish that ownership. It refuses an existing enrollment directory.

These local controls do not establish confidentiality against the host administrator, container escape, or production network threats. The simulator's state is disposable; stopping or recreating it can invalidate saved AK contexts, including after the recommended Compose command stops all containers. For a new demonstration, remove this reference's containers and volumes and repeat fresh enrollment. Preserved registration files alone do not establish restart usability. Preserve consumption state for as long as the corresponding keys and capabilities are accepted. Production transport security, key custody, enrollment, revocation, availability engineering, and audit-log retention are separate work.

The reference is not an identity provider, marketplace, product site, or production authorization gateway. Prior-work links do not merge its claim with the claims of attested-capability-broker, GoldKey, SENTINEL, or raptor-trace.

## Deferred work

The following are explicitly deferred:

- payments;
- token commerce;
- multi-cloud federation;
- a general policy language; and
- a public authorization service.

Also deferred are physical TPM enrollment, production attestation policy, additional resources or delegation hops, OAuth/DCR integration, broader MCP conformance, production transport and key management, revocation, distributed consumption, and operational recovery.
