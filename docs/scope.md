# Scope

## Implemented reference boundary

The repository confines one locally issued capability to one resource audience, one synthetic object, the `object.read` tool, and the digest of its exact arguments. It records the original principal and permits at most one signed attenuation to a second principal. The resource verifies holder possession and atomically consumes the root capability identifier before dispatch.

The authorization proxy authenticates its registered bearer credential, omits inbound authorization headers, and rejects the known inbound credential reflected in the serialized outbound body or decoded string fields, including object member names. The resource independently rejects `Authorization` and `Proxy-Authorization` headers. These checks do not establish general credential provenance or identify arbitrary unknown or transformed credentials.

There is one grant type, one resource, one proxy, and one delegation hop. The reference's capability, attenuation, and invocation-proof records are local formats, not standardized OAuth or MCP extensions.

The service adapter uses bounded HTTP JSON at `/issuance`, `/forwarding`, and `/redemption`. It is sufficient to exercise confinement of the single `object.read` request. Full MCP transport and OAuth authorization-server conformance are deferred behind that adapter boundary.

## Attestation and principal registration

The default HTTP evidence profile is `assurance="development"`. An ephemeral Ed25519 key signs a fresh attestation record containing the challenge, principal, holder public key, manifest digest, and expiry. Released Agent Manifest `0.12.0` verifies the signed agent manifest. The registry pins the manifest digest, signer, issuer, artifact expectations, holder key, and attestation key. The local registration and verification interfaces keep these checks explicit.

The signed capability's `authorizing_principal` value `user` is a fixed synthetic fixture label. It does not authenticate an end user or implement a user-consent ceremony. The authenticated actors in this reference are the two registered principal keys and the configured issuers.

This profile does not produce or verify a TPM quote. It establishes no hardware-rooted identity, PCR measurement, attestation-key enrollment, holder-key residency, principal and attester co-location, runtime integrity, or proof of manifest execution. A passing development-profile test must not be described as hardware or software-TPM attestation.

The absence of TPM evidence in this HTTP path does not disable capability signatures, manifest verification, attenuation, holder proofs, audience enforcement, or the redemption store.

## Optional software-TPM procedure

The `software_tpm` Compose profile provides a disposable simulator. `examples.confined_redemption.software_tpm_verification` creates an attestation key in that simulator, issues a synthetic certificate chain around its public key, and obtains a genuine TPM quote. Released Agent Manifest quote verification checks the configured root, quote signature, expected composite PCR digest, and qualifying data. The qualifying data commits to a fresh challenge, principal identifier, signed manifest digest, holder public key, and expiry.

After verification within the freshness interval, this separate procedure marks the binding `assurance="software_tpm"` and uses it for direct core capability issuance and holder-signed redemption. It then verifies that repeat redemption is rejected. Its generated enrollment, quote artifacts, and consumption database are temporary procedure state.

This path is not integrated into the HTTP services and does not exercise TPM-backed delegation. It uses synthetic attestation-key enrollment, not manufacturer enrollment or a hardware endorsement chain. It establishes no holder-key residency, holder and TPM co-location, physical hardware provenance, manifest execution, runtime integrity, or independent PCR-selection appraisal. The expected composite PCR digest is checked; that must not be expanded into a claim that this reference appraises all PCR-selection policy semantics.

## Released dependency composition

| Component | Use in this reference | Boundary |
| --- | --- | --- |
| Agent Manifest `0.12.0` | Verify signed manifests and, in the optional isolated procedure, software-TPM quotes | Uses released verifiers; no vendored replacement |
| Local development attestation | Authenticate the fixture's principal and manifest binding | Ephemeral signed record; no TPM quote or hardware provenance |
| Optional `software_tpm` procedure | Verify a real simulator quote and use its binding in direct core redemption | Synthetic enrollment; separate from HTTP and delegated redemption |
| Local capability and attenuation records | Bind audience, object, action, and principal authority | Reference protocol; no cA2A interoperability claim |
| Local service protocol | Exercise the proxy and resource enforcement boundary | No production gateway or MCP compatibility claim |

cA2A and cMCP are not dependencies of this implementation. The released cA2A `0.2.0` delegation credential used by the prior broker has no audience field, so this reference does not claim that credential natively carries this repository's audience requirement. This reference keeps its explicit audience, action, and attenuation requirements in a narrow local format. The service adapter does not assert cMCP interoperability. These are composition boundaries, not assertions that those projects are defective.

## Demonstration limits

Phase A evaluates an abstract predicate over synthetic grant and request records. The disabled predicate accepts; the enabled predicate requires equality and rejects the differing request. This is a counterfactual decision model with no network activity or resource action. It is not a runnable vulnerable service or a reproduction of an upstream vulnerability.

Phase B uses the running services with confinement enabled. Generated registration keys and one synthetic object are sufficient for the procedure. No private AgenTrust security material, unpublished advisory detail, operational credential, or third-party test target belongs in this repository.

## Redemption limits

The SQLite store enforces at-most-once consumption of the root capability identifier. Direct and attenuated uses share that identifier. Persistence and integrity of the store are required for that property across requests and process restarts.

A crash after consumption can prevent the handler from completing or returning a result. The reference does not offer exactly-once effects, guaranteed completion, distributed consensus, rollback-resistant storage, or recovery that restores a consumed capability. Normal service stops preserve the consumption store. Removing this project's registration and redemption volumes resets only the disposable demonstration; the next registration creates new keys. Clearing consumption state while retaining accepted issuer keys and capabilities would invalidate the replay-protection assumption.

## Deployment limits

Compose provides an internal network without published host ports. Its HTTP service traffic is unencrypted. Each service runs under a distinct user ID with all capabilities dropped and a read-only container filesystem. Generated private registration files belong to their role's user; public registration is shared. The one-shot initialization runs as root with only the added `CHOWN` and `FOWNER` capabilities to establish that ownership. It refuses an existing enrollment directory.

These local controls do not establish confidentiality against the host administrator, container escape, or production network threats. Ephemeral registration material is appropriate for the verification procedure only. Production transport security, operational key custody, enrollment, revocation, availability engineering, and audit-log retention are separate work.

The reference is not an identity provider, marketplace, product site, or production authorization gateway. Prior-work links do not merge its claim with the claims of attested-capability-broker, GoldKey, SENTINEL, or raptor-trace.

## Deferred work

The following are explicitly deferred:

- payments;
- token commerce;
- multi-cloud federation;
- a general policy language; and
- a public authorization service.

Also deferred are hardware TPM enrollment, software-TPM integration with HTTP and delegation, production attestation policy, additional resources or delegation hops, standardized protocol integration, production transport and key management, revocation, distributed consumption, and operational recovery.
