# Threat model

## Scope and assurance statement

The protected operation is `object.read` on one synthetic object. The reference has one authorization server, one resource server, one authorization proxy, an original calling principal, and at most one permitted delegated principal. A capability authorizes an exact audience, object, tool, and argument digest.

For the tested configuration, successful verification can establish that the resource authenticated the capability and invocation proof, enforced the recorded principal and action bindings, and consumed the root capability identifier at most once before handler dispatch. It does not establish physical hardware provenance, principal execution, key residency, principal and attester co-location, runtime integrity, confidentiality, or exactly-once business execution.

The recommended HTTP enrollment requires genuine software-TPM quotes from separately enrolled caller and delegate keys. Released Agent Manifest verifies each manifest and quote at issuance. Explicit development enrollment instead uses ephemeral Ed25519-signed records and makes no TPM claim. Enrollment fixes the required assurance; missing simulator access cannot cause a development fallback. Neither evidence profile proves that an agent executed the manifest.

## Assets and objectives

The protected assets are the ability to invoke the resource handler, the integrity of capability and principal bindings, and the integrity of the redemption store.

The resource shall require:

1. a capability signed by the configured authorization server;
2. an audience identifying this resource, and the configured object;
3. the exact tool and argument digest authorized by the capability;
4. an original principal binding accepted at issuance;
5. a valid signed attenuation record for a permitted second principal;
6. a valid invocation signature from the effective holder; and
7. an unconsumed root capability identifier at the transaction that precedes dispatch.

The proxy shall omit inbound bearer credentials from its downstream request and reject a known inbound credential reflected in that request's record. The resource shall reject `Authorization` or `Proxy-Authorization` headers even when the accompanying capability would otherwise be valid.

## Trusted computing base

The reference trusts:

- authorization-server and resource-server code, configuration, and hosts;
- the configured issuer, manifest signer, registered principal, and enrolled attestation verification keys and trust roots;
- private-key secrecy, signature implementations, canonical serialization, and the randomness source;
- the released Agent Manifest verifier, MCP SDK protocol validation, and pinned runtime dependencies;
- the resource's clock and configured validity policy;
- SQLite transaction and uniqueness guarantees, persistent store integrity, and the operating system's storage behavior; and
- a topology in which the protected handler is reachable only after resource-side verification and consumption.

Compromise of a trusted issuer or verification key, replacement of application code, or deletion or rollback of the redemption database is outside the claim. The authority of a signed record depends on the configured signer policy.

## Untrusted inputs

The caller may supply altered capabilities, an incorrect audience, substituted tool arguments, an unrecorded principal, a modified attenuation record, or repeated invocation proofs. The resource treats these values as untrusted until the applicable verification succeeds. A proxy does not acquire authority to change a capability merely by transporting it.

The reference does not infer identity from an HTTP header or trust an unsigned assertion that a caller is the original principal. Possession of the capability alone is insufficient: the effective holder must supply the invocation signature required by the accepted capability and attenuation record.

The capability's fixed `authorizing_principal` label `user` is synthetic context. It is not an authenticated end-user identity or evidence of a consent ceremony. The reference authenticates the registered calling and delegated principal keys.

## Issuance boundary

Agent Manifest `0.12.0` verifies the signed manifest against the configured signer. Under software-TPM enrollment, the authorization server verifies the quote against the server-selected principal's AK, chain, root, and expected composite PCR digest. It checks both caller and delegate evidence before granting delegation. The capability signature covers the resource, action, original principal binding, and permitted delegation.

Under explicit development enrollment, an enrolled fixture key authenticates the signed record but establishes no TPM state. That record is rejected under software-TPM enrollment. This distinction remains visible in evidence types, policy, and the [scope](scope.md).

The HTTP authorization server supplies and consumes the issuance challenge. The signed evidence binds that challenge, principal, holder public key, manifest digest, and expiry. Public registration pins the expected manifest signer, issuer, artifact expectations, principal keys, assurance, and attestation trust. After verification, issuance rechecks freshness while holding the challenge lock, consumes the challenge once, and bounds capability expiry by the evidence validity. Request evidence cannot replace enrollment.

## Software-TPM boundary

Registration generates separate caller and delegate attestation keys in the simulator and synthetic test-CA certificate chains around those keys. During HTTP issuance, released verification checks the enrolled root, quote signature, expected composite PCR digest, and qualifying data. The qualifying data commits to a fresh challenge, principal, holder public key, signed manifest digest, and expiry. Direct and delegated redemption use the resulting signed `software_tpm` bindings.

This procedure adds the simulator, synthetic CA enrollment, fixed TPM command tools, and quote verifier to its trusted computing base. Per-role filesystem permissions separate saved AK contexts; a shared read-only lock serializes simulator operations. These controls do not isolate principals from a compromised simulator or host. The synthetic chain establishes neither manufacturer enrollment nor physical hardware provenance. The holder key is not shown to reside in or beside the TPM. Independent PCR-selection appraisal, workload execution, and runtime integrity remain outside the claim.

## Delegation boundary

The reference permits zero or one attenuation record. For delegated use, the original principal signs the record naming the permitted second principal and confining the action to the issued authority. The delegated principal supplies proof of possession for the invocation. The original principal remains recorded rather than being replaced by an assertion that the second principal is the original user.

The resource rejects an unpermitted delegate, an absent or invalid attenuation signature, an enlarged action, or an invocation signed by a different holder. Direct and delegated redemption consume the same root capability identifier. Issuing multiple invocation proofs or choosing different permitted paths does not create additional redemptions.

## Resource and forwarding boundaries

The resource performs signature, audience, principal, attenuation, and action checks before the protected handler. Its acceptance decision does not depend on the proxy enforcing those checks first. A request sent directly to the resource must satisfy the same confinement requirements.

The proxy authenticates the registered bearer credential and builds a downstream request from the reference capability and invocation fields. It omits inbound authorization headers and checks the serialized body and decoded object names and string values for the known inbound credential before forwarding the checked record. The resource independently rejects `Authorization` and `Proxy-Authorization` headers. This excludes known credential reflection, including JSON string escaping; it does not establish the origin of arbitrary unknown or transformed credential bytes.

Both proxy and resource accept MCP `2026-07-28` discovery, listing, and tool calls at `/mcp`. SDK validation checks protocol metadata and mirrored headers. The adapter requires the outer tool and arguments to match the invocation in namespaced authorization metadata before invoking the enforcing callback. Proxy forwarding constructs fresh downstream metadata, omits inbound credentials, and correlates responses to fresh request identifiers. Present Origin headers must match an explicit allowlist; none are allowed by default. Discovery and listing are public, while every tool call requires reference authorization.

The profile uses single JSON responses and local capability authorization. It does not implement OAuth, authorization-code flows, DCR, or full MCP conformance. Bounded JSON issuance and coordination endpoints remain local reference interfaces. The tests make no defect or remediation claim about another project's authorization service.

## At-most-once boundary

The resource records consumption of the root capability identifier in an SQLite write transaction before handler invocation. Uniqueness of that identifier prevents a second accepted consumption, including competing requests that have separately valid signatures.

At-most-once redemption is an availability tradeoff. A crash after consumption and before or during dispatch can leave the capability spent with no completed effect or response. A failed response is not proof that consumption did not occur. Exactly-once business execution, transactionally coupled external effects, distributed redemption, and recovery after database rollback are outside scope.

## Demonstration boundary

Phase A evaluates an inert counterfactual predicate over synthetic grant and request records. Its disabled predicate accepts; its enabled predicate compares the records and rejects their mismatch. It does not provide an insecure HTTP route, forward a live bearer credential, execute a resource action, or test a third-party endpoint. Its expected counterfactual result is not evidence of a defect in any released dependency.

Phase B and every running service enforce the acceptance requirements. No runtime switch disables those requirements.

## Deployment and operational exclusions

The internal Compose network publishes no host ports, but service traffic is HTTP without TLS. This is a local verification topology, not a confidentiality or production-network boundary. Running services have distinct user IDs, read-only container filesystems, and all capabilities dropped. One-shot registration uses root with scoped ownership capabilities to create role-owned private records. These controls do not protect against a compromised host administrator or establish container isolation against all threats.

Registration keys are ephemeral demonstration material. Ordinary shutdown preserves files and the consumption store, but stopping or recreating the simulator can invalidate saved AK contexts. Repeat the complete cleanup and fresh enrollment procedure for another run. Removing this reference's registration and redemption volumes deletes both; new provisioning creates new keys. Consumption-store deletion while old keys remain trusted is outside the at-most-once assumption. Production enrollment, transport authentication, rotation, revocation, denial-of-service resistance, administrative controls, and operational recovery are not implemented assurance claims.

All examples use synthetic objects and generated registration material. This repository neither includes private security reports nor establishes the status of upstream security findings.
