# Threat model

## Scope and assurance statement

The protected operation is `object.read` on one synthetic object. The reference has one authorization server, one resource server, one authorization proxy, an original calling principal, and at most one permitted delegated principal. A capability authorizes an exact audience, object, tool, and argument digest.

For the tested configuration, successful verification can establish that the resource authenticated the capability and invocation proof, enforced the recorded principal and action bindings, and consumed the root capability identifier at most once before handler dispatch. It does not establish physical hardware provenance, principal execution, key residency, principal and attester co-location, runtime integrity, confidentiality, or exactly-once business execution.

The default HTTP evidence, `assurance="development"`, is an ephemeral Ed25519-signed attestation record. It is not a TPM quote. Released Agent Manifest verification authenticates the configured signed manifest; neither a signed manifest nor this development evidence proves that an agent executed the manifest. The optional software-TPM procedure has a separate, isolated core boundary described below.

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
- the configured issuer, manifest signer, registered principal, and development attestation verification keys;
- private-key secrecy, signature implementations, canonical serialization, and the randomness source;
- the released Agent Manifest verifier and pinned runtime dependencies;
- the resource's clock and configured validity policy;
- SQLite transaction and uniqueness guarantees, persistent store integrity, and the operating system's storage behavior; and
- a topology in which the protected handler is reachable only after resource-side verification and consumption.

Compromise of a trusted issuer or verification key, replacement of application code, or deletion or rollback of the redemption database is outside the claim. The authority of a signed record depends on the configured signer policy.

## Untrusted inputs

The caller may supply altered capabilities, an incorrect audience, substituted tool arguments, an unrecorded principal, a modified attenuation record, or repeated invocation proofs. The resource treats these values as untrusted until the applicable verification succeeds. A proxy does not acquire authority to change a capability merely by transporting it.

The reference does not infer identity from an HTTP header or trust an unsigned assertion that a caller is the original principal. Possession of the capability alone is insufficient: the effective holder must supply the invocation signature required by the accepted capability and attenuation record.

The capability's fixed `authorizing_principal` label `user` is synthetic context. It is not an authenticated end-user identity or evidence of a consent ceremony. The reference authenticates the registered calling and delegated principal keys.

## Issuance boundary

Agent Manifest `0.12.0` verifies the signed manifest against the configured signer. The authorization server checks the registered principal binding and the development attestation record before issuing a capability. The capability signature covers the resource, action, original principal binding, and permitted delegation.

The development attestation key is a fixture trust root. Its signature authenticates the record under that key; it does not establish measured platform state or a TPM attestation key. This distinction remains visible in the evidence type and the [scope](scope.md).

The HTTP authorization server supplies and consumes the issuance challenge. The signed evidence binds that challenge, principal, holder public key, manifest digest, and expiry. Public registration pins the expected manifest signer, issuer, artifact expectations, and principal and attestation keys. Issuance depends on successful verification under those configured values.

## Optional software-TPM boundary

The isolated software-TPM procedure generates an attestation key in the simulator and a synthetic test-CA certificate chain around that key. It uses released Agent Manifest verification for the quote signature, configured root, expected composite PCR digest, and qualifying data. The qualifying data commits to a fresh challenge, principal, holder public key, signed manifest digest, and expiry. The procedure checks freshness before issuing a capability from the resulting `software_tpm` binding, then performs direct core redemption and rejects repeat use.

This procedure adds the simulator, synthetic CA, fixed TPM command tools, and quote verifier to its trusted computing base. It does not change the HTTP services' development assurance and does not exercise TPM-backed delegation. The synthetic chain does not establish manufacturer enrollment or physical hardware provenance. The holder key is not shown to reside in the TPM or beside it. Independent PCR-selection appraisal, workload execution, and runtime integrity are outside this procedure's claim.

## Delegation boundary

The reference permits zero or one attenuation record. For delegated use, the original principal signs the record naming the permitted second principal and confining the action to the issued authority. The delegated principal supplies proof of possession for the invocation. The original principal remains recorded rather than being replaced by an assertion that the second principal is the original user.

The resource rejects an unpermitted delegate, an absent or invalid attenuation signature, an enlarged action, or an invocation signed by a different holder. Direct and delegated redemption consume the same root capability identifier. Issuing multiple invocation proofs or choosing different permitted paths does not create additional redemptions.

## Resource and forwarding boundaries

The resource performs signature, audience, principal, attenuation, and action checks before the protected handler. Its acceptance decision does not depend on the proxy enforcing those checks first. A request sent directly to the resource must satisfy the same confinement requirements.

The proxy authenticates the registered bearer credential and builds a downstream request from the reference capability and invocation fields. It omits inbound authorization headers and checks the serialized body and decoded object names and string values for the known inbound credential before forwarding the checked record. The resource independently rejects `Authorization` and `Proxy-Authorization` headers. This excludes known credential reflection, including JSON string escaping; it does not establish the origin of arbitrary unknown or transformed credential bytes.

The service adapter exposes bounded HTTP JSON at `/issuance`, `/forwarding`, and `/redemption` for `object.read`. It is not a complete MCP transport or OAuth implementation. No compatibility, defect, or remediation claim about released MCP authorization services follows from these checks.

## At-most-once boundary

The resource records consumption of the root capability identifier in an SQLite write transaction before handler invocation. Uniqueness of that identifier prevents a second accepted consumption, including competing requests that have separately valid signatures.

At-most-once redemption is an availability tradeoff. A crash after consumption and before or during dispatch can leave the capability spent with no completed effect or response. A failed response is not proof that consumption did not occur. Exactly-once business execution, transactionally coupled external effects, distributed redemption, and recovery after database rollback are outside scope.

## Demonstration boundary

Phase A evaluates an inert counterfactual predicate over synthetic grant and request records. Its disabled predicate accepts; its enabled predicate compares the records and rejects their mismatch. It does not provide an insecure HTTP route, forward a live bearer credential, execute a resource action, or test a third-party endpoint. Its expected counterfactual result is not evidence of a defect in any released dependency.

Phase B and every running service enforce the acceptance requirements. No runtime switch disables those requirements.

## Deployment and operational exclusions

The internal Compose network publishes no host ports, but service traffic is HTTP without TLS. This is a local verification topology, not a confidentiality or production-network boundary. Running services have distinct user IDs, read-only container filesystems, and all capabilities dropped. One-shot registration uses root with scoped ownership capabilities to create role-owned private records. These controls do not protect against a compromised host administrator or establish container isolation against all threats.

Registration keys are ephemeral demonstration material. Ordinary shutdown preserves them and the persistent consumption store. Removing the reference's registration and redemption volumes deletes both; provisioning a new run creates new keys. Consumption-store deletion while old keys remain trusted is outside the at-most-once assumption. Secure production enrollment, transport authentication, key rotation, revocation, rate limiting, denial-of-service resistance, administrative controls, and operational recovery are not implemented assurance claims.

All examples use synthetic objects and generated registration material. This repository neither includes private security reports nor establishes the status of upstream security findings.
