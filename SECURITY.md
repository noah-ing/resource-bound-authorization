# Security policy

## Reporting a vulnerability

Do not include suspected vulnerability details in a public issue.

Use GitHub's private vulnerability reporting flow when the repository's **Security** page shows **Report a vulnerability**. See GitHub's [private reporting procedure](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

If that option is unavailable, open an issue containing only a request for a private reporting channel. Include no sensitive details in the public request. This repository does not publish an alternative security contact address.

In a private report, include the affected commit, prerequisites, observed impact, a minimal safe failing test where appropriate, and any proposed correction or disclosure constraints. Do not include operational credentials or unrelated third-party confidential material.

This reference implementation has no bug-bounty program, response-time service-level agreement, or production support commitment. Its assurance limits are documented in [scope](docs/scope.md) and the [threat model](docs/threat_model.md).

## Reference material

Demonstrations use generated registration keys and synthetic records. Phase A includes an inert counterfactual predicate and live audience-confinement regressions; all running services enforce confinement. The recommended HTTP issuance procedure verifies genuine simulator quotes for caller and delegate under synthetic enrollment, followed by resource-side MCP redemption. This does not establish physical hardware provenance, holder-key residency, or manifest execution. Explicit development enrollment uses signed software records with no TPM assurance; these records cannot satisfy a software-TPM enrollment. OAuth and DCR are not implemented.

Reports concerning another project should follow that project's private reporting policy. This repository is not a publication channel for unpublished upstream security findings.
