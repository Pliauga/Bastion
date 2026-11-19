# MITRE ATT&CK Coverage: Bastion Against the Cloud Escalation Matrix

> **Closed-Source Commercial Software** — Full technique-by-technique verification dossiers and live demonstration recordings are available under NDA. **Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com).

This document maps Bastion's policy-evaluated authorization capabilities onto the **MITRE ATT&CK Cloud Matrix (IaaS)** for security architects and enterprise procurement teams.

---

## Policy-Evaluated Coverage Standard

For every technique below, Bastion does not grep policies for sensitive action names or wildcards. It evaluates full multi-hop AWS IAM policy semantics — identity policies, trust policies, resource-based policies, permissions boundaries, exclusions, conditions, and dynamic policy variables — returning falsifiable authorization decisions paired with non-breaking remediation.

A technique is marked covered only when:
1. Its authorization primitives are evaluated over full multi-hop policy semantics.
2. Live AWS control-plane executions and/or published benchmark suites validate detection and containment directly.
3. Negative controls verify Bastion distinguishes genuinely exploitable grants from inert decoys.

---

## Coverage Summary

| Technique | Name | Tactic | Published 57-Path Suite | Live AWS Validation | Status |
| :--- | :--- | :--- | :---: | :---: | :--- |
| [`T1098.001`](#t1098001-additional-cloud-credentials) | Additional Cloud Credentials | Persistence, Privilege Escalation | `9 / 9` | Verified | **Full (Policy-Evaluated)** |
| [`T1098.003`](#t1098003-additional-cloud-roles) | Additional Cloud Roles | Persistence, Privilege Escalation | `14 / 14` | Verified | **Full (Policy-Evaluated)** |
| [`T1548.005`](#t1548005-temporary-elevated-cloud-access) | Temporary Elevated Cloud Access | Privilege Escalation, Defense Evasion | `32 / 32` | Verified | **Full (Policy-Evaluated)** |
| [`T1078.004`](#t1078004-valid-accounts-cloud-accounts) | Valid Accounts: Cloud Accounts | Initial Access, Persistence, Privilege Escalation | — | Verified | **Policy-Evaluated (Session/Trust)** |
| [`T1190`](#t1190-exploit-public-facing-application) | Exploit Public-Facing Application | Initial Access | `2 / 2` | Verified | **Policy-Evaluated (Resource Policies)** |

Across the published 57-path AWS IAM escalation benchmark, Bastion achieves **`57 / 57` (`100%`)** coverage (`32 / 32` on the independent bias-free subset), with zero double-counting across technique categories.

---

## T1098.001: Additional Cloud Credentials

### The Threat
An adversary holding an initial foothold mints durable credentials or inherits elevated group privileges (`iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:AddUserToGroup`, or MFA/access-key manipulation). Scoped ARNs and tag-gated conditions routinely slip past wildcard-only scanners.

### Bastion Capability
- Evaluates credential-minting, group-inheritance, and ABAC tag-poisoning preconditions over full multi-hop graphs.
- Validated live on AWS for blind multi-chain discovery, tag-poisoned key minting containment (`HTTP 200 -> 403` with `0` broken legitimate calls), and decoy rejection (`0` false positives).
- **`9 / 9`** credential-access paths detected in the published 57-path suite.

---

## T1098.003: Additional Cloud Roles

### The Threat
An adversary expands authority without minting new static credentials via policy attachment, inline policy writes, policy-version switching, trust-policy rewrites (`iam:UpdateAssumeRolePolicy`), or guardrail tampering — often scoped to narrow resource ARNs.

### Bastion Capability
- Evaluates scoped policy mutations, trust rewrites, and boundary-tampering routes across single chains and converging multi-branch graphs.
- Synthesizes self-defending containment guardrails verified live under `AdministratorAccess` to block boundary deletion, replacement, mutation, unrestricted role minting, and privileged policy attachment while keeping legitimate scoped work running.
- **`14 / 14`** IAM self-mutation and trust-abuse paths detected in the published 57-path suite.

---

## T1548.005: Temporary Elevated Cloud Access

### The Threat
An adversary obtains elevated short-lived credentials through multi-hop `sts:AssumeRole` chains, hidden allow-by-exclusion grants (`PowerUserAccess` / `NotAction`), split-brain `Terraform PR + Live Drift` chains, `sts:TagSession` smuggling, conditional/vacuous-quantifier traps, dynamic `${...}` policy-variable expansion, or compute-carrier laundering (`iam:PassRole` + serverless/compute execution or `lambda:UpdateFunctionCode`).

### Bastion Capability
- Evaluates caller identity policies, target role trust policies, compute-carrier pairings, exclusion/inversion algebra, condition-operator semantics, and dynamic `${...}` policy variables together with **`100%` live AWS parity**.
- Verified live on AWS across serverless pipelines, multi-hop role chains, split-brain Terraform PR + live drift compositions, converging diamond graphs, `PowerUserAccess`, `ForAllValues`/`IfExists` traps, dynamic policy variables, STS session-tag smuggling, and surgical same-verb `iam:PassRole` retention (`HTTP 200 -> 403` containment with `100%` benign continuity).
- **`32 / 32`** temporary-access paths detected in the published 57-path suite.

---

## T1078.004: Valid Accounts: Cloud Accounts

### The Threat
An adversary abuses overly permissive role trusts, valid cloud identities, or session-assumption conditions to obtain legitimate short-lived sessions that chain into privileged access.

### Bastion Capability
- Evaluates trust conditions, tag constraints, session-tag propagation, and multi-hop role-session reachability across chained assumptions rather than stopping at the initial identity.
- Validated live on AWS across chained role assumptions, `sts:TagSession` enforcement parity, role-session resource-policy bypass containment, conditional assumption traps, and session-tag policy-variable overrides.

---

## T1190: Exploit Public-Facing Application

### The Threat
In cloud IAM authorization terms, direct-entry exposure arises through **resource-based policies** (such as S3 bucket policies or Lambda function/layer permissions) that admit unintended principals, allow resource-policy takeover, or bypass attached Permissions Boundaries.

### Bastion Capability
- Evaluates resource-based policies jointly with identity policies and permissions boundaries — identifying and sealing same-account boundary bypasses and `NotPrincipal` boundary traps while preserving legitimate access (`HTTP 200`).
- **`2 / 2`** resource-policy abuse paths (`lambda:AddPermission`, `lambda:AddLayerVersionPermission`) detected in the published 57-path suite.

---

## Scope & NDA Technical Review

Bastion focuses specifically on **cloud IAM authorization reachability and verified non-breaking remediation** — complementing (not replacing) runtime intrusion detection, network WAFs, and application-code scanners.

For detailed technique mappings, live AWS demonstration recordings, or a read-only architecture evaluation in your environment:

**Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com)

---

**Related:** [Public Overview](../README.md) · [Executive CISO Brief](../proof/CISO_SUMMARY.md) · [Plain-English Enterprise Scenarios](./EXECUTIVE_SCENARIOS.md)
