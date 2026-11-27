# MITRE ATT&CK Coverage: Auga IAM Against the Cloud Escalation Matrix

> **Closed-Source Commercial Software** — Full technique-by-technique verification dossiers and live demonstration recordings are available under NDA. **Contact:** [Ed@Pliauga.co.uk](mailto:Ed@Pliauga.co.uk).

This document maps Auga IAM's policy-evaluated authorization capabilities onto the **MITRE ATT&CK Cloud Matrix (IaaS)** across **AWS** and **GCP** for security architects and enterprise procurement teams.

---

## Policy-Evaluated Coverage Standard

For every technique below, Auga IAM does not grep policies for sensitive action names or wildcards. It evaluates full multi-hop cloud authorization semantics — AWS identity policies, trust policies, resource-based policies, permissions boundaries, Service Control Policies (SCPs), Resource Control Policies (RCPs), exclusions, conditions, and dynamic policy variables, alongside GCP `IAM Allow`, `IAM Deny v2`, CEL conditions, `Org Policy v2`, and `Principal Access Boundaries (PAB)` — returning falsifiable authorization decisions paired with non-breaking remediation.

A technique is marked covered only when:
1. Its authorization primitives are evaluated over full multi-hop policy semantics.
2. Live AWS and/or GCP control-plane executions and published benchmark suites validate detection and containment directly.
3. Negative controls verify Auga IAM distinguishes genuinely exploitable grants from inert decoys.

---

## Coverage Summary

| Technique | Name | Tactic | Published AWS Suites (`57` + `92` Catalog) | Live AWS & GCP Validation | Status |
| :--- | :--- | :--- | :---: | :---: | :--- |
| [`T1098.001`](#t1098001-additional-cloud-credentials) | Additional Cloud Credentials | Persistence, Privilege Escalation | `9 / 9` + `pathfinding.cloud` | Verified (AWS & GCP) | **Full (Policy-Evaluated)** |
| [`T1098.003`](#t1098003-additional-cloud-roles) | Additional Cloud Roles | Persistence, Privilege Escalation | `14 / 14` + `pathfinding.cloud` | Verified (AWS & GCP) | **Full (Policy-Evaluated)** |
| [`T1548.005`](#t1548005-temporary-elevated-cloud-access) | Temporary Elevated Cloud Access | Privilege Escalation, Defense Evasion | `32 / 32` + `pathfinding.cloud` | Verified (AWS & GCP) | **Full (Policy-Evaluated)** |
| [`T1078.004`](#t1078004-valid-accounts-cloud-accounts) | Valid Accounts: Cloud Accounts | Initial Access, Persistence, Privilege Escalation | Verified (Trust / WIF) | Verified (AWS & GCP) | **Policy-Evaluated (Session/Trust)** |
| [`T1190`](#t1190-exploit-public-facing-application) | Exploit Public-Facing Application | Initial Access | `2 / 2` + `pathfinding.cloud` | Verified (AWS & GCP) | **Policy-Evaluated (Resource Policies)** |

Across the published 57-path AWS IAM escalation benchmark, Auga IAM achieves **`57 / 57` (`100%`)** coverage (`32 / 32` on the independent bias-free subset), and across Datadog's **`92`-path `pathfinding.cloud`** multi-service catalog, Auga IAM achieves **`92 / 92` (`100%`)** coverage — with zero double-counting across technique categories.

---

## T1098.001: Additional Cloud Credentials

### The Threat
An adversary holding an initial foothold mints durable credentials or inherits elevated group privileges (`iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:AddUserToGroup`, or on GCP `iam.serviceAccountKeys.create`, `apikeys.keys.create`, `storage.hmacKeys.create`). Scoped ARNs and tag-gated conditions routinely slip past wildcard-only scanners.

### Auga IAM Capability
- Evaluates credential-minting, group-inheritance, and ABAC tag-poisoning preconditions over full multi-hop graphs across both AWS and GCP.
- Validated live on AWS (`26/26` org parity, tag-poisoned key minting `HTTP 200 -> 403`, `0` decoy false positives) and live on GCP (`GAUNTLET-100` `77/77`, Stratus Red Team `4/4` including `create-service-account-key`, `HTTP 403` with `Δ Benign = 0`).
- **`9 / 9`** credential-access paths detected in the published 57-path suite, plus **`100%`** of credential paths in the `92`-path `pathfinding.cloud` catalog.

---

## T1098.003: Additional Cloud Roles

### The Threat
An adversary expands authority without minting new static credentials via policy attachment, inline policy writes, policy-version switching, trust-policy rewrites (`iam:UpdateAssumeRolePolicy`), guardrail tampering, or GCP `iam.roles.update` / `setIamPolicy` backdoors — often scoped to narrow resource ARNs.

### Auga IAM Capability
- Evaluates scoped policy mutations, trust rewrites, and boundary-tampering routes across single chains and converging multi-branch graphs.
- Synthesizes self-defending containment guardrails verified live under `AdministratorAccess` (`15/15` escape vectors blocked at `HTTP 403`) with atomic in-place `CreatePolicyVersion` cutover and multi-class convergence (verifying both data-plane reads and policy-mutation verbs before declaring enforcement complete), plus live GCP custom-role and SA policy narrowing (`5/5` blocked).
- **`14 / 14`** IAM self-mutation and trust-abuse paths detected in the published 57-path suite, plus **`100%`** of role/policy-mutation paths in the `92`-path catalog.

---

## T1548.005: Temporary Elevated Cloud Access

### The Threat
An adversary obtains elevated short-lived credentials through multi-hop `sts:AssumeRole` chains, hidden allow-by-exclusion grants (`PowerUserAccess` / `NotAction`), split-brain `Terraform PR + Live Drift` chains, `sts:TagSession` smuggling, conditional/vacuous-quantifier traps, dynamic `${...}` policy-variable expansion, compute-carrier laundering (`iam:PassRole` + serverless/compute execution or `lambda:UpdateFunctionCode`), structural AWS Organizations RCP exemptions, or GCP `signJwt` / `actAs` / Cloud Run / GCE carrier impersonation.

### Auga IAM Capability
- Evaluates caller identity policies, target role trust policies, compute-carrier pairings, exclusion/inversion algebra, condition-operator semantics, dynamic `${...}` policy variables, and AWS Organizations `SCP + RCP` inheritance together with **`100%` live control-plane parity**.
- Where services sit outside AWS RCP reach (such as `iam` or `lambda`), Auga IAM surfaces the RCP boundary honestly and automatically synthesizes paired **SCP + Permissions Boundary** fallback containment (`HTTP 200 -> 403`, `Δ Benign = 0`).
- Verified live on AWS across `26/26` org arms (`0` steady-state production heartbeat errors across `33` calls), compressed boundaries (`69,556 -> 3,603` chars across `500` objects / `519` grants, scaling to `1,000+` objects with `0` leaks), and live on GCP across `12` workload carriers (`GAUNTLET-100` `77/77`, `MESSY-PROD-LIVE-200` `5/5` blocked, `BAR` `11/11` `100%`).
- **`32 / 32`** temporary-access paths detected in the published 57-path suite, plus **`100%`** of temporary-access and compute-carrier paths in the `92`-path `pathfinding.cloud` catalog.

---

## T1078.004: Valid Accounts: Cloud Accounts

### The Threat
An adversary abuses overly permissive role trusts, valid cloud identities, federated OIDC / Workload Identity Federation (`principalSet://`) bindings, or session-assumption conditions to obtain legitimate short-lived sessions that chain into privileged access.

### Auga IAM Capability
- Evaluates trust conditions, tag constraints, session-tag propagation, OIDC `StringLike` / WIF attribute predicates, and multi-hop role-session reachability across chained assumptions rather than stopping at the initial identity.
- Validated live on AWS (`sts:TagSession`, EKS Pod Identity, OIDC trust hardening, `sts:ExternalId` confused-deputy rejection) and live on GCP (`principalSet://` attribute filtering, tombstoned `deleted:` principals).

---

## T1190: Exploit Public-Facing Application

### The Threat
In cloud IAM authorization terms, direct-entry exposure arises through **resource-based policies** (such as S3 bucket policies, SQS/SNS/ECR/DynamoDB/Backup policies, or Lambda function/layer permissions) that admit unintended principals, allow resource-policy takeover, or bypass attached Permissions Boundaries.

### Auga IAM Capability
- Evaluates resource-based policies jointly with identity policies, permissions boundaries, SCPs, and RCPs — identifying and sealing same-account boundary bypasses, `NotPrincipal` boundary traps, and multi-service resource-policy exposures (`33` AWS services, `17` policy/resource-policy synthesis types) while preserving legitimate access (`HTTP 200`).
- **`2 / 2`** resource-policy abuse paths (`lambda:AddPermission`, `lambda:AddLayerVersionPermission`) detected in the published 57-path suite, plus `16/16` live AWS RBP/carrier arms PASS.

---

## Scope & NDA Technical Review

Auga IAM focuses specifically on **cloud IAM authorization reachability and verified non-breaking remediation** — complementing (not replacing) runtime intrusion detection, network WAFs, and application-code scanners.

For detailed technique mappings, live AWS and GCP demonstration recordings, or a read-only architecture evaluation in your environment:

**Contact:** [Ed@Pliauga.co.uk](mailto:Ed@Pliauga.co.uk)

---

**Related:** [Public Overview](../README.md) · [Executive CISO Brief](../proof/CISO_SUMMARY.md) · [Plain-English Enterprise Scenarios](./EXECUTIVE_SCENARIOS.md)
