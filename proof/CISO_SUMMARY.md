# Executive Brief — Bastion for Cloud Security Leadership

> **Closed-Source Commercial Software** — Full technical verification dossiers, live AWS demonstration recordings, and pilot scoping are available under NDA. **Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com).

## 1. The Problem in One Sentence

IAM privilege escalation is a multi-hop authorization reachability problem, yet standard cloud scanners stop at noisy static alerts instead of delivering a minimal remediation that is **proven to block the attack on live AWS** and **proven not to break production**.

---

## 2. Verified Live AWS Capabilities

Bastion has been validated end-to-end against the live AWS control plane across the hardest classes of real-world cloud IAM compromise:

- **Zero-Collateral Containment:** Severs multi-hop privilege escalation paths across serverless pipelines, transitive role chains, and converging multi-branch graphs while preserving **`100%` of legitimate production workloads (`HTTP 200`/`201`)**.
- **Split-Brain Pre-Merge Protection (`Terraform PR + Live Drift`):** Catches escalation chains that only exist when a clean pull request meets pre-existing live console drift — blocking the compromise before merge and generating clean Terraform fixes.
- **Blind Account Discovery & Observed Traffic Continuity:** Discovers hidden multi-hop chains across unfamiliar multi-principal accounts with **`100%` recall and `0` decoy false positives**, incorporating observed CloudTrail activity (including implicit downstream AWS service calls) so remediation never disrupts running services.
- **Live AWS Semantic Parity Where Scanners Fail:** Matches live AWS control-plane behavior across:
  - Same-account resource-policy Permissions-Boundary bypasses and self-defending guardrails tested under `AdministratorAccess`
  - Allow-by-exclusion policies (`PowerUserAccess`, `NotAction`, `NotResource`) and `NotPrincipal` boundary traps
  - Complex condition-operator and absent-key algebra (`ForAllValues`, `IfExists`, negated denies, case-folding, multi-valued tag sets)
  - Dynamic `${...}` IAM policy variables (tag-driven interpolation, defaults, live STS session-tag overrides, principal-type rules, version gating, and wildcard-injection safety)
  - ABAC tag poisoning and STS session-tag smuggling where standard scanners and AWS's own policy simulator diverge from live AWS STS
  - Multi-service `iam:PassRole` precision — blocking admin escalation while preserving benign role passing for the exact same caller
- **Head-to-Head Scanner Accuracy:** In a balanced `36`-scenario evaluation (`18` genuine escalations, `18` unexploitable decoys across `9` IAM domains), Bastion achieved **`100.0%` Precision, `100.0%` Recall (`1.000` F1)** — compared to **`0.833` F1** for Principal Mapper (`1.1.5`), **`0.276` F1** for Checkov (`3.3.30`), **`0.190` F1** for Trivy (`0.76.0`) and Prowler IaC (`5.48.0`), and **`0.182` F1** for Cloudsplaining (`0.9.1`).
- **Datadog `pathfinding.cloud` Coverage (`92` Modern AWS Paths):** Bastion detected **`86 / 92` (`93.5%`)** overall — including **`59 / 59` (`100%`)** across all IAM, STS, and mainstream compute-carrier paths — vs. **`60 / 92` (`65.2%`)** for Cloudsplaining, **`27 / 92` (`29.3%`)** for PMapper, **`26 / 92` (`28.3%`)** for Checkov (`CKV_AWS_286`), and **`3 / 92` (`3.3%`)** for Trivy.
- **Zero-Collateral Remediation (`AWSGoat` & `TerraGoat`):** On INE's `AWSGoat` (`module-2`), Bastion was the **only** tool to catch the full escalation path and synthesize a verified guardrail closing the exploit with **`100%` (`3/3`)** production workload calls intact (competitors produced `0` fixes), while reporting **`0` false escalation alarms** on Bridgecrew's `TerraGoat` (where Checkov and Cloudsplaining both false-alarmed).
<<<<<<< HEAD
=======
- **Multi-Account Organizations (SCP + RCP + Cross-Account Trust) Parity (`24` Scenarios):** Across AWS Organizations SCPs, Resource Control Policies (RCPs), cross-account trust conditions (`aws:PrincipalOrgID`, `sts:ExternalId`, `aws:PrincipalArn`), and cross-account resource-policy intersection, Bastion was the **only** tool to achieve **`100.0%` Accuracy (`24/24`, `1.000` F1, `0` FP, `0` FN)** — ahead of PMapper (`0.842` F1, `3` RCP FPs), Checkov (`0.516` F1, `15` FPs), Cloudsplaining (`0.381` F1), and Trivy (`0.000` F1).
- **Live AWS IAM Access Analyzer Blind Spot & OIDC Poisoning:** On live AWS, **AWS IAM Access Analyzer** produced **zero findings** on a 3-hop external-account path to an S3 bucket (Role → Role → Bucket), while Bastion proved the full 3-hop path end-to-end and also blocked wildcard GitHub Actions OIDC (`StringLike` `sub`) poisoning with a synthesized `StringEquals` guardrail that kept the trusted repository working.
- **Fortune-500 Scale & Adversarial Synthesis (`10,003,452` Nodes, `12.77M+` Edges):** Ingested `2,500` accounts under **`1.98 GB`** peak lean memory, resolved `20,001`-node hub queries in `0.017 ms`–`110.6 ms`, evaluated nested-wildcard 4-tier SCP torture policies in `0.12 ms`–`0.14 ms`, and blocked **`25 / 25`** simultaneous 8-hop exploit paths while retaining **`500 / 500` (`100%`)** benign actions in **`1.07 s`** — deterministic verification with **No AI, No API Keys, No Hallucinations**.

---

## 3. Why Existing Tools Stall Remediation

| Failure Mode of Alert-First Tools | Business Impact | Bastion Outcome |
| :--- | :--- | :--- |
| **Static alerts without safe placement** | Locking down a shared entry role breaks production workflows; tickets stall indefinitely in Jira | Automatically selects non-breaking placement across single chains and converging graphs (`0` broken workloads) |
| **Missed implicit downstream AWS calls** | Manual least-privilege scoping misses background service calls (e.g., Secrets Manager decrypting KMS keys), causing silent outages | Incorporates observed CloudTrail telemetry so both explicit and implicit dependencies stay intact |
| **Blind spots on complex AWS IAM semantics** | Scanners and simulators miss `PowerUserAccess`, `ForAllValues`, `${...}` variables, `sts:TagSession`, and resource-policy bypasses | Verified `100%` live AWS parity across subtle IAM, STS, S3, and SSM authorization behaviors |
| **Split-brain between IaC PRs and live drift** | PR scanners pass the diff; posture tools pass the live account; merging their union hands over admin | Evaluates proposed Terraform changes composed with the live account before merge |
| **Fragile guardrails** | Teams attach boundaries that can be bypassed via resource policies or tampered with by privileged roles | Seals resource-policy bypasses and hardens guardrails against tampering even under `AdministratorAccess` |

---

## 4. Three-Stage Enterprise Rollout

Bastion deploys incrementally with zero initial disruption:

1. **Read-Only Live Account Audit** — Connect read-only IAM and CloudTrail access to identify genuinely exploitable multi-hop paths and review zero-collateral remediation proposals without changing a single resource.
2. **Verified Non-Breaking Containment** — Apply minimal, self-defending guardrails verified to block live escalation while preserving observed production workflows.
3. **Standing Pre-Merge CI/CD Gate** — Run Bastion on every Terraform pull request composed with your live AWS state to stop split-brain escalations before merge.

---

## 5. Request the Full NDA Verification Package

To review live AWS control-plane demonstration videos, full technical verification evidence, or scope a read-only pilot in your AWS environment:

**Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com)

---

**Related:** [Public Overview](../README.md) · [Plain-English Enterprise Scenarios](../docs/EXECUTIVE_SCENARIOS.md) · [MITRE ATT&CK Coverage](../docs/MITRE_ATTACK_COVERAGE.md)
