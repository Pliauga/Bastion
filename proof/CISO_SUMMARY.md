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
