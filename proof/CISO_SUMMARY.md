# Executive Brief — Bastion for Cloud Security Leadership

> **Closed-Source Commercial Software** — Full technical verification dossiers, live AWS & GCP demonstration recordings, and pilot scoping are available under NDA. **Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com).

## 1. The Problem in One Sentence

IAM privilege escalation is a multi-hop authorization reachability problem, yet standard cloud scanners stop at noisy static alerts instead of delivering a minimal remediation that is **proven to block the attack on live AWS and GCP** and **proven not to break production**.

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
  - Live KMS anti-lockout (`BypassPolicyLockoutSafetyCheck=False`), EKS Pod Identity `sts:TagSession` + transitive tags, multi-segment path-qualified `aws:PrincipalArn`, `iam:SetDefaultPolicyVersion` rollback, `PassRole`-free `lambda:UpdateFunctionCode` solo hijack, and 4-hop role-chaining severance (`HTTP 200` → `403`, `Δ Benign = 0`)
- **Head-to-Head Scanner Accuracy:** In a balanced `36`-scenario evaluation (`18` genuine escalations, `18` unexploitable decoys across `9` IAM domains), Bastion achieved **`100.0%` Precision, `100.0%` Recall (`1.000` F1)** — compared to **`0.833` F1** for Principal Mapper (`1.1.5`), **`0.276` F1** for Checkov (`3.3.30`), **`0.190` F1** for Trivy (`0.76.0`) and Prowler IaC (`5.48.0`), and **`0.182` F1** for Cloudsplaining (`0.9.1`).
- **Datadog `pathfinding.cloud` & Expanded Multi-Service Coverage (`92` Paths + `9` Live Data/AI/CI Carriers):** Bastion detected **`92 / 92` (`100%`)** overall — covering **`100%`** across all IAM, STS, mainstream compute-carrier, and modern AWS service paths — vs. **`60 / 92` (`65.2%`)** for Cloudsplaining, **`27 / 92` (`29.3%`)** for PMapper, **`26 / 92` (`28.3%`)** for Checkov (`CKV_AWS_286`), and **`3 / 92` (`3.3%`)** for Trivy — and enforces exact resource-policy & carrier reachability across **Secrets Manager, SQS, SNS, ECR, Lambda, CodeBuild, Step Functions, SageMaker, and EventBridge Scheduler** (`20/20` true paths, `0/16` decoy false positives).
- **Zero-Collateral Remediation (`AWSGoat` & `TerraGoat`):** On INE's `AWSGoat` (`module-2`), Bastion was the **only** tool to catch the full escalation path and synthesize a verified guardrail closing the exploit with **`100%` (`3/3`)** production workload calls intact (competitors produced `0` fixes), while reporting **`0` false escalation alarms** on Bridgecrew's `TerraGoat` (where Checkov and Cloudsplaining both false-alarmed).
- **Multi-Account Organizations (SCP + RCP + Cross-Account Trust) Parity (`24` Scenarios):** Across AWS Organizations SCPs, Resource Control Policies (RCPs), cross-account trust conditions (`aws:PrincipalOrgID`, `sts:ExternalId`, `aws:PrincipalArn`), and cross-account resource-policy intersection, Bastion was the **only** tool to achieve **`100.0%` Accuracy (`24/24`, `1.000` F1, `0` FP, `0` FN)** — ahead of PMapper (`0.842` F1, `3` RCP FPs), Checkov (`0.516` F1, `15` FPs), Cloudsplaining (`0.381` F1), and Trivy (`0.000` F1).
- **Live AWS IAM Access Analyzer Blind Spots & OIDC Poisoning:** On live AWS, **AWS IAM Access Analyzer** produced **zero findings** both on a 3-hop external-account path to an S3 bucket (Role → Role → Bucket) and across **`6` scanned resources** covering four real attack vectors (same-account multi-hop, dormant policy-version rollback, `${aws:PrincipalTag/...}` interpolation, and session-ARN S3 boundary bypass)—while **Bastion caught `4/4` (`0` decoy false positives)**, closed all four live (`HTTP 200` → `403`, `Δ Benign = 0`), and hardened wildcard GitHub Actions OIDC (`StringLike` `sub`) poisoning while keeping the trusted repository working.
- **`15`-Vector Escape Test Under `AdministratorAccess`:** With **`AdministratorAccess` attached directly to a live AWS role** capped by a Bastion boundary, **`15/15` escape attempts** (boundary deletion/replacement, policy-version overwrites, unbounded `CreateRole`/`CreateUser`, inline/managed policy writes, trust hijack, credential minting, `PassRole`, `AssumeRole`, and protected S3 access) returned **`HTTP 403`** (`16/16` live AWS parity) while legitimate reads remained **`HTTP 200` (`Δ Benign = 0`)**.
- **Prompt-Injected AI Agent Containment (Live AWS):** Proved deterministic, zero-AI guardrails against a live over-privileged AI coding-agent role (`Allow NotAction` developer authority): **`4/4` prompt-injected rogue actions initially succeeded (`HTTP 200`)**, including `sts:AssumeRole` into a production administrator role and reading protected production S3 data; after attaching Bastion's synthesized 5-statement guardrail, **`8/8` rogue escalation and persistence vectors flipped to `HTTP 403`** while **`2/2` legitimate developer S3 workflows stayed `HTTP 200` (`Δ Benign = 0`, `10/10` live AWS parity)**.
- **Zero-Downtime Incident-Response Containment (Live AWS):** Contained a live compromised CI/CD release-runner role **in place** (no role deletion, no credential rotation) while a continuous `1.0s` production S3 heartbeat ran on the original session: **`59/59` production calls stayed `HTTP 200` (`0` downtime errors)** across pre-containment, attachment, and post-containment, the already-issued stolen session was blocked from escalating, **`8/8` attacker persistence and escalation vectors flipped from `HTTP 200` to `403`**, and **`3/3` CI/CD operations stayed `HTTP 200` (`Δ Benign = 0`, `11/11` live AWS parity)**.
- **Third-Party SaaS / Vendor Integration Containment (Live AWS):** Scoped an over-privileged third-party SaaS vendor role (`Allow NotAction` + `sts:ExternalId` trust) **in place** after proving `4/4` pre-containment pivots (`HTTP 200`, including organization admin assumption and customer PII S3 read): **`8/8` vendor breach vectors flipped to `HTTP 403`**, confused-deputy access with a mismatched `ExternalId` was blocked (`403`), and **`2/2` legitimate vendor telemetry calls stayed `HTTP 200` (`Δ Benign = 0`, `10/10` live AWS parity)**.
- **Live Multi-Account AWS Organizations Enforcement (`SCP + RCP + PB + Resource Policy`):** Verified end-to-end across a live Management + Member Organization (`100%` recall, `0` decoy false positives, `100%` live AWS parity): closed cross-account role assumptions, obfuscated `NotAction` / `${aws:PrincipalTag/...}` evasions, split-brain Terraform PR escalations, and session-ARN S3/SQS resource-policy bypasses (`HTTP 200` → `403`, plus **`22/22` live parity** across `iam`, `sts`, `s3`, `lambda`, `sqs`, `sns`, and `ecr`, and **`16/16` live RBP/carrier arms PASS / `15/15` parity** across **33** AWS services and **17** policy/resource-policy synthesis types) using compiled `--network=none --read-only` containers (`linux/amd64` & `linux/arm64`) with live `> 6,144`-character boundary compression (`8,867 → 586` chars, and **`13,531 → 5,580` chars across `74` multi-service grants in `13.1 ms`** with zero `s3:*`/`kms:*` widening and explicit-deny blocking of counterfeit `iam:CreatePolicy` boundary minting) and boundary self-defense (`403`)—while keeping both same-account and cross-account workloads running (`HTTP 200`, `0` collateral breakage), and validated across multi-page (`126`-role) live IAM estates. Moreover, when an Organization **RCP** blocked `sqs:ReceiveMessage` and `s3:GetObject` (`403`) while **structurally exempting `lambda:InvokeFunction` (`200`)** (AWS rejects `lambda:InvokeFunction` in RCPs), Bastion detected the gap and plugged it in-place via the caller's permissions boundary (`200 → 403`, `Δ Benign = 0`, `10/10` parity).
- **Three-Round Adversarial Red-Team Hardening (`55/55` Closed, `11/11` Live AWS Wire Parity):** Validated across three consecutive independent adversarial red-team audits (**`0 CRITICAL / 0 HIGH / 0 MEDIUM`** remaining, `930` unit tests passing), proving live on AWS (`11/11` parity, `0` leaked resources) that caller-supplied `aws:RequestTag` mint forgery, case-folded `aws:TagKeys` bypasses across `iam:TagRole`/`UntagRole` and live `sts:AssumeRole` session-tag hops, wildcard principal shapes, and cross-bucket/cross-key compression widening are blocked while benign workloads remain **`HTTP 200`**.
- **Fortune-500 Scale & Adversarial Synthesis (`10,003,452` Nodes, `12.77M+` Edges):** Ingested `2,500` accounts under **`1.98 GB`** peak lean memory, resolved `20,001`-node hub queries in `0.017 ms`–`110.6 ms`, evaluated nested-wildcard 4-tier SCP torture policies in **`0.014 ms` hot / `0.041 ms` cold**, blocked **`25 / 25`** simultaneous 8-hop exploit paths while retaining **`500 / 500` (`100%`)** benign actions in **`0.97 s`**, and swept a `1,000`-principal SCP-heavy adversarial decoy torture in **`0.068 s`** (`5.09 s` CI gate over `1,293` principals) with **`50 / 50` (`100%`)** recall, **`0 / 950` (`0.00%`)** false positives, and **`50 / 50`** benign-preserving fixes — deterministic verification with **No AI, No API Keys, No Hallucinations**.

---

## 2b. Verified Live GCP Capabilities

Bastion extends the same deterministic, zero-collateral verification engine to **Google Cloud Platform (GCP)** across `Organization -> Folder -> Project -> Resource` hierarchies and **6 remediation layers** (`IAM Deny v2`, `Allow Policy Narrowing`, `IAM Conditions / CEL`, `Organization Policy Guardrails`, `Principal Access Boundary (PAB)`, and `Custom Role Least-Privilege`):

- **Live GCP `GAUNTLET-100` Scaled Proof (`0` Leaked Resources):** Validated live on GCP across 4-hop diamond service-account delegation/key-admin chains, live **Cloud Run v2** carrier takeover (`HTTP 200`), Workload Identity Federation (`principalSet://.../attribute.env/prod` vs `dev`), ABAC tag-mutation detection, `denyAdmin` policy-mutation detection, and `apikeys.keys.create`/`storage.hmacKeys.create` — closing **`77/77` gauntlet paths (`0` residual, `quotas_ok=True`)**, blocking live key creation and Cloud Run `PATCH` at **`HTTP 403 PERMISSION_DENIED`**, and preserving **`100%` of benign GCS, Cloud KMS, Secret Manager, and Cloud Run `GET` calls (`HTTP 200`, `Δ Benign = 0`)**.
- **12 GCP Workload Carriers & Exact Semantic Modeling:** Separates inert `iam.serviceAccounts.actAs` bindings from executable multi-hop privilege-escalation chains across `12` GCP compute, serverless, workflow, data, and ML services with **`10/10` corpus parity**, **`36/36` clean E2E syntheses**, **`574` passing unit tests**, three-valued CEL evaluation, fail-closed PAB scope checks, `LockoutGuard` anti-lockout protection for break-glass admins and Google-managed service agents, and a **Pre-Merge Split-Brain CI/CD Gate** (`Terraform PR + Live GCP Drift`) with **SARIF 2.1.0** output.
- **External GCP Benchmarks & Scale:** Blocked **`4/4`** measured live **Datadog Stratus Red Team** GCP IAM/persistence TTPs (`HTTP 403`, `0` leaked resources; `1` TTP unmeasured due to an upstream Terraform provider warmup failure), scored **`100%` (`11/11` deployed in-scope routes; `2` undeployed preconditions skipped)** with **`0` false positives** and `0` leaked resources on **BugBase Cloud Attack Range (GCP)**, validated **`1,000,000` hierarchy nodes / `10,046,557` edges** (`14.00 s` escalation sweep, `5.51 GiB` peak RSS, **`10/10` messy-GCP edge cases** including `deleted:` principals and Org Policy v2 `dryRunSpec`/`reset`/`inheritFromParent`), and closed `50` paths across a **`100`-SA / `1,000`-binding** offline scale gate in **`1.98 s`** (`0` residual, `0` broken benign).

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
3. **Standing Pre-Merge CI/CD Gate** — Run Bastion on every Terraform pull request composed with your live AWS or GCP state to stop split-brain escalations before merge.

- **Zero-Privilege Read-Only Onboarding:** Copy-paste `gcloud` and Terraform templates scoped strictly to read-only viewer roles—no admin or write credentials required for Stage 1 diagnostics.
- **Air-Gapped Offline Snapshot Mode (`--network=none`):** Ingests offline `gcloud asset export` snapshots (NDJSON/JSON) alongside Terraform plans with zero live cloud API credentials or outbound network access.
- **Paired Rollback Commands on Every Fix:** Every generated guardrail includes ready-to-run CLI and Terraform revert commands for one-step rollback during rollout.

---

## 5. Request the Full NDA Verification Package

To review live AWS & GCP control-plane demonstration videos, full technical verification evidence, or scope a read-only pilot in your cloud environment:

**Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com)

---

**Related:** [Public Overview](../README.md) · [Plain-English Enterprise Scenarios](../docs/EXECUTIVE_SCENARIOS.md) · [MITRE ATT&CK Coverage](../docs/MITRE_ATTACK_COVERAGE.md)
