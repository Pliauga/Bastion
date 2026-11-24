# Bastion — No AI, No API Keys, No Hallucinations

**Autonomous, Zero-Collateral AWS IAM Privilege Escalation Detection & Verified Remediation**

> **Closed-Source Commercial Software** — This repository is a public capability overview. Architecture documentation, live AWS execution recordings, and full verification dossiers are available to prospective enterprise buyers and security teams under NDA. **Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com).

Every cloud security scanner can hand your team ten thousand IAM alerts. Almost none can tell you which multi-hop paths are **genuinely exploitable on live AWS**, and none can hand engineering a minimal, production-safe fix proven not to break running workloads.

**Bastion closes the gap between finding an escalation chain and safely eliminating it.** It evaluates real AWS IAM authorization semantics across live cloud estates and pending Infrastructure-as-Code changes, proves which multi-step routes reach privileged targets, and generates targeted guardrails verified to block the escalation while keeping legitimate production traffic untouched.

**Quick links:** [Executive CISO Brief](./proof/CISO_SUMMARY.md) · [Plain-English Enterprise Scenarios](./docs/EXECUTIVE_SCENARIOS.md) · [MITRE ATT&CK Coverage](./docs/MITRE_ATTACK_COVERAGE.md) · [Benchmark JSON Teasers](./proof/benchmarks/)

---

## Live AWS & Enterprise-Scale Proof Highlights

| What Was Proven | Live AWS / Scale Result | Collateral Impact |
| :--- | :--- | :--- |
| **Prompt-Injected AI Coding Agents** | `4/4` rogue pivots (`200`) → **`8/8` blocked (`HTTP 403`)** | **`2/2` dev workflows `200` (`Δ = 0`)** |
| **Zero-Downtime Incident Response** | Compromised CI/CD role contained **in place** (`8/8` `403`, stolen token blocked) | **`59/59` live prod calls `200` (`0` downtime)** |
| **Third-Party SaaS Vendor Roles** | `8/8` vendor breach vectors `403` + wrong `ExternalId` rejected (`403`) | **`2/2` telemetry calls `200` (`Δ = 0`)** |
| **AWS IAM Access Analyzer Blind Spots** | Access Analyzer: **`0` findings** across `6` resources → Bastion: **`4/4` caught & closed** | **`100%` benign survival (`Δ = 0`)** |
| **Escape Test Under `AdministratorAccess`** | **`15/15` escape attempts `HTTP 403`** from one assumed session (`16/16` parity) | **`100%` benign reads `200` (`Δ = 0`)** |
| **Enterprise Scale & Decoy Precision** | `10,003,452` nodes (`1.98 GB`, `0.014 ms` hot SCP) · `1,000`-principal torture: **`50/50` recall in `0.061 s`** (`4.57 s` CI gate over `1,293` principals) | **`0 / 950` (`0.00%`) false positives** |

---

## Why Existing IAM Scanners Stall in Production

Alert-first posture tools and static IaC linters fail security teams in three predictable ways:

1. **False positives drown out real takeovers.** Grepping for sensitive actions or wildcards ignores conditions, trust policies, boundaries, and multi-hop reachability — flooding engineers with unexploitable noise.
2. **Real AWS semantics break naive models.** Standard scanners — and even AWS's own policy simulator — diverge from live AWS control-plane enforcement on exclusion policies, condition-operator edge cases, dynamic policy variables, session-tag smuggling, and resource-policy boundary bypasses.
3. **Locking down the wrong identity breaks production.** Remediation dies in Jira when security proposes a blanket restriction on a shared entry role without proving zero collateral impact across observed production workloads.

Bastion was engineered to solve all three — verified end-to-end against the live AWS control plane.

---

## Verified Capabilities

### 1. Live AWS Control-Plane Containment With Zero Broken Production Workflows
Bastion does not stop at static findings. Every remediation it produces is designed to sever the exact escalation path while preserving legitimate business operations:
- **End-to-end live enforcement:** Across live AWS validation scenarios covering serverless pipelines, transitive multi-hop role chains, multi-service compute carriers, converging multi-branch escalation graphs, and dynamic policy traps, every planted escalation succeeded live before remediation (`HTTP 200`/`201`) and was blocked live after Bastion's guardrail (`HTTP 403`) — with **`100%` of legitimate production workloads continuing uninterrupted (`HTTP 200`/`201`)**.
- **Repeatable, deterministic enforcement:** Repeated live apply-and-release cycles produced identical containment placement every time, enforcing live blocks within seconds (`~10–12s` typical IAM propagation).

### 2. Split-Brain Pre-Merge Detection (`Terraform PR + Live AWS Drift`)
A pull request can pass every IaC security scanner (`0` findings), and your live AWS account can pass every posture scanner (`0` paths) — yet merging the two creates a live multi-hop route straight to administrator access.
- **Hybrid composition before merge:** Bastion evaluates proposed Terraform changes together with the live AWS authorization graph, catching split-brain drift escalations *before* merge and generating non-breaking Terraform guardrails that resolve the path cleanly.

### 3. Multi-Branch & Multi-Hop Placement Without Collateral Damage
Real cloud graphs branch and converge. Locking down a shared entry identity breaks active workflows; locking down only one branch leaves an alternate route open.
- **Zero-collateral containment across complex graphs:** Bastion evaluates multi-hop chains and converging diamond graphs against observed production activity (including implicit downstream service calls captured from CloudTrail, such as Secrets Manager's implicit KMS decryption), automatically rejecting collateral-breaking cuts and placing tailored per-identity guardrails that close every route to admin with zero workload disruption.

### 4. Exact Live AWS Semantics Where Standard Scanners & Simulators Diverge
Bastion models the live AWS authorization engine across the subtle policy constructs that break conventional scanners:
- **Permissions-Boundary bypasses & self-defence:** Detects when same-account resource policies bypass standard Permissions Boundaries, seals open bypasses while keeping legitimate reads active, and hardens containment boundaries to withstand live escape and self-tampering attempts even with `AdministratorAccess` attached directly underneath.
- **Exclusion & inversion policies (`PowerUserAccess`, `NotAction`, `NotResource`, `NotPrincipal`):** Accurately identifies hidden escalation paths inside allow-by-exclusion policies like AWS-managed `PowerUserAccess`, stays silent on safe deny-exclusion guardrails, and catches boundary-breaking `NotPrincipal` traps before they cause outages.
- **Condition-operator & absent-key algebra:** Accurately evaluates vacuous quantifiers (`ForAllValues`), `IfExists` modifiers, negated `Deny` semantics, case-folded keys versus exact values, and multi-valued tag sets — achieving **`100%` parity** against live AWS control-plane probes.
- **Dynamic IAM policy variables (`${...}`):** Evaluates tag-driven resource interpolation, fallback defaults, live STS session-tag overrides, principal-type divergence (`${aws:username}`), policy version gating, and wildcard-injection resistance with **`100%` live AWS parity** — catching hidden variable escalations while staying silent on inert decoys.
- **ABAC & STS session-tag smuggling:** Detects self-satisfiable tag-poisoning chains and STS session-tag escalations where standard scanners and AWS's own `iam:SimulateCustomPolicy` disagree with live AWS STS — placing containment where AWS actually enforces it.
- **Multi-service `iam:PassRole` precision:** Distinguishes genuinely exploitable compute-carrier combinations from unexploitable misconfigurations — severing admin role passing while retaining `iam:PassRole` on benign execution roles for the exact same caller.

### 5. High-Precision Blind Account Audits
When dropped into an unfamiliar multi-principal account with zero path hints and hostile decoys alongside innocent fleet identities:
- **`100%` recall on planted multi-hop chains** with **`0` false positives** across hostile decoys and innocent service roles.

### 6. Coordinated Multi-Layer Containment & Adversarial Evasion Resilience
When a single guardrail layer leaves an alternate route open — such as a resource-policy bypass alongside an identity flaw and a federated trust trap — Bastion coordinates containment across **Permissions Boundaries, Trust Policies, and Resource Policies simultaneously**:
- **Coordinated 3-layer live enforcement:** Verified end-to-end on live AWS by closing identity escalation, trust-policy exposure, and a same-account session-ARN S3 resource-policy bypass in one unified remediation pass — blocking every attack path (`HTTP 403`) while keeping legitimate workloads running (`HTTP 200`, zero collateral breakage).
- **Adversarial evasion & decoy precision (`100%` Recall, `0` False Positives):** Catches obfuscated `Allow NotAction`, `NotResource` exclusions, tag-interpolated `${aws:PrincipalTag/...}` targets, and `iam:PassedToService` multi-service grants live on AWS (`HTTP 200`/`201` → `403`), while staying completely silent on matched inert decoys (safe `Deny NotAction` guardrails, mismatched `iam:PassedToService` preconditions, and identical variable policies bound to non-privileged tags).

### 7. Live Multi-Account AWS Organizations Governance & Pagination Scale
- **Live multi-account Organization verification (`SCP + RCP + Permissions Boundary + Resource Policy`):** Verified live across a Management and Member AWS Organization (`100%` recall, `0` false positives): recognized when an OU Service Control Policy already blocked an apparent IAM escalation (`HTTP 403`), closed cross-account `sts:AssumeRole` and session-ARN S3 resource-policy bypasses (`HTTP 200` → `403`) under coordinated four-layer enforcement, and kept both same-account and cross-account production reads intact (`HTTP 200`, zero collateral breakage).
- **End-to-end compiled container proof:** Verified with compiled, offline (`--network=none --read-only`, `linux/amd64` & `linux/arm64`) containers against a live Management + Member Organization combining `Allow NotAction`, `${aws:PrincipalTag/...}` variables, a split-brain Terraform PR plan, CloudTrail traffic preservation, and live boundary self-defense (`HTTP 403` on self-removal)—achieving **`100%` recall (`0` decoy false positives), `10/10` live AWS parity, and `100%` benign workload survival (`Δ Benign = 0`)** across both accounts.
- **Live `> 6,144`-character boundary compression (`8,867 → 586` chars):** Compressed an **`8,867`-character** policy surface down to **`586` characters**—accepted live by AWS well under the `6,144`-character managed-policy hard limit—while closing every escalation path (`HTTP 403`) and keeping legitimate workloads untouched (`HTTP 200`, `Δ Benign = 0`).
- **Multi-page estate scale & fail-closed telemetry:** Verified across multi-page (`126`-role) live AWS IAM estates with `100%` recall and `0` false positives across page boundaries, surfacing restricted read permissions explicitly rather than silently masking blind spots.
- **Federation, EKS Pod Identity & path-qualified principals:** Proved live AWS enforcement across OIDC trust hardening (`0` post-patch traps), EKS Pod Identity `sts:TagSession` + transitive `aws:RequestTag/*` validation (`HTTP 200` valid tags vs. `403` spoofed/untagged), and multi-segment IAM role paths (`aws:PrincipalArn`) where pathless patterns silently miss.
- **KMS anti-lockout & shadow non-role vectors:** Synthesized KMS key-policy guardrails accepted live by AWS with `BypassPolicyLockoutSafetyCheck=False` (where naive lockouts fail `MalformedPolicyDocumentException`), and verified live containment (`HTTP 200` → `403`, `Δ Benign = 0`) across `iam:SetDefaultPolicyVersion` policy rollback, `iam:AddUserToGroup`, `iam:CreateAccessKey`, `iam:DeleteUserPermissionsBoundary`, `PassRole`-free `lambda:UpdateFunctionCode` solo hijack, and live 4-hop role-chaining severance (`6`-hop AWS chaining ceiling).
- **Side-by-side AWS IAM Access Analyzer blind-spot showdown:** On live AWS across four real attack classes (same-account multi-hop chain, dormant `SetDefaultPolicyVersion` rollback, `${aws:PrincipalTag/...}` variable escalation, and session-ARN S3 boundary bypass), **AWS IAM Access Analyzer reported `0` findings across `6` scanned resources**, while **Bastion caught `4/4` (`0` decoy false positives)** and closed every path live (`HTTP 200` → `403`, `Δ Benign = 0`).

- **Bounded `AdministratorAccess` `15`-vector escape test:** With **`AdministratorAccess` attached directly to a live AWS role** capped by a Bastion guardrail, **`15/15` live escape attempts** (`DeleteRolePermissionsBoundary`, `PutRolePermissionsBoundary`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, unbounded/bypassing `CreateRole`/`CreateUser`, `PutRolePolicy`, `AttachRolePolicy`, `UpdateAssumeRolePolicy`, `CreateAccessKey`, `AddUserToGroup`, `AssumeRole`, `PassRole` via `lambda:CreateFunction`, and protected S3 read) all bounced at **`HTTP 403`** from one assumed session (`16/16` live AWS parity) while legitimate reads stayed **`HTTP 200` (`Δ Benign = 0`)**.

### 8. Live Operational Containment: AI Agents, Zero-Downtime IR & Third-Party Vendors
- **Prompt-injected AI coding-agent containment (live AWS):** Provisioned an over-privileged AI agent role (`Allow NotAction` developer authority excluding only `organizations:*` / `account:*`) where **`4/4` prompt-injected rogue actions succeeded (`HTTP 200`)**, including `sts:AssumeRole` into a production administrator role and reading a protected production S3 object; Bastion ingested the live account, synthesized a **5-statement** guardrail, and blocked **`8/8` rogue escalation and persistence vectors (`HTTP 403`)**—including `iam:CreateRole`, `iam:DeleteRolePermissionsBoundary`, `lambda:CreateFunction`, `iam:PutRolePolicy`, `iam:CreateAccessKey`, `s3:PutBucketPolicy`, `sts:AssumeRole`, and production S3 read—while keeping **`2/2` legitimate developer S3 workflows at `HTTP 200` (`Δ Benign = 0`, `10/10` live AWS parity, `0` leaked resources)**.
- **Zero-downtime incident-response containment (live AWS):** Provisioned a live compromised CI/CD release-runner role (`Allow NotAction`) with a continuous `1.0s` production S3 heartbeat (`59` calls across pre-containment, in-place guardrail attachment, and post-containment) using the runner's **original** session (`0` credential rotation or role deletion); **`4/4` attacker moves succeeded pre-containment (`HTTP 200`)**, Bastion attached its synthesized **6-statement** guardrail **in place** with **`0` downtime errors across all `59` production calls**, neutralized the already-issued stolen session, blocked **`8/8` attacker vectors (`HTTP 403`)**, and kept **`3/3` legitimate CI/CD operations at `HTTP 200` (`Δ Benign = 0`, `11/11` live AWS parity, `0` leaked resources)**.
- **Third-party SaaS / vendor integration containment (live AWS):** Provisioned an over-privileged SaaS vendor role (`Allow NotAction` + `sts:ExternalId` trust) where **`4/4` pre-containment pivots succeeded (`HTTP 200`)**, including assuming an organization administrator role and reading customer PII; Bastion attached its synthesized **5-statement** guardrail **in place** (`no revocation`, `no rotation`), confirmed confused-deputy rejection (`wrong ExternalId` → `HTTP 403`), blocked **`8/8` vendor breach vectors (`HTTP 403`)**, and kept **`2/2` legitimate telemetry S3 calls at `HTTP 200` (`Δ Benign = 0`, `10/10` live AWS parity, `0` leaked resources)**.

---

## Sanitized Live AWS Control-Plane Excerpts

Every refusal below is an anonymized excerpt from live AWS control-plane verification after Bastion's guardrail took effect (account IDs, resource names, and authorization tokens sanitized):

**Serverless pipeline escalation contained while live Lambda & DynamoDB production writes continue (`HTTP 200`):**
```text
AccessDeniedException (HTTP 403)
User: arn:aws:sts::123456789012:assumed-role/pipeline-role/session is not authorized to perform:
lambda:UpdateFunctionCode on resource: arn:aws:lambda:us-east-1:123456789012:function:data-processor
because no permissions boundary allows the lambda:UpdateFunctionCode action
```

**Same-account resource-policy boundary bypass sealed live while legitimate reads stay `HTTP 200`:**
```text
AccessDenied (HTTP 403)
User: arn:aws:sts::123456789012:assumed-role/app-worker-role/session is not authorized to perform:
s3:GetObject on resource: "arn:aws:s3:::crown-data-bucket/crown.txt"
with an explicit deny in a permissions boundary: arn:aws:iam::123456789012:policy/bastion-guardrail
```

**Live self-defence under `AdministratorAccess` — boundary deletion and unrestricted role minting refused:**
```text
AccessDenied (HTTP 403)
User: arn:aws:sts::123456789012:assumed-role/bounded-admin-role/session is not authorized to perform:
iam:DeleteRolePermissionsBoundary on resource: role bounded-admin-role
with an explicit deny in a permissions boundary: arn:aws:iam::123456789012:policy/bastion-guardrail
```

**Dynamic `${...}` policy-variable admin escalation severed live while benign reads stay `HTTP 200`:**
```text
AccessDenied (HTTP 403)
User: arn:aws:sts::123456789012:assumed-role/tagged-worker-role/session is not authorized to perform:
sts:AssumeRole on resource: arn:aws:iam::123456789012:role/ops-admin
```

---

## Head-to-Head Scanner Comparison (36-Scenario AWS IAM Semantics Suite)

We evaluated Bastion side-by-side against five widely deployed open-source cloud IAM & Infrastructure-as-Code scanners on a balanced **36-scenario live-AWS-grounded benchmark** (`18` genuine multi-hop & semantic privilege escalations paired with `18` unexploitable look-alike decoys across `9` AWS IAM authorization domains). All scanners were scored strictly on findings targeting candidate principals/policies (excluding sink admin roles and generic password-policy/hygiene warnings):

| Tool | Version | TP | FP | FN | TN | Precision | Recall | F1 Score | Verified Fix Synthesis |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Bastion** | Commercial | **`18`** | **`0`** | **`0`** | **`18`** | **`100.0%`** | **`100.0%`** | **`1.000`** | **Yes (Zero-Collateral)** |
| Principal Mapper (`pmapper`) | `1.1.5` | `15` | `3` | `3` | `15` | `83.3%` | `83.3%` | `0.833` | No (`0`) |
| Checkov | `3.3.30` | `4` | `7` | `14` | `11` | `36.4%` | `22.2%` | `0.276` | No (`0`) |
| Trivy | `0.76.0` | `2` | `1` | `16` | `17` | `66.7%` | `11.1%` | `0.190` | No (`0`) |
| Prowler IaC | `5.48.0` | `2` | `1` | `16` | `17` | `66.7%` | `11.1%` | `0.190` | No (`0`) |
| Cloudsplaining | `0.9.1` | `2` | `2` | `16` | `16` | `50.0%` | `11.1%` | `0.182` | No (`0`) |

- **IaC linters & static parsers** missed **`78%–89%`** of real multi-hop, scoped, and conditional escalations while flooding teams with false alarms on bounded roles and deny-exclusion guardrails.
- **Even the strongest open-source graph tool (`pmapper`)** missed multi-hop version rewrites, policy-variable expansions, and ABAC preconditions while firing false positives on boundary-capped and inert policy constructs.
- **Bastion** achieved **`100.0%` Precision (`0` false positives) and `100.0%` Recall (`0` misses)** — **`+0.167` F1 over `pmapper`** and **`+0.724` to `+0.818` F1 over Checkov, Trivy, Prowler IaC, and Cloudsplaining** — while uniquely synthesizing verified non-breaking remediations.

---

## Datadog `pathfinding.cloud` Catalog Coverage (92 Modern AWS Escalation Paths)

We also evaluated all **5 scanners** across **`92` modern multi-service AWS privilege-escalation paths** from Datadog's `pathfinding.cloud` catalog — spanning IAM/STS (`22` Tier 1 paths), mainstream compute carriers (`37` Tier 2 paths across EC2, ECS, Lambda, Glue, SageMaker, CodeBuild, SSM, RDS, DataPipeline), and modern/long-tail AWS services (`33` Tier 3 paths across Bedrock, AppRunner, Batch, CloudFormation, Step Functions, EMR, Cognito, Omics, Scheduler):

| Tool | Version | Tier 1 (IAM / STS, `22`) | Tier 2 (Compute, `37`) | Tier 3 (Modern Services, `33`) | Total (`92` Paths) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Bastion** | Commercial | **`22 / 22` (`100%`)** | **`37 / 37` (`100%`)** | **`33 / 33` (`100%`)** | **`92 / 92` (`100%`)** |
| Cloudsplaining | `0.9.1` | `21 / 22` (`95.5%`) | `29 / 37` (`78.4%`) | `10 / 33` (`30.3%`) | `60 / 92` (`65.2%`) |
| Principal Mapper (`pmapper`) | `1.1.5` | `15 / 22` (`68.2%`) | `9 / 37` (`24.3%`) | `3 / 33` (`9.1%`) | `27 / 92` (`29.3%`) |
| Checkov *(PE rule `CKV_AWS_286`)* | `3.3.30` | `16 / 22` (`72.7%`) | `8 / 37` (`21.6%`) | `2 / 33` (`6.1%`) | `26 / 92` (`28.3%`) |
| Trivy | `0.76.0` | `3 / 22` (`13.6%`) | `0 / 37` (`0.0%`) | `0 / 33` (`0.0%`) | `3 / 92` (`3.3%`) |

Bastion achieved **`100%` (`92 / 92`)** coverage across every IAM, STS, mainstream compute, and modern AWS service escalation path — outperforming Cloudsplaining by **`+34.8` points**, PMapper by **`+70.7` points**, Checkov's privilege-escalation rule by **`+71.7` points**, and Trivy by **`+96.7` points**.

---

## Zero-Collateral Remediation on `AWSGoat` & `TerraGoat`

Alerting on IAM risk is half the problem — the real question for engineering and security leadership is *who can eliminate an escalation path without breaking running workloads?* We ran Bastion alongside the same open-source scanners against **INE's `AWSGoat` (`module-2`)** (an already-bounded ECS role escalating via `iam:PassRole` + `ec2:RunInstances` into an admin deployer role alongside active production traffic) and **Bridgecrew's `TerraGoat`** (broad service wildcards with zero IAM/STS escalation paths):

| Tool | `AWSGoat` Escalation Caught | `AWSGoat` Verified Non-Breaking Fix | `AWSGoat` Production Traffic Intact | `TerraGoat` False Escalation Alarms |
| :--- | :---: | :---: | :---: | :---: |
| **Bastion** | **Yes** *(full path)* | **Yes** *(re-scan clean)* | **`100%` (`3/3` workload calls)** | **`0`** |
| Principal Mapper (`pmapper`) | Partial *(role-pair only)* | **No (`0`)** | `N/A` | `0` |
| Checkov (`CKV_AWS_286`) | Static policy flags only | **No (`0`)** | `N/A` | **`1` false alarm** |
| Cloudsplaining | Static policy flags *(flagged boundary)* | **No (`0`)** | `N/A` | **`2` false alarms** |
| Trivy | **No** *(missed admin escalation)* | **No (`0`)** | `N/A` | `N/A` |

Bastion is the **only** evaluated tool that identified the exact `AWSGoat` escalation path, generated a verified guardrail that closed the exploit on re-scan (`0` remaining paths), preserved **`100%` (`3/3`)** of observed ECS/SSM/EC2 production calls, and stayed silent (**`0` false alarms**) on `TerraGoat`'s non-escalating service policies.

---

## Independent Benchmarks & Enterprise Scale

In addition to live AWS control-plane verification, Bastion is validated against published third-party escalation corpora and large-scale synthetic cloud estates:

| Benchmark | Result |
| :--- | :--- |
| **Published 57-Path AWS IAM Escalation Suite** | **`57 / 57` (`100%`)** detected (`32 / 32` on the independent bias-free subset) |
| **Upstream Vulnerable IAM Benchmarks (`iam-vulnerable` / held-out `CloudGoat`)** | **`100%` recall** with **`0` false positives** across negative controls |
| **Enterprise-Scale Synthetic Organization (`10,003,452` nodes / `12.77M+` edges across `2,500` accounts)** | Ingested in `66.0 s` under **`1.98 GB`** peak lean memory (`6.28 GB` with full policy documents); `20,001`-node hub queries in **`0.017 ms`–`110.6 ms`** |
| **Adversarial Policy & Guardrail Synthesis Stress Test** | **`0.014 ms` hot / `0.041 ms` cold** single-decision latency on nested-wildcard 4-tier SCPs (`8.8×` faster); blocked **`25 / 25`** simultaneous 8-hop exploit paths while retaining **`500 / 500` (`100%`)** benign actions in **`0.97 s`** |
| **`1,000`-Principal Adversarial Decoy Torture (`50` buried chains + `950` hostile look-alikes)** | **`50 / 50` (`100%`)** recall (`2–6` hops, `Allow NotAction`, `${aws:PrincipalTag/...}`, `PassRole`, boundary removal), **`0 / 950` (`0.00%`)** false positives across `8` trap classes, **`50 / 50`** boundaries synthesized with **`50 / 50`** benign grants intact, **`0.061 s` (`61 ms`) sweep** (`13,194×` vs baseline), and **`4.57 s` CI gate** across `1,293` principals (`103×` vs baseline) |

**Sanitized Benchmark JSON Teasers:** [`57-path-scanner-matrix.json`](./proof/benchmarks/57-path-scanner-matrix.json) · [`57-path-bastion-comparison.json`](./proof/benchmarks/57-path-bastion-comparison.json) · [`iam-vulnerable-cloudgoat-comparison.json`](./proof/benchmarks/iam-vulnerable-cloudgoat-comparison.json) · [`10m-node-scale-stress.json`](./proof/benchmarks/10m-node-scale-stress.json) · [`10m-node-memory-profile.json`](./proof/benchmarks/10m-node-memory-profile.json) · [`1000-principal-decoy-torture.json`](./proof/benchmarks/1000-principal-decoy-torture.json)

*Detailed benchmark breakdowns, live video recordings, and side-by-side tool evaluations are provided to qualified buyers under NDA.*

---

## CI/CD & Enterprise Rollout

Bastion fits directly into existing cloud security and platform engineering workflows with zero initial disruption:

1. **Stage 1 — Read-Only Discovery & Risk Proof:** Connect read-only IAM and CloudTrail telemetry to surface verified, genuinely exploitable multi-hop paths alongside zero-collateral remediation proposals — modifying zero cloud resources.
2. **Stage 2 — Verified Non-Breaking Containment:** Roll out minimal, self-defending guardrails across high-risk identities and converging paths, validated against observed production traffic.
3. **Stage 3 — Standing Pre-Merge Hybrid Gate:** Integrate Bastion into Terraform pull requests (with native SARIF output for GitHub Code Scanning) to block split-brain `PR + Live Drift` escalations before merge.

---

## MITRE ATT&CK Alignment

Bastion maps its policy-evaluated authorization proofs directly onto the MITRE ATT&CK Cloud (IaaS) matrix (`T1098.001`, `T1098.003`, `T1548.005`, `T1078.004`, `T1190`). See [MITRE ATT&CK Coverage](./docs/MITRE_ATTACK_COVERAGE.md).

---

## Request an NDA Walkthrough & Live Demo

Bastion is closed-source commercial software. For enterprise buyers, CISOs, and cloud security leaders interested in:
- **Live AWS control-plane demonstration videos** and full technical verification dossiers
- **Architecture & security review** under mutual NDA
- **Read-only pilot evaluation** in a staging or production AWS environment

**Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com)
