# Bastion

**Autonomous, Zero-Collateral AWS IAM Privilege Escalation Detection & Verified Remediation**

> **Closed-Source Commercial Software** — This repository is a public capability overview. Architecture documentation, live AWS execution recordings, and full verification dossiers are available to prospective enterprise buyers and security teams under NDA. **Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com).

Every cloud security scanner can hand your team ten thousand IAM alerts. Almost none can tell you which multi-hop paths are **genuinely exploitable on live AWS**, and none can hand engineering a minimal, production-safe fix proven not to break running workloads.

**Bastion closes the gap between finding an escalation chain and safely eliminating it.** It evaluates real AWS IAM authorization semantics across live cloud estates and pending Infrastructure-as-Code changes, proves which multi-step routes reach privileged targets, and generates targeted guardrails verified to block the escalation while keeping legitimate production traffic untouched.

**Quick links:** [Executive CISO Brief](./proof/CISO_SUMMARY.md) · [Plain-English Enterprise Scenarios](./docs/EXECUTIVE_SCENARIOS.md) · [MITRE ATT&CK Coverage](./docs/MITRE_ATTACK_COVERAGE.md)

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

## Independent Benchmarks & Enterprise Scale

In addition to live AWS control-plane verification, Bastion is validated against published third-party escalation corpora and large-scale synthetic cloud estates:

| Benchmark | Result |
| :--- | :--- |
| **Published 57-Path AWS IAM Escalation Suite** | **`57 / 57` (`100%`)** detected (`32 / 32` on the independent bias-free subset) |
| **Upstream Vulnerable IAM Benchmarks (`iam-vulnerable` / held-out `CloudGoat`)** | **`100%` recall** with **`0` false positives** across negative controls |
| **Enterprise-Scale Synthetic Organization (`10,000,000+` nodes)** | Sub-second typical chain analysis and containment synthesis at Fortune-500 scale |

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
