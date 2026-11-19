# Bastion: Four Scenarios for Security & Engineering Leaders

**Zero IAM jargon. Real live AWS outcomes.**

Each scenario follows four simple beats: **the problem, the exploit, the outcome, and the fix.** Every outcome reflects live AWS control-plane verification; detailed evidence and demonstration recordings are available under NDA via [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com).

---

## Scenario 1: The Clean Pull Request That Still Hands Over Admin

**The problem.** Your cloud team does everything by the book. A developer opens a Terraform pull request that wires up an ingest service and a worker role. Your pull-request security scanner checks the diff and turns green (`0` findings). Your cloud posture tool checks the live AWS account and reports `0` admin escalation paths. Everybody approves and merges.

**The exploit.** Months earlier, someone made a quick console edit ("click-ops drift") on a legacy operations admin role. On its own, nobody in the live account can reach it. On its own, the Terraform pull request has no admin role in it at all. The moment the pull request is merged, however, the **union** of the pull request and the pre-existing console edit snaps together into a live multi-step bridge straight to full administrator access.

**Why it is bad.** Every existing tool in your pipeline passed. Neither the pull request nor the live account looked dangerous in isolation — the compromise only exists where code and live drift meet. Worse, if a team tries to panic-lock the starting ingest identity after the fact, they break a legitimate shared workflow.

**The outcome.** On live AWS:
- Scanning the Terraform pull request alone passed with `0` findings, and auditing the live account alone showed `0` reachable paths.
- Evaluating the **combined state before merge**, Bastion caught the full multi-step escalation path, avoided the disruptive entry-identity cut that would have broken an active workflow, and generated a clean Terraform guardrail instead.
- **Before the fix**, the live multi-step attack succeeded every time (`HTTP 200`).
- **After applying Bastion's guardrail**, the admin hop failed every time (`HTTP 403 AccessDenied`) while **every legitimate production call kept succeeding (`HTTP 200`)** and the updated Terraform re-scanned clean.

**The fix.** Bastion catches split-brain drift paths inside the pull request *before* merge and produces a tailored, zero-collateral guardrail straight in Terraform so engineering can ship safely without breaking downstream jobs.

---

## Scenario 2: The Guardrail Everyone Trusted — Until Someone Walked Straight Around It

**The problem.** After an audit, your security team attaches an AWS Permissions Boundary to sensitive users and service roles — telling leadership the identities are "contained" because the boundary doesn't allow access to your crown-jewel S3 bucket. Everyone marks the ticket closed.

**The exploit.** Live AWS policy rules contain a surprise most teams never test: certain same-account resource-policy grants let a request **walk straight past a Permissions Boundary's default ceiling** and download the crown-jewel file (`HTTP 200`). Even worse, teams worry that if a role has broad permissions underneath a boundary, a clever attacker might delete the boundary, swap it for a weaker one, or create a fresh unrestricted role to escape.

**Why it is bad.** Your dashboard says "guardrail attached." In reality, the front door to the crown-jewel bucket is still unlocked — and any guardrail that cannot defend itself against tampering collapses the moment an attacker lands on a powerful identity.

**The outcome.** Verified live on AWS:
- Standard boundaries allowed open same-account resource-policy bypasses to download the crown-jewel object (`HTTP 200`).
- With Bastion's hardened containment in place, **every open bypass flipped from `HTTP 200` to `HTTP 403`** while legitimate reads remained **`HTTP 200`**.
- Under a live escape test with **full `AdministratorAccess` attached directly underneath Bastion's guardrail**, AWS refused every tampering and escape attempt — deleting the boundary, replacing it, editing it, creating unrestricted roles, and attaching admin policies — while still permitting legitimate scoped operations (`HTTP 200`).

**The fix.** Bastion does not treat "boundary attached" as good enough. It detects real resource-policy bypass interactions, seals open bypasses, and hardens guardrails against tampering and unrestricted identity minting.

---

## Scenario 3: The "Safe" Built-In Policy That Quietly Opens the Admin Door

**The problem.** Engineers need broad access to build services, so security grants AWS's built-in `PowerUserAccess` policy — reasoning that "PowerUser blocks IAM administration, so they can't escalate." Separately, a storage team locks down a sensitive bucket by denying everyone *except* named service accounts.

**The exploit.** Both assumptions fail on live AWS:
1. AWS's `PowerUserAccess` is written as an **allow-by-exclusion**: it grants almost everything *except* a short list of IAM actions. So while live AWS refuses `iam:CreateRole` (`403`), giving reviewers a false sense of safety, it **quietly allows `sts:AssumeRole` straight into an operations administrator role (`200`)**.
2. On the bucket lockdown, attaching a security guardrail to an exempted identity can trigger a `NotPrincipal` boundary trap that **silently breaks the legitimate storage workload (`403`)**.

**Why it is bad.** Scanners that misread exclusion policies miss live `PowerUserAccess` escalations completely — and teams that harden accounts without modeling boundary interactions risk taking down production storage jobs.

**The outcome.** Verified live on AWS:
- With AWS-managed `PowerUserAccess` attached, `iam:CreateRole` returned `403`, yet **`sts:AssumeRole` into an operations admin role succeeded (`HTTP 200`)**.
- After Bastion applied its tailored guardrail, **`sts:AssumeRole` flipped `200 -> 403` within seconds**, while all legitimate reads stayed **`HTTP 200`**.
- Bastion achieved **`100%` parity with live AWS** across exclusion policies, case-sensitivity edge cases, harmless deny-exclusion decoys (`0` false alarms), and boundary-safe bucket exemptions.

**The fix.** Bastion models exclusion and inversion policies with exact live AWS semantics — severing hidden `PowerUserAccess` and `NotAction` admin routes without breaking legitimate workloads or flagging safe guardrails.

---

## Scenario 4: Two Roads to Admin, One Outage Waiting to Happen

**The problem.** In a real cloud account, escalation paths rarely run in a neat single line. A shared entry role can branch into two different worker roles that both reach the same administrator role — one through a serverless compute carrier, the other by modifying role trust.

**The exploit.** An attacker landing on the entry role has two completely independent paths to full control. If security locks down the shared entry role, they break **multiple active production workflows**. If they only lock down Branch A, the attacker walks right up Branch B. If they slap one blanket restriction onto both branches, workloads break or inherit unnecessary access.

**Why it is bad.** This is the exact "remediation cliff" that paralyzes cloud security teams at scale: single-identity alerts can't coordinate a multi-role fix, and manual guesswork risks an outage across a busy account filled with innocent service roles and noisy decoys.

**The outcome.** Verified live across a populated multi-principal AWS account packed with hostile decoys and innocent service roles:
- **Before the fix**, both parallel branches escalated live to admin (`HTTP 200`/`201`).
- Bastion rejected the disruptive entry-role lockdown, closed **both parallel branches** with distinct per-branch guardrails applied through real Terraform workflows, flipped both live attack routes to **`HTTP 403`**, kept **`100%` of legitimate workload operations succeeding (`HTTP 200`/`201`)**, and re-audited the entire account to **`0` reachable admin paths** with **`0` false positives** on decoys or innocent fleet roles.

**The fix.** When an attack graph branches, Bastion coordinates least-privilege containment across multiple identities automatically — delivering tailored, non-breaking guardrails straight into Terraform.

---

## See Bastion Live Under NDA

Want to see the live AWS demonstration recordings or test Bastion read-only against your own cloud architecture?

**Contact:** [EdPliauga@gmail.com](mailto:EdPliauga@gmail.com)

---

**Related:** [Public Overview](../README.md) · [Executive CISO Brief](../proof/CISO_SUMMARY.md) · [MITRE ATT&CK Coverage](./MITRE_ATTACK_COVERAGE.md)
