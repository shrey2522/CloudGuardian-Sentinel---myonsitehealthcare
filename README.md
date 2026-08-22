# CloudGuardian Sentinel

**Real-time security monitoring and automated remediation for Infrastructure-as-Code and cloud resources across AWS and GCP.**

[![security gate](https://github.com/shrey2522/CloudGuardian-Sentinel---myonsitehealthcare/actions/workflows/sentinel-gate.yml/badge.svg)](https://github.com/shrey2522/CloudGuardian-Sentinel---myonsitehealthcare/actions/workflows/sentinel-gate.yml)

Built for a 6-hour hackathon. Everything below runs against **real AWS and GCP
accounts** — no mocks, no emulators.

---

## The problem

Cloud teams deploy infrastructure from Terraform templates every day, and a
single misconfigured line — a security group open to `0.0.0.0/0`, a database
flagged `publicly_accessible = true`, a public storage bucket — becomes a
live vulnerability that nobody notices until an audit or a breach. By then
it has been deployed for weeks. Teams need detection **at the moment of
change**, remediation that doesn't wait for a human, an audit trail for
compliance, and a CI/CD gate that refuses to ship while known risks are open.

## What Sentinel does

| Capability | How Sentinel delivers it |
|---|---|
| Continuous monitoring | Polls AWS + GCP resource state every 30s (concurrent provider checks) |
| Detection via configurable rules | YAML rule engine — severities, ports and thresholds are configuration, not code |
| Automated remediation | Flips the risky Terraform variable and runs `terraform apply` — idempotent, verified by re-scan |
| Reversibility | Every remediation snapshots prior state; `sentinel rollback` restores it in one command |
| Audit trail | Append-only JSONL (fsync) + SQLite; every event has a UTC timestamp and actor identity |
| CI/CD enforcement | `ci-scan` gate blocks deployments while actionable findings are open — proven live on GitHub Actions (red run → auto-remediation → green run) |
| Multi-cloud | AWS (security groups, RDS, S3) and GCP (firewalls, GCS) — found real misconfigurations in a brand-new GCP project's default network |
| Visibility | Control-center dashboard: risk heatmap, live findings, audit feed, and buttons that run the whole workflow |

### Detection rules shipped (8, all in YAML)

- `AWS-SG-SSH-OPEN` — security group exposes SSH/RDP to the internet (CRITICAL, auto-fix)
- `AWS-SG-DB-PORTS-OPEN` — security group exposes database ports 3306/5432/27017/… (CRITICAL, auto-fix)
- `AWS-RDS-PUBLIC` — RDS instance publicly accessible (CRITICAL, auto-fix)
- `AWS-S3-PUBLIC-READ` — S3 bucket publicly readable (CRITICAL, auto-fix)
- `AWS-RDS-UNENCRYPTED` — RDS storage unencrypted at rest (HIGH — requires instance rebuild, flagged for manual action)
- `AWS-S3-NO-ENCRYPTION` — S3 bucket without server-side encryption (fires on legacy buckets; AWS enables SSE by default since 2023)
- `GCP-FW-SSH-OPEN` — firewall rule allows SSH/RDP from `0.0.0.0/0` (CRITICAL)
- `GCP-GCS-PUBLIC` — GCS bucket readable by `allUsers` (HIGH)

## Architecture

```
              ┌───────────────────────────────────────────────────────┐
              │                Sentinel service (Python)              │
              │                                                       │
              │   Providers (concurrent)        Rule engine (YAML)    │
              │   ├─ AWS  (boto3: EC2/RDS/S3)   └─ 8 rules, no code   │
              │   └─ GCP (REST: Compute/GCS)         changes needed   │
              │              │                                        │
              │              ▼                                        │
              │        Findings store          Remediation engine     │
              │        (fingerprinted,          `terraform apply`     │
              │         regression-aware)       + rollback snapshots  │
              │              │                                        │
              │              ▼                                        │
              │        Audit trail (JSONL + SQLite, timestamps+actor) │
              └───────────────────────────────────────────────────────┘
                 ▲  poll every 30s                      │ safe values
                 │                                      ▼
        AWS / GCP live state               Terraform-managed stack posture

   CI: GitHub Actions → sentinel ci-scan --gate-only → block or allow deploy
   UI: dashboard (heatmap, findings, audit) with action buttons
```

**Key design decisions**

- **Remediation is Terraform-native.** Misconfigurations are encoded as
  boolean "posture variables" in the stack (`ssh_open`, `db_publicly_accessible`,
  …). Remediation = apply the stack with the safe value, so fixes are
  idempotent, auditable, and reversible by re-applying the snapshotted value.
- **Ownership boundary.** Sentinel auto-remediates only resources it manages;
  findings on anything else are flagged `MANUAL` (persistently visible, never
  blindly overwritten). Detect everything, fix only what you own.
- **A blind scanner never passes.** If a provider is unreachable or returns
  zero resources, the CI gate **fails** instead of reporting a clean pass.
- **Regression-aware.** A finding that was fixed and comes back re-alerts and
  re-remediates automatically.
- **Known infra floor:** modifying an RDS instance takes ~100s on AWS's side;
  SG/S3 remediations complete well under 60s.

## Quickstart

Prereqs: Python 3.12+, Terraform ≥ 1.5, an AWS account (credentials
configured via `aws configure`), optional GCP project.

```bash
git clone https://github.com/shrey2522/CloudGuardian-Sentinel---myonsitehealthcare.git
cd CloudGuardian-Sentinel---myonsitehealthcare
pip install -r requirements.txt

# optional GCP (detection): service-account JSON key with Viewer at
#   secrets/gcp-key.json  and the project id in secrets/gcp_project
# (the secrets/ folder is gitignored — keys never leave your machine)

python -m sentinel demo-setup   # deploy the intentionally vulnerable demo stack
python -m sentinel scan         # detect: 7 findings across AWS + GCP
python -m sentinel dashboard    # open http://127.0.0.1:8080 — full control center
python -m sentinel monitor      # autonomous: poll → alert → remediate → verify
```

### CLI reference

| Command | Purpose |
|---|---|
| `sentinel status` | provider health, rules loaded, stack ownership |
| `sentinel scan [--json]` | one-shot multi-cloud scan |
| `sentinel monitor` | continuous 30s loop with auto-remediation |
| `sentinel remediate --all / --rule ID / --fingerprint FP [--dry-run]` | Terraform remediation (dry-run prints the commands) |
| `sentinel rollback --latest / --id ID` | revert a remediation from its snapshot |
| `sentinel audit [--limit N] [--type T]` | inspect the audit trail |
| `sentinel demo-setup` | (re)deploy the vulnerable demo stack |
| `sentinel ci-scan [--gate-only]` | CI gate — exit 1 blocks the deployment |
| `sentinel dashboard` | control-center UI with action buttons |

Configuration is environment-based (`SENTINEL_POLL_INTERVAL`,
`SENTINEL_AUTO_REMEDIATE`, `SENTINEL_AWS_REGIONS`, `GCP_PROJECT`,
`SENTINEL_ACTOR`, …) — see `sentinel/config.py`.

## The demo (two stories)

**1. Planted misconfigurations, auto-fixed.** `demo-setup` deploys an open
security group, a publicly-accessible RDS instance and a public S3 bucket.
The monitor detects them within one 30s cycle and remediates them via
Terraform (SG/S3 in ~15s, RDS in ~100s — bounded by AWS), verifying each fix
and recording detect→clean SLA per finding. `rollback --latest` reverts any
fix on demand.

**2. The rogue stack.** `infra/test-stack` is an "unapproved" stack a
developer might apply (SG wide open, public bucket). Sentinel flags it within
one cycle, marks it `MANUAL` because it doesn't own those resources, alerts
every cycle until a human runs `terraform destroy` — then records
`RESOLVED_EXTERNAL`. Detect → flag → human fix → verified resolution.

## CI/CD gate

`.github/workflows/sentinel-gate.yml` runs on every push and PR:
terraform `fmt`/`validate`, then `sentinel ci-scan --gate-only` against live
cloud state. Repo secrets needed: `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`. A scan that cannot see the cloud **fails** the gate.
Proven live: a push with open misconfigurations produced a red run; after
Sentinel auto-remediated, the next push was green. The audit trail is
uploaded as a workflow artifact.

## Safety notes

- No credentials are stored in this repo. `secrets/`, Terraform state and
  key files are gitignored; the only passwords in code are demo-only
  defaults for the throwaway demo database.
- The demo stack deploys **intentionally vulnerable** resources — destroy
  them after the demo: `bash scripts/teardown.sh` (asks for confirmation).
  The optional rogue-stack RDS (~₹2/hr) is off by default.
- Audit artifacts in `audit/` are committed as demo evidence (event history
  and resource identifiers only).

## Repository layout

```
sentinel/                the service (providers, rule engine, remediation,
                         rollback, audit, monitor, CLI, dashboard)
infra/vulnerable-stack/  demo stack whose posture is controlled by variables
infra/test-stack/        "rogue" stack for external-detection demos
.github/workflows/       the CI security gate
audit/                   audit trail + remediation snapshots (demo evidence)
scripts/teardown.sh      manual teardown of all demo resources
TESTING.md               PRD-mapped verification guide (every claim, how to reproduce)
CONTEXT.md               domain glossary and design decisions
```

## Verification

Every claim above is reproducible — see **[TESTING.md](TESTING.md)** for the
step-by-step acceptance tests with expected outputs, run end-to-end against
real AWS and GCP accounts.
