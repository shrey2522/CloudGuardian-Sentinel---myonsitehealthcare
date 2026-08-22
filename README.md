# CloudGuardian Sentinel

Real-time security monitoring and automated remediation for Infrastructure-as-Code
and cloud resource configurations across **AWS and GCP**.

Sentinel continuously polls cloud resources (default: every 30s), evaluates a
**YAML-driven rule engine** against them, raises alerts, writes an immutable
**audit trail**, and **remediates misconfigurations via `terraform apply`** —
with every change reversible through a one-command **rollback**. A CI/CD gate
(`ci-scan`) **blocks deployments** when remediation fails.

## Architecture

```
        ┌────────────────────────────────────────────────────────┐
        │                     Sentinel service                    │
        │                                                        │
        │  Providers (concurrent)     Rule engine (YAML)          │
        │  ├─ AWS  (boto3)            ├─ open dangerous ports     │
        │  └─ GCP  (REST APIs)        ├─ public RDS / S3          │
        │                             ├─ unencrypted storage      │
        │                             └─ GCP firewall/bucket      │
        │        findings                                         │
        │           │                                            │
        │           ▼                                            │
        │  Audit trail (JSONL + SQLite)   Remediation engine      │
        │  timestamps + actor             `terraform apply`       │
        │                                 snapshots for rollback  │
        └────────────────────────────────────────────────────────┘
             ▲                                        │
             │ poll 30s                                ▼
      AWS / GCP resources                    safe state (idempotent)
```

- **Detection rules** live in [`sentinel/rules/rules.yaml`](sentinel/rules/rules.yaml) —
  severities, ports and thresholds are configuration, not code.
- **Remediation** flips a security-posture Terraform variable and re-applies the
  stack, so fixes are idempotent (re-apply = no drift) and auditable.
- **Rollback** re-applies the state snapshotted before a remediation.
- **CI gate** (`ci-scan`) scans live cloud state and exits non-zero to block
  the deployment. CI runners use `--gate-only` (no Terraform state there);
  locally the gate also remediates and re-verifies. A blind or unhealthy
  provider fails the gate — a scan that cannot see never passes.

## Quickstart

```bash
pip install -r requirements.txt

python -m sentinel status          # provider health, rules, stack ownership
python -m sentinel scan            # one-shot scan across AWS (+GCP if configured)
python -m sentinel monitor         # continuous: poll -> alert -> auto-remediate
python -m sentinel remediate --rule AWS-SG-SSH-OPEN   # targeted fix via terraform
python -m sentinel remediate --all --dry-run          # preview terraform commands
python -m sentinel rollback --latest                  # revert last remediation
python -m sentinel audit --limit 20                   # inspect the audit trail
python -m sentinel demo-setup       # (re)deploy the vulnerable demo stack
python -m sentinel ci-scan          # CI gate - exit 1 blocks deployment
```

### Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_POLL_INTERVAL` | `30` | seconds between scans |
| `SENTINEL_AUTO_REMEDIATE` | `true` | auto-fix on detection |
| `SENTINEL_AWS_REGIONS` | `us-east-1` | comma-separated AWS regions |
| `GCP_PROJECT` / `GCP_KEY_FILE` | – | enables the GCP provider |
| `SENTINEL_ACTOR` | user / `GITHUB_ACTOR` | audit user context |

## Demo (docker)

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
export GCP_PROJECT=my-project
docker compose up --build   # monitor + auto-remediation in a container
```

## Demo stack

`infra/vulnerable-stack` deploys intentionally misconfigured resources
(open security group, publicly-accessible RDS, public S3 bucket) whose posture
is controlled by variables — the Sentinel remediates them by re-applying the
stack with safe values. Teardown is manual: `bash scripts/teardown.sh`.

## Non-functional behaviour

- detect → remediate measured and audited per finding (target < 60s)
- provider checks execute concurrently (≥ 5 workers)
- audit events are append-only JSONL (fsync) + SQLite index — no data loss
- remediation is idempotent; rollback reverses any remediation
- the whole service ships as a container and its infra as Terraform
