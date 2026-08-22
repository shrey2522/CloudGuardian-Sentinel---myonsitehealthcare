# CONTEXT.md — domain glossary

## Terms

- **Resource**: a normalized cloud object (security group, RDS instance, S3/GCS bucket, firewall rule) identified by provider, type, id and region.
- **Rule**: a YAML-declared check pairing a *detection* with an optional *remediation action*, severity and title. Rules are configuration; only genuinely new check *logic* requires code.
- **Detection type**: the evaluator a rule selects (e.g. `open_ingress`, `attribute_flag`, `s3_public_read`) plus its parameters.
- **Finding**: a rule violation observed on a specific Resource at a point in time. Identified by a **fingerprint** (`rule:provider:resource-id`). Lifecycle: OPEN → REMEDIATING → REMEDIATED, with ROLLED_BACK, REMEDIATION_FAILED, RESOLVED_EXTERNAL as alternate outcomes.
- **Provider**: a pluggable cloud adapter (aws, gcp) that collects Resources. A provider may be *not configured*, in which case it is skipped and reported unhealthy without stopping the monitor.
- **Remediation action**: the named fix a Finding can receive (e.g. `close_ssh_ingress`). Implemented as a Terraform *posture toggle* flip plus `terraform apply` of the owning stack — hence idempotent.
- **Posture toggle**: a boolean Terraform variable in the demo stack that encodes one risky/safe posture (e.g. `ssh_open`). The set of current toggle values is the *stack posture state*.
- **Stack ownership**: only Resources created by the Sentinel demo stack are auto-remediable; findings on anything else are flagged for manual action.
- **Snapshot**: the record of the previous stack posture state saved before each remediation; the unit of rollback.
- **Rollback**: re-applying a snapshot's posture state via Terraform, reverting exactly one remediation.
- **Audit event**: an immutable, timestamped, actor-attributed record (JSONL + SQLite) of anything the system observed or did — scans, detections, remediations, rollbacks, CI decisions.
- **Actor**: the human or automation identity context attached to every audit event (local user, `GITHUB_ACTOR`, container).
- **CI gate (ci-scan)**: the scan → remediate → re-scan decision that allows or blocks a deployment; blocks when remediation fails or actionable findings remain.
- **SLA**: measured seconds from first detection to confirmed-clean (resource disappears from scans); target 60s.

## Decisions worth remembering

- "Unencrypted storage" for S3: AWS enables SSE-S3 by default on all new buckets since 2023, so a true "no encryption" S3 rule fires only on legacy buckets; the RDS-unencrypted rule is the live demonstration of this class.
- GCP is detection-only in the MVP (PRD requires Terraform remediation for at least one AWS misconfiguration; GCP firewall/bucket remediation remains future work).
