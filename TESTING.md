# Testing Guide — CloudGuardian Sentinel

Every test below runs against **real AWS and GCP**. Expected outputs are stated
so results are self-verifying. Run all commands from the repo root.

## 0. Pre-flight (30 seconds)

```bash
python -m sentinel status
```
**Expected:** 8 rules loaded, stack "outputs OK", AWS healthy, GCP healthy.
If GCP says "not configured": check `secrets/gcp-key.json` exists.

## 1. Detection — YAML rule engine finds misconfigurations (PRD: ≥3 rules)

```bash
python -m sentinel demo-setup     # ensure vulnerable state (takes ~2 min: RDS flip)
python -m sentinel scan
```
**Expected: 7 findings** — CRITICAL AWS-SG-SSH-OPEN, AWS-SG-DB-PORTS-OPEN,
AWS-RDS-PUBLIC, AWS-S3-PUBLIC-READ; HIGH AWS-RDS-UNENCRYPTED; plus 2 CRITICAL
GCP-FW-SSH-OPEN on `default-allow-ssh` / `default-allow-rdp` (real GCP defaults).

## 2. Real-time monitoring + automated remediation (PRD: poll 30s, fix <60s)

Two terminals:

```bash
# terminal 1 — the monitor
python -m sentinel monitor

# terminal 2 — plant misconfigurations while it watches
python -m sentinel demo-setup
```
**Expected in terminal 1:** `[ALERT]` lines within one cycle (~30s), then
`[REMEDIATE] ... SUCCESS` lines, and `RETRY` lines if anything transiently
fails. Full clean-up takes ~2–3 min (the RDS flip alone is ~104s of AWS-side
processing). Stop with Ctrl+C.

**Idempotency check (PRD: safe to retry):** while the stack is safe, run
`python -m sentinel remediate --rule AWS-S3-PUBLIC-READ` — it exits SUCCESS
making zero changes.

## 3. Audit trail (PRD: timestamps + user context, 24h no loss)

```bash
python -m sentinel audit --limit 30
```
**Expected:** MONITOR_START, DETECTION, REMEDIATION_START/SUCCESS,
REMEDIATION_VERIFIED (with `sla_s`), SCAN events — each with UTC timestamp and
actor. Durability: `audit/audit.jsonl` is append-only with fsync; the SQLite
copy lives in `audit/audit.db`. CI additionally uploads both as an artifact.

## 4. Rollback — every remediation reversible (PRD constraint)

```bash
python -m sentinel demo-setup
python -m sentinel remediate --rule AWS-SG-SSH-OPEN   # closes SSH
python -m sentinel scan                               # SSH finding gone
python -m sentinel rollback --latest                  # revert it
python -m sentinel scan                               # SSH finding is back
```

## 5. CI/CD gate — blocks deployment (PRD deliverable)

```bash
python -m sentinel ci-scan --gate-only; echo exit=$?
```
- With misconfigurations open → prints `CI-BLOCK`, **exit=1** (deployment blocked).
- Local full mode `python -m sentinel ci-scan` remediates then re-verifies → `CI-PASS`, exit=0.
- On GitHub: any push while the stack is vulnerable → red run; after the
  monitor cleans up, push anything (even empty commit:
  `git commit --allow-empty -m recheck && git push`) → green run.
- Blind-scanner protection: remove AWS secrets and the gate fails instead of
  passing vacuously (verified in run 8 history).

## 6. Rule engine configurability (PRD: YAML-driven rules)

Open `sentinel/rules/rules.yaml`, change e.g. the `AWS-S3-PUBLIC-READ`
severity CRITICAL → MEDIUM, save, run `python -m sentinel scan` — the finding
now reports MEDIUM. No code changes. (Change it back after.)

## 7. CLI simulation (PRD: CLI to simulate/test remediation workflows)

```bash
python -m sentinel remediate --all --dry-run
```
**Expected:** prints the exact `terraform apply -var=...` commands without
executing them.

## 8. Dashboard / Control Center (bonus + full UI demo)

```bash
python -m sentinel dashboard     # open http://127.0.0.1:8080
```
**Expected:** provider×severity heatmap, live findings, audit feed, and
**action buttons** that run the same CLI commands (Scan now, Plant
misconfigurations, Remediate all, Rollback last fix, Run CI gate check) with
output streamed to an on-page console. The entire demo can be driven from
this one page.

## 9. Container (cloud-native packaging)

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
docker compose up --build
```
**Expected:** monitor cycles inside the container; audit/ and infra/ mounted
so state and trail persist.

## 10. After testing — leave things safe

```bash
python -m sentinel remediate --all     # or let the monitor finish its cycles
```
Post-hackathon teardown (destroys all demo resources, asks confirmation):
```bash
bash scripts/teardown.sh
```

## Known behavior notes

- RDS remediation takes ~104s — that is AWS's own modification time, so the
  60s SLA is met for SG/S3 findings but is infrastructure-bound for RDS.
- GCP rules are detection-only by MVP design.
- `demo-setup` while the monitor is running is fully supported; the monitor
  retries findings whose remediation was deferred by state-lock contention.
