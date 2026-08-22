"""Remediation engine - converges misconfigured resources via `terraform apply`.

Every remediation flips one of the stack's security-posture variables and
re-applies the stack, which makes remediation:
  - terraform-native (PRD: remediation via Terraform apply)
  - idempotent (re-apply converges to the same safe state)
  - reversible (previous values snapshotted for the rollback command)
Only resources owned by the demo stack are auto-remediated; everything else is
flagged for manual action.
"""
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from sentinel.models import utcnow

# safe values per remediation action
ACTIONS = {
    "close_ssh_ingress":   {"ssh_open": False},
    "close_db_ingress":    {"db_port_open": False},
    "disable_rds_public":  {"db_publicly_accessible": False},
    "enable_s3_encryption": {"s3_encrypted": True},
    "block_s3_public":     {"s3_public": False},
}

# deliberately vulnerable defaults (the state the demo stack ships with)
VULNERABLE_STATE = {
    "ssh_open": True,
    "db_port_open": True,
    "db_publicly_accessible": True,
    "s3_encrypted": False,
    "s3_public": True,
}


@dataclass
class RemediationResult:
    finding: object
    action: str
    status: str          # SUCCESS | FAILED | SKIPPED | DRY_RUN
    message: str
    duration_s: float = 0.0
    snapshot_id: str = ""


class Remediator:
    def __init__(self, stack_dir, snapshot_dir, audit, state_file):
        self.stack_dir = Path(stack_dir)
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        self.state_file = Path(state_file)
        self._state = self._load_state()

    # ------------------------------------------------------------- state
    def _load_state(self):
        if self.state_file.exists():
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        return dict(VULNERABLE_STATE)

    def _save_state(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    @property
    def state(self):
        return dict(self._state)

    # --------------------------------------------------- stack ownership
    def stack_outputs(self):
        proc = self._run(["terraform", "output", "-json"], check=False)
        if proc.returncode != 0:
            # transient failures happen when another terraform command holds the
            # state lock - one retry before giving up
            import time as _t
            _t.sleep(2)
            proc = self._run(["terraform", "output", "-json"], check=False)
        if proc.returncode != 0:
            return {}
        try:
            return {k: v.get("value") for k, v in json.loads(proc.stdout).items()}
        except json.JSONDecodeError:
            return {}

    def owns_resource(self, finding):
        """The terraform-var remediation only affects demo-stack resources."""
        outputs = self.stack_outputs()
        known = {
            outputs.get("open_security_group_id"),
            outputs.get("public_db_identifier"),
            outputs.get("public_db_arn"),
            outputs.get("unencrypted_bucket"),
            outputs.get("public_bucket"),
        }
        return finding.resource_id in known

    # ------------------------------------------------------------ engine
    def _run(self, cmd, check=True):
        return subprocess.run(cmd, cwd=self.stack_dir, capture_output=True,
                              text=True, timeout=600, check=check)

    def _terraform_apply(self, values, dry_run=False):
        cmd = ["terraform", f"-chdir={self.stack_dir}", "apply", "-auto-approve", "-no-color"]
        cmd += [f"-var={k}={'true' if v else 'false'}" for k, v in sorted(values.items())]
        if dry_run:
            return 0, " ".join(cmd), ""
        proc = self._run(cmd, check=False)
        return proc.returncode, proc.stdout, proc.stderr

    def remediate(self, finding, dry_run=False):
        action = finding.remediation_action
        if not action:
            result = RemediationResult(finding, "", "SKIPPED",
                                       "detection-only rule (no remediation action defined)")
            self.audit.record("REMEDIATION_SKIPPED", f"{finding.rule_id} on {finding.resource_id}: "
                              "detection-only rule", resource_id=finding.resource_id,
                              rule_id=finding.rule_id)
            return result
        if action not in ACTIONS:
            self.audit.record("REMEDIATION_FAILED", f"unknown action {action}",
                              resource_id=finding.resource_id, rule_id=finding.rule_id)
            return RemediationResult(finding, action, "FAILED", f"unknown action {action}")
        if not self.owns_resource(finding):
            self.audit.record("REMEDIATION_SKIPPED",
                              f"{finding.resource_id} not managed by the demo stack - manual "
                              "remediation required", resource_id=finding.resource_id,
                              rule_id=finding.rule_id)
            return RemediationResult(finding, action, "SKIPPED",
                                     "resource not managed by the demo stack")

        previous = self.state
        target = dict(previous)
        target.update(ACTIONS[action])
        snapshot_id = f"{utcnow().replace(':', '').replace('+', '_')}_{action}"
        if not dry_run:
            snapshot = self.snapshot_dir / f"{snapshot_id}.json"
            snapshot.write_text(json.dumps({
                "snapshot_id": snapshot_id,
                "action": action,
                "previous_state": previous,
                "finding": finding.to_dict(),
                "created_at": utcnow(),
            }, indent=2, default=str), encoding="utf-8")

        self.audit.record("REMEDIATION_START",
                          f"{action} on {finding.resource_id} ({finding.rule_id})",
                          resource_id=finding.resource_id, rule_id=finding.rule_id,
                          vars_applied=ACTIONS[action], dry_run=dry_run)
        t0 = time.monotonic()
        code, out, err = self._terraform_apply(target, dry_run=dry_run)
        duration = round(time.monotonic() - t0, 1)

        if dry_run:
            return RemediationResult(finding, action, "DRY_RUN", out, duration)

        if code == 0:
            self._state = target
            self._save_state()
            self.audit.record("REMEDIATION_SUCCESS",
                              f"{action} applied on {finding.resource_id} in {duration}s",
                              resource_id=finding.resource_id, rule_id=finding.rule_id,
                              duration_s=duration, snapshot_id=snapshot_id,
                              terraform_tail=out.strip().splitlines()[-3:])
            return RemediationResult(finding, action, "SUCCESS",
                                     f"terraform apply ok ({duration}s)", duration, snapshot_id)
        self.audit.record("REMEDIATION_FAILED",
                          f"{action} failed on {finding.resource_id}",
                          resource_id=finding.resource_id, rule_id=finding.rule_id,
                          duration_s=duration, error=err.strip()[-500:])
        return RemediationResult(finding, action, "FAILED",
                                 f"terraform apply failed: {err.strip()[-300:]}", duration)
