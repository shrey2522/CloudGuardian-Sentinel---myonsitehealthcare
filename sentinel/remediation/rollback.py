"""Rollback - reverts a remediation by re-applying the snapshotted variable state.

PRD constraint: every remediation must be reversible via a rollback command.
"""
import json
import subprocess
import time

from sentinel.models import utcnow


def list_snapshots(snapshot_dir):
    return sorted(snapshot_dir.glob("*.json"))


def rollback(stack_dir, snapshot_dir, state_file, audit, snapshot_id=None):
    """Apply the most recent (or given) snapshot's previous state. Returns (ok, msg)."""
    snapshots = list_snapshots(snapshot_dir)
    if not snapshots:
        return False, "no remediation snapshots found - nothing to roll back"
    if snapshot_id:
        matches = [s for s in snapshots if s.name.startswith(snapshot_id)]
        if not matches:
            return False, f"snapshot '{snapshot_id}' not found"
        snapshot_file = matches[-1]
    else:
        snapshot_file = snapshots[-1]

    doc = json.loads(snapshot_file.read_text(encoding="utf-8"))
    previous = doc["previous_state"]
    action = doc["action"]
    audit.record("ROLLBACK_START", f"rolling back {action} ({doc['snapshot_id']})",
                 snapshot_id=doc["snapshot_id"], previous_state=previous)

    cmd = ["terraform", f"-chdir={stack_dir}", "apply", "-auto-approve", "-no-color"]
    cmd += [f"-var={k}={'true' if v else 'false'}" for k, v in sorted(previous.items())]

    t0 = time.monotonic()
    proc = subprocess.run(cmd, cwd=".", capture_output=True, text=True, timeout=600)
    duration = round(time.monotonic() - t0, 1)
    if proc.returncode != 0:
        audit.record("ROLLBACK_FAILED", f"rollback of {action} failed",
                     snapshot_id=doc["snapshot_id"], error=proc.stderr.strip()[-500:])
        return False, f"terraform apply failed: {proc.stderr.strip()[-300:]}"

    state_file.write_text(json.dumps(previous, indent=2), encoding="utf-8")
    audit.record("ROLLBACK", f"reverted {action} in {duration}s "
                f"(restored {doc['snapshot_id']})", snapshot_id=doc["snapshot_id"],
                duration_s=duration, restored_state=previous)
    return True, f"rolled back {action} ({doc['snapshot_id']}) in {duration}s"
