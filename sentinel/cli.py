"""CloudGuardian Sentinel command-line interface.

Commands:
  status       - show provider health, rule count and stack ownership
  scan         - one-shot scan, prints findings (optionally JSON)
  monitor      - continuous monitoring loop (30s default)
  remediate    - run remediation for findings (--all / --rule / --fingerprint)
  rollback     - revert a remediation from its snapshot (--latest / --id)
  audit        - show recent audit-trail events
  demo-setup   - (re)deploy the intentionally vulnerable demo stack
  ci-scan      - CI gate: scan, remediate, re-scan; exit 1 if remediation failed
"""
import argparse
import json
import subprocess
import sys

from sentinel.audit import AuditLog
from sentinel.config import settings
from sentinel.models import utcnow
from sentinel.monitor import Monitor
from sentinel.providers import AwsProvider, GcpProvider
from sentinel.remediation import Remediator, VULNERABLE_STATE
from sentinel.remediation.rollback import rollback as rollback_fn
from sentinel.rules import RuleEngine

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_components():
    settings.ensure_dirs()
    providers = [AwsProvider(settings.aws_regions),
                 GcpProvider(settings.gcp_project, settings.gcp_key_path)]
    engine = RuleEngine(settings.rules_file)
    audit = AuditLog(settings.audit_dir, settings.actor)
    remediator = Remediator(settings.stack_dir, settings.snapshot_dir, audit,
                            settings.audit_dir / "remediation_state.json")
    return providers, engine, audit, remediator


def print_findings(findings):
    if not findings:
        print("No misconfigurations detected.")
        return
    print(f"\n{len(findings)} finding(s):\n" + "-" * 78)
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
        print(f"[{f.severity:<8}] {f.rule_id}")
        print(f"           resource : {f.provider}:{f.resource_type} {f.resource_id} ({f.region})")
        print(f"           detail   : {f.details}")
        print(f"           action   : {f.remediation_action or 'detection-only'}"
              f"{' (auto)' if f.auto_remediation else ''}")
        print(f"           detected : {f.detected_at}")
        print("-" * 78)


def cmd_status(args):
    providers, engine, audit, remediator = build_components()
    print(f"CloudGuardian Sentinel - {utcnow()}  actor={settings.actor}")
    print(f"rules      : {len(engine.rules)} loaded from {settings.rules_file}")
    outputs = remediator.stack_outputs()
    print(f"stack      : {settings.stack_dir} "
          f"({'outputs OK' if outputs else 'NOT DEPLOYED / terraform error'})")
    for p in providers:
        status = {"healthy": p.name == "aws"}
        if p.name == "gcp":
            status = {"healthy": p.configured(),
                      "reason": "" if p.configured() else "GCP_PROJECT / secrets/gcp-key.json missing"}
        print(f"provider   : {p.name:<4} {status}")
    print(f"audit db   : {settings.audit_dir / 'audit.db'}")


def cmd_scan(args):
    providers, engine, audit, _ = build_components()
    monitor = Monitor(providers, engine, audit, None, settings)
    findings, statuses = monitor.scan_once()
    audit.record("SCAN", f"one-shot scan: {len(findings)} finding(s)",
                 findings=[f.to_dict() for f in findings])
    for name, status in statuses.items():
        if not status.get("healthy", False):
            print(f"[PROVIDER:{name}] {status}", file=sys.stderr)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
    else:
        print_findings(findings)


def cmd_monitor(args):
    providers, engine, audit, remediator = build_components()
    if args.no_auto_remediate:
        settings.auto_remediate = False
    monitor = Monitor(providers, engine, audit, remediator, settings)
    try:
        monitor.run()
    except KeyboardInterrupt:
        audit.record("MONITOR_STOP", "monitoring stopped by user")
        print("\nmonitor stopped")


def select_findings(findings, args):
    if args.fingerprint:
        return [f for f in findings if f.fingerprint == args.fingerprint]
    if args.rule:
        return [f for f in findings if f.rule_id == args.rule]
    if args.all:
        return [f for f in findings if f.remediation_action]
    raise SystemExit("choose one of --all / --rule ID / --fingerprint FP")


def cmd_remediate(args):
    providers, engine, audit, remediator = build_components()
    monitor = Monitor(providers, engine, audit, remediator, settings)
    findings, _ = monitor.scan_once()
    targets = select_findings(findings, args)
    if not targets:
        print("no matching findings to remediate")
        return
    exit_code = 0
    for f in targets:
        result = remediator.remediate(f, dry_run=args.dry_run)
        print(f"[{result.status}] {f.rule_id} on {f.resource_id}: {result.message}")
        if result.status == "FAILED":
            exit_code = 1
    sys.exit(exit_code)


def cmd_rollback(args):
    _, _, audit, _ = build_components()
    snapshot_id = None if args.latest else args.id
    ok, msg = rollback_fn(settings.stack_dir, settings.snapshot_dir,
                          settings.audit_dir / "remediation_state.json",
                          audit, snapshot_id=snapshot_id)
    print(("[OK] " if ok else "[FAIL] ") + msg)
    sys.exit(0 if ok else 1)


def cmd_audit(args):
    _, _, audit, _ = build_components()
    events = audit.recent(limit=args.limit, event_type=args.type)
    if not events:
        print("audit trail is empty")
        return
    for e in events:
        print(f"{e['ts']}  {e['event_type']:<22} actor={e['actor']}")
        print(f"    {e['message']}")


def cmd_demo_setup(args):
    _, _, audit, _ = build_components()
    cmd = ["terraform", f"-chdir={settings.stack_dir}", "apply", "-auto-approve", "-no-color"]
    cmd += [f"-var={k}={'true' if v else 'false'}" for k, v in sorted(VULNERABLE_STATE.items())]
    print(" ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    print(proc.stdout[-1500:])
    if proc.returncode != 0:
        print(proc.stderr[-800:], file=sys.stderr)
        audit.record("DEMO_SETUP_FAILED", "vulnerable stack apply failed",
                     error=proc.stderr[-300:])
        sys.exit(1)
    (settings.audit_dir / "remediation_state.json").write_text(
        json.dumps(VULNERABLE_STATE, indent=2), encoding="utf-8")
    audit.record("DEMO_SETUP", "intentionally vulnerable demo stack deployed",
                 state=VULNERABLE_STATE)
    print("[OK] demo stack is in the vulnerable state")


def cmd_ci_scan(args):
    """CI/CD gate: block the deployment when remediation fails or leaves risks open."""
    providers, engine, audit, remediator = build_components()
    monitor = Monitor(providers, engine, audit, remediator, settings)
    findings, _ = monitor.scan_once()
    audit.record("CI_SCAN", f"CI gate scan: {len(findings)} finding(s)",
                 findings=[f.to_dict() for f in findings])
    actionable = [f for f in findings if f.remediation_action]
    if not findings:
        audit.record("CI_PASS", "no misconfigurations - deployment allowed")
        print("CI-PASS: no misconfigurations detected")
        sys.exit(0)
    print_findings(findings)
    failures = []
    for f in actionable:
        result = remediator.remediate(f)
        print(f"[REMEDIATE] {f.rule_id} on {f.resource_id}: {result.status}")
        if result.status == "FAILED":
            failures.append(f.fingerprint)
    remaining, _ = monitor.scan_once()
    still_open = [f for f in remaining if f.remediation_action or args.fail_on == "any"]
    if failures or still_open:
        audit.record("CI_BLOCK", "deployment BLOCKED - remediation failed or risks remain",
                     failed=failures, remaining=[f.to_dict() for f in still_open])
        print(f"CI-BLOCK: deployment blocked ({len(failures)} failed remediations, "
              f"{len(still_open)} open actionable findings)")
        sys.exit(1)
    audit.record("CI_PASS", "all misconfigurations remediated - deployment allowed")
    print("CI-PASS: all actionable misconfigurations remediated")
    sys.exit(0)


def cmd_dashboard(args):
    import uvicorn
    from sentinel.dashboard import app
    print(f"dashboard on http://{args.host}:{args.port} (auto-refresh 5s)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


def main():
    parser = argparse.ArgumentParser(prog="sentinel",
                                     description="CloudGuardian Sentinel - IaC/cloud security monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show provider health and configuration").set_defaults(func=cmd_status)

    p_scan = sub.add_parser("scan", help="one-shot scan")
    p_scan.add_argument("--json", action="store_true", help="output findings as JSON")
    p_scan.set_defaults(func=cmd_scan)

    p_mon = sub.add_parser("monitor", help="continuous monitoring loop")
    p_mon.add_argument("--no-auto-remediate", action="store_true")
    p_mon.set_defaults(func=cmd_monitor)

    p_rem = sub.add_parser("remediate", help="remediate findings via terraform apply")
    p_rem.add_argument("--all", action="store_true", help="all actionable findings")
    p_rem.add_argument("--rule", help="remediate findings of this rule id")
    p_rem.add_argument("--fingerprint", help="remediate this exact finding")
    p_rem.add_argument("--dry-run", action="store_true", help="print the terraform command only")
    p_rem.set_defaults(func=cmd_remediate)

    p_rb = sub.add_parser("rollback", help="revert a remediation from its snapshot")
    p_rb.add_argument("--latest", action="store_true", help="roll back most recent snapshot")
    p_rb.add_argument("--id", help="roll back a specific snapshot id")
    p_rb.set_defaults(func=cmd_rollback)

    p_aud = sub.add_parser("audit", help="show audit trail")
    p_aud.add_argument("--limit", type=int, default=20)
    p_aud.add_argument("--type", help="filter by event type")
    p_aud.set_defaults(func=cmd_audit)

    sub.add_parser("demo-setup", help="(re)deploy the vulnerable demo stack").set_defaults(func=cmd_demo_setup)

    p_ci = sub.add_parser("ci-scan", help="CI/CD gate - exit 1 when remediation fails")
    p_ci.add_argument("--fail-on", choices=["actionable", "any"], default="actionable")
    p_ci.set_defaults(func=cmd_ci_scan)

    p_dash = sub.add_parser("dashboard", help="risk heatmap dashboard (bonus)")
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--port", type=int, default=8080)
    p_dash.set_defaults(func=cmd_dashboard)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
