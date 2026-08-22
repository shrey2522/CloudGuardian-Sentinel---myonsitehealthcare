"""Monitoring loop - polls providers every N seconds, detects, alerts, remediates.

Satisfies the PRD timing requirements:
  - poll interval 30s (configurable)
  - provider checks run concurrently (>= 5 concurrent checks supported)
  - detect -> remediate SLA is measured and audited (target: < 60s)
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor

from sentinel.models import utcnow

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Monitor:
    def __init__(self, providers, engine, audit, remediator, settings):
        self.providers = providers
        self.engine = engine
        self.audit = audit
        self.remediator = remediator
        self.settings = settings
        self.store_path = settings.findings_store

    # ------------------------------------------------------------- store
    def load_store(self):
        if self.store_path.exists():
            return json.loads(self.store_path.read_text(encoding="utf-8"))
        return {}

    def save_store(self, store):
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(json.dumps(store, indent=2, default=str),
                                   encoding="utf-8")

    # -------------------------------------------------------------- scan
    def scan_once(self):
        resources, statuses = [], {}
        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as ex:
            futures = {ex.submit(p.collect): p for p in self.providers}
        for fut, provider in futures.items():
            try:
                res, status = fut.result(timeout=180)
            except Exception as exc:
                res, status = [], {"healthy": False, "errors": [str(exc)]}
            resources.extend(res)
            statuses[provider.name] = {**status, "resources": len(res)}
        findings = self.engine.evaluate(resources)
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        return findings, statuses

    # ------------------------------------------------------------- cycle
    def cycle(self):
        t0 = time.monotonic()
        findings, statuses = self.scan_once()
        now = utcnow()
        fps = {f.fingerprint for f in findings}
        store = self.load_store()

        new_findings = []
        for f in findings:
            if f.fingerprint not in store:
                new_findings.append(f)
                store[f.fingerprint] = {**f.to_dict(),
                                        "first_seen": now, "last_seen": now, "status": "OPEN"}
            else:
                rec = store[f.fingerprint]
                rec["last_seen"] = now
                if rec.get("status") in ("REMEDIATED", "RESOLVED_EXTERNAL"):
                    # regression: a previously fixed misconfiguration is back
                    rec["status"] = "OPEN"
                    rec["regressed_at"] = now
                    new_findings.append(f)
                    self.audit.record("REGRESSION",
                                      f"{f.rule_id} on {f.resource_id} has REAPPEARED after "
                                      "being remediated - re-alerting and re-remediating",
                                      rule_id=f.rule_id, resource_id=f.resource_id,
                                      severity=f.severity)

        # resources that disappeared => remediation verified or externally fixed
        for fpr, rec in list(store.items()):
            if fpr in fps:
                continue
            if rec.get("status") == "REMEDIATING":
                sla = self._seconds_between(rec.get("first_seen"), now)
                rec["status"] = "REMEDIATED"
                rec["remediated_at"] = now
                rec["sla_s"] = sla
                self.audit.record("REMEDIATION_VERIFIED",
                                  f"{rec.get('rule_id')} on {rec.get('resource_id')} confirmed "
                                  f"clean (detect->clean {sla}s)", rule_id=rec.get("rule_id"),
                                  resource_id=rec.get("resource_id"), sla_s=sla)
            elif rec.get("status") == "OPEN":
                rec["status"] = "RESOLVED_EXTERNAL"
                rec["resolved_at"] = now
                self.audit.record("RESOLVED_EXTERNAL",
                                  f"{rec.get('rule_id')} on {rec.get('resource_id')} no longer "
                                  "present (fixed outside Sentinel)",
                                  rule_id=rec.get("rule_id"), resource_id=rec.get("resource_id"))

        # alert on new detections
        for f in new_findings:
            self.audit.record("DETECTION", f"{f.severity} {f.rule_id}: {f.title} on "
                              f"{f.resource_id} ({f.region}) - {f.details}",
                              rule_id=f.rule_id, resource_id=f.resource_id,
                              severity=f.severity, provider=f.provider,
                              remediation_action=f.remediation_action)
            print(f"[ALERT] {f.severity} {f.rule_id} {f.resource_id} - {f.title}")

        # auto-remediation: new findings plus retries for anything still open
        if self.settings.auto_remediate:
            new_fps = {f.fingerprint for f in new_findings}
            now = utcnow()
            retry_targets = []
            for f in findings:
                if f.fingerprint in new_fps or not (f.auto_remediation and f.remediation_action):
                    continue
                rec = store.get(f.fingerprint) or {}
                status = rec.get("status")
                if status in ("OPEN", "REMEDIATION_FAILED"):
                    retry_targets.append(f)
                elif status == "REMEDIATING" and self._seconds_between(
                        rec.get("remediation_started_at") or rec.get("last_seen", now), now) > 120:
                    retry_targets.append(f)   # convergence stalled - re-apply
            for f in new_findings + retry_targets:
                if not (f.auto_remediation and f.remediation_action):
                    continue
                tag = "REMEDIATE" if f.fingerprint in new_fps else "RETRY"
                result = self.remediator.remediate(f)
                print(f"[{tag}] {f.rule_id} on {f.resource_id}: {result.status} "
                      f"({result.message})")
                if result.status == "SUCCESS":
                    store[f.fingerprint]["status"] = "REMEDIATING"
                    store[f.fingerprint]["remediation_started_at"] = now
                elif result.status == "FAILED":
                    store[f.fingerprint]["status"] = "REMEDIATION_FAILED"

        self.save_store(store)
        elapsed = time.monotonic() - t0
        return {"new": len(new_findings), "open": len([f for f in findings]),
                "elapsed_s": round(elapsed, 1), "providers": statuses}

    def run(self):
        self.audit.record("MONITOR_START",
                          f"monitoring started (interval={self.settings.poll_interval}s, "
                          f"auto_remediate={self.settings.auto_remediate}, "
                          f"providers={[p.name for p in self.providers]})")
        print(f"CloudGuardian Sentinel monitoring every {self.settings.poll_interval}s. "
              f"Ctrl+C to stop.")
        cycle_no = 0
        while True:
            cycle_no += 1
            try:
                summary = self.cycle()
            except Exception as exc:
                self.audit.record("MONITOR_ERROR", f"cycle {cycle_no} failed: {exc}")
                summary = {"elapsed_s": 0}
            for name, status in summary.get("providers", {}).items():
                if not status.get("healthy", False):
                    print(f"[PROVIDER:{name}] unhealthy: {status}")
            print(f"[cycle {cycle_no}] new={summary.get('new')} open={summary.get('open')} "
                  f"took={summary.get('elapsed_s')}s")
            time.sleep(max(0, self.settings.poll_interval - summary.get("elapsed_s", 0)))

    @staticmethod
    def _seconds_between(ts_start, ts_end):
        from datetime import datetime, timezone
        try:
            fmt = "%Y-%m-%dT%H:%M:%S%z"
            start = datetime.strptime(ts_start, fmt)
            end = datetime.strptime(ts_end, fmt)
            return round((end - start).total_seconds(), 1)
        except (TypeError, ValueError):
            return -1
