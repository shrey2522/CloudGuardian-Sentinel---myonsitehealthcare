"""Central configuration - everything overridable via environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


class Settings:
    # paths
    base_dir = BASE_DIR
    rules_file = Path(_env("SENTINEL_RULES_FILE", BASE_DIR / "sentinel" / "rules" / "rules.yaml"))
    stack_dir = Path(_env("SENTINEL_STACK_DIR", BASE_DIR / "infra" / "vulnerable-stack"))
    audit_dir = Path(_env("SENTINEL_AUDIT_DIR", BASE_DIR / "audit"))
    snapshot_dir = Path(_env("SENTINEL_SNAPSHOT_DIR", BASE_DIR / "audit" / "snapshots"))
    findings_store = Path(_env("SENTINEL_FINDINGS_STORE", BASE_DIR / "audit" / "findings.json"))

    # behaviour
    poll_interval = int(_env("SENTINEL_POLL_INTERVAL", "30"))          # PRD: every 30s
    auto_remediate = _env("SENTINEL_AUTO_REMEDIATE", "true").lower() in ("1", "true", "yes")
    max_workers = int(_env("SENTINEL_MAX_WORKERS", "5"))                # PRD: 5 concurrent checks

    # cloud
    aws_regions = [r.strip() for r in _env("SENTINEL_AWS_REGIONS", "us-east-1").split(",")]
    gcp_project = _env("GCP_PROJECT", "")
    gcp_key_path = Path(_env("GCP_KEY_FILE", BASE_DIR / "secrets" / "gcp-key.json"))

    def __init__(self):
        if not self.gcp_project:
            project_file = self.base_dir / "secrets" / "gcp_project"
            if project_file.exists():
                object.__setattr__(self, "gcp_project", project_file.read_text(encoding="utf-8").strip())

    # identity for audit "user context"
    actor = _env("SENTINEL_ACTOR", os.environ.get("GITHUB_ACTOR") or os.environ.get("USERNAME") or "unknown")

    def ensure_dirs(self):
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
