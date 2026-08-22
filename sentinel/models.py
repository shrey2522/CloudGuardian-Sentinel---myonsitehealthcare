"""Domain objects shared across the Sentinel system."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Resource:
    """A cloud resource normalized across providers."""
    provider: str            # aws | gcp
    type: str                # e.g. aws_security_group, gcs_bucket
    id: str
    region: str
    attributes: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    """A detected rule violation on a resource."""
    rule_id: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    provider: str
    resource_type: str
    resource_id: str
    region: str
    details: str
    detected_at: str
    remediation_action: str = ""      # empty => detection-only
    auto_remediation: bool = False
    status: str = "OPEN"              # OPEN | REMEDIATING | REMEDIATED | ROLLED_BACK
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = f"{self.rule_id}:{self.provider}:{self.resource_id}"

    def to_dict(self):
        return asdict(self)
