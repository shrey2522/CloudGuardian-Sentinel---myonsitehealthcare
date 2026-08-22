"""YAML-driven rule engine.

Each rule declares a `detection.type` that maps to an evaluator function below.
Evaluators receive (attributes, params) and return (violated: bool, detail: str).
Adding a new check = new YAML entry (plus an evaluator only for genuinely new logic).
"""
import yaml

from sentinel.models import Finding, Resource, utcnow

ANYWHERE = ("0.0.0.0/0", "::/0")


# ---------------------------------------------------------------- evaluators
def eval_open_ingress(attrs, params):
    """True when an ingress rule grants ANYWHERE cidr on one of the given ports."""
    ports = set(params.get("ports", []))
    hits = []
    for rule in attrs.get("ingress", []):
        if not any(cidr in ANYWHERE for cidr in rule.get("cidrs", [])):
            continue
        if rule.get("protocol") not in ("tcp", "-1", "all"):
            continue
        lo, hi = rule.get("from_port", 0), rule.get("to_port", 0)
        if rule.get("protocol") == "-1" or set(range(lo, hi + 1)) & ports or lo == hi == -1:
            hits.append(f"port {rule.get('from_port')}-{rule.get('to_port')} from {rule.get('cidrs')}")
    return bool(hits), "; ".join(hits)


def eval_attribute_flag(attrs, params):
    """Generic boolean/string attribute comparison."""
    key = params["attribute"]
    expected = params.get("equals")
    actual = attrs.get(key)
    return actual == expected, f"{key}={actual!r} (expected {expected!r})"


def eval_s3_public_read(attrs, params):
    """Public when a wildcard-read policy exists AND public access is not blocked."""
    public = attrs.get("policy_public") and not attrs.get("public_access_blocked")
    return public, f"policy_public={attrs.get('policy_public')}, blocked={attrs.get('public_access_blocked')}"


def eval_gcp_firewall_open(attrs, params):
    ports = {str(p) for p in params.get("ports", [])}   # GCP API returns ports as strings
    hits = []
    if attrs.get("direction", "INGRESS").upper() != "INGRESS":
        return False, "egress rule"
    if not any(r in ANYWHERE for r in attrs.get("source_ranges", [])):
        return False, "restricted source ranges"
    for allowed in attrs.get("allowed", []):
        proto = (allowed.get("protocol") or "").lower()
        rule_ports = [str(p) for p in (allowed.get("ports") or [])]
        if proto in ("tcp", "all") and (proto == "all" or not rule_ports
                                        or set(rule_ports) & ports):
            hits.append(f"{proto}:{rule_ports or 'all'}")
    return bool(hits), "; ".join(hits) or "no matching protocol/port"


def eval_gcp_bucket_public(attrs, params):
    return bool(attrs.get("public")), f"public={attrs.get('public')}"


EVALUATORS = {
    "open_ingress": eval_open_ingress,
    "attribute_flag": eval_attribute_flag,
    "s3_public_read": eval_s3_public_read,
    "gcp_firewall_open": eval_gcp_firewall_open,
    "gcp_bucket_public": eval_gcp_bucket_public,
}


# ------------------------------------------------------------------- engine
class RuleEngine:
    def __init__(self, rules_file):
        with open(rules_file, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        self.rules = doc.get("rules", [])
        unknown = {r.get("id"): r.get("detection", {}).get("type")
                   for r in self.rules
                   if r.get("detection", {}).get("type") not in EVALUATORS}
        if unknown:
            raise ValueError(f"unknown detection types: {unknown}")

    def evaluate(self, resources):
        """Evaluate every rule against every compatible resource -> [Finding]."""
        findings = []
        for rule in self.rules:
            for res in resources:
                if res.provider != rule.get("provider") or res.type != rule.get("resource_type"):
                    continue
                evaluator = EVALUATORS[rule["detection"]["type"]]
                violated, detail = evaluator(res.attributes, rule.get("detection", {}))
                if not violated:
                    continue
                remediation = rule.get("remediation", {})
                findings.append(Finding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "MEDIUM"),
                    title=rule.get("title", rule["id"]),
                    provider=res.provider,
                    resource_type=res.type,
                    resource_id=res.id,
                    region=res.region,
                    details=detail,
                    detected_at=utcnow(),
                    remediation_action=remediation.get("action", ""),
                    auto_remediation=bool(remediation.get("action")) and remediation.get("auto", False),
                ))
        return findings
