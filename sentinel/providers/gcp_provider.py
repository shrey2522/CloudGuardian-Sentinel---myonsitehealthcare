"""GCP provider - collects firewall rules and GCS buckets via the REST APIs.

Activated as soon as GCP_PROJECT + a service-account JSON key are configured;
otherwise the provider reports 'not configured' and is skipped gracefully.
"""
from google.oauth2 import service_account
from googleapiclient.discovery import build

from sentinel.models import Resource
from .base import BaseProvider

SCOPES = [
    "https://www.googleapis.com/auth/compute.readonly",
    "https://www.googleapis.com/auth/devstorage.read_only",
]


class GcpProvider(BaseProvider):
    name = "gcp"

    def __init__(self, project, key_path):
        self.project = project
        self.key_path = key_path
        self._credentials = None

    def _creds(self):
        if self._credentials is None:
            self._credentials = service_account.Credentials.from_service_account_file(
                str(self.key_path), scopes=SCOPES)
        return self._credentials

    def configured(self):
        return bool(self.project) and self.key_path.exists()

    def collect(self):
        if not self.configured():
            return [], {"healthy": False, "errors": [],
                        "reason": f"not configured (need GCP_PROJECT + key at {self.key_path})"}
        resources = []
        errors = []
        for fn in (self._firewalls, self._buckets):
            try:
                resources.extend(fn())
            except Exception as exc:
                errors.append(f"{fn.__name__}: {exc}")
        return resources, {"healthy": not errors, "errors": errors}

    def _firewalls(self):
        compute = build("compute", "v1", credentials=self._creds(), cache_discovery=False)
        fw = compute.firewalls().list(project=self.project).execute().get("items", [])
        out = []
        for rule in fw:
            out.append(Resource(
                provider="gcp", type="gcp_firewall", id=rule["name"], region="global",
                attributes={
                    "direction": rule.get("Direction", rule.get("direction", "INGRESS")),
                    "source_ranges": rule.get("sourceRanges", []),
                    "allowed": [
                        {"protocol": a.get("IPProtocol", a.get("protocol")),
                         "ports": a.get("ports", [])}
                        for a in rule.get("allowed", rule.get("Allowed", []))
                    ],
                    "target_tags": rule.get("targetTags", rule.get("target_tags", [])),
                },
            ))
        return out

    def _buckets(self):
        storage = build("storage", "v1", credentials=self._creds(), cache_discovery=False)
        out = []
        for bucket in storage.buckets().list(project=self.project).execute().get("items", []):
            name = bucket["name"]
            public = False
            try:
                policy = storage.buckets().getIamPolicy(bucket=name).execute()
                for binding in policy.get("bindings", []):
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public = True
            except Exception:
                public = False
            out.append(Resource(
                provider="gcp", type="gcs_bucket", id=name, region=bucket.get("location", ""),
                attributes={"public": public, "storage_class": bucket.get("storageClass")},
            ))
        return out
