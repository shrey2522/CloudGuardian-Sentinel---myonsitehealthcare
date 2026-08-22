"""AWS provider - collects security groups, RDS instances and S3 buckets."""
import json

import boto3
from botocore.exceptions import ClientError

from sentinel.models import Resource
from .base import BaseProvider, ProviderError

ANYWHERE = ("0.0.0.0/0", "::/0")


class AwsProvider(BaseProvider):
    name = "aws"

    def __init__(self, regions):
        self.regions = regions

    def collect(self):
        resources = []
        errors = []
        for fn in (self._security_groups, self._rds_instances, self._s3_buckets):
            try:
                resources.extend(fn())
            except Exception as exc:  # keep other collectors alive
                errors.append(f"{fn.__name__}: {exc}")
        status = {"healthy": not errors, "errors": errors, "regions": self.regions}
        return resources, status

    def _security_groups(self):
        out = []
        for region in self.regions:
            ec2 = boto3.client("ec2", region_name=region)
            for sg in ec2.describe_security_groups()["SecurityGroups"]:
                ingress = [
                    {
                        "from_port": p.get("FromPort", 0),
                        "to_port": p.get("ToPort", 0),
                        "protocol": p.get("IpProtocol", "-1"),
                        "cidrs": [ip["CidrIp"] for ip in p.get("IpRanges", [])],
                    }
                    for p in sg.get("IpPermissions", [])
                ]
                tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
                out.append(Resource(
                    provider="aws", type="aws_security_group", id=sg["GroupId"],
                    region=region,
                    attributes={"name": sg["GroupName"], "vpc_id": sg.get("VpcId"),
                                "ingress": ingress, "tags": tags},
                ))
        return out

    def _rds_instances(self):
        out = []
        for region in self.regions:
            rds = boto3.client("rds", region_name=region)
            for db in rds.describe_db_instances()["DBInstances"]:
                arn = db["DBInstanceArn"]
                tag_list = rds.list_tags_for_resource(ResourceName=arn).get("TagList", [])
                tags = {t["Key"]: t["Value"] for t in tag_list}
                out.append(Resource(
                    provider="aws", type="aws_rds_instance", id=db["DBInstanceIdentifier"],
                    region=region,
                    attributes={
                        "arn": arn, "engine": db.get("Engine"),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "endpoint": (db.get("Endpoint") or {}).get("Address"),
                        "tags": tags,
                    },
                ))
        return out

    def _s3_buckets(self):
        out = []
        s3 = boto3.client("s3", region_name=self.regions[0])
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            client = boto3.client("s3", region_name=region)
            out.append(Resource(
                provider="aws", type="aws_s3_bucket", id=name, region=region,
                attributes={
                    "encrypted": self._bucket_encrypted(client, name),
                    "policy_public": self._bucket_policy_public(client, name),
                    "public_access_blocked": self._bucket_public_blocked(client, name),
                    "tags": self._bucket_tags(client, name),
                },
            ))
        return out

    @staticmethod
    def _bucket_encrypted(client, name):
        try:
            client.get_bucket_encryption(Bucket=name)
            return True
        except ClientError:
            return False

    @staticmethod
    def _bucket_policy_public(client, name):
        try:
            policy = client.get_bucket_policy(Bucket=name).get("Policy", "")
        except ClientError:
            return False
        try:
            for stmt in json.loads(policy).get("Statement", []):
                principal = stmt.get("Principal")
                is_wildcard = principal == "*" or (
                    isinstance(principal, dict) and "*" in (principal.get("AWS") or []))
                actions = stmt.get("Action", [])
                actions = [actions] if isinstance(actions, str) else actions
                if is_wildcard and any(a.startswith("s3:GetObject") for a in actions):
                    return True
        except json.JSONDecodeError:
            return False
        return False

    @staticmethod
    def _bucket_public_blocked(client, name):
        try:
            conf = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            return all(conf.get(k, False) for k in (
                "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"))
        except ClientError:
            return False  # no PAB configuration at all => not blocked

    @staticmethod
    def _bucket_tags(client, name):
        try:
            tag_set = client.get_bucket_tagging(Bucket=name).get("TagSet", [])
            return {t["Key"]: t["Value"] for t in tag_set}
        except ClientError:
            return {}
