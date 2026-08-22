#!/usr/bin/env bash
# MANUAL teardown of the CloudGuardian demo stack (run after the hackathon).
# Destroys: RDS instance, security group, S3 buckets, subnet group.
set -euo pipefail
cd "$(dirname "$0")/../infra/vulnerable-stack"
echo "This will DESTROY all demo resources (RDS incl. data, SG, S3 buckets)."
read -r -p "Type DESTROY to confirm: " answer
[ "$answer" = "DESTROY" ] || { echo "aborted"; exit 1; }
terraform destroy -auto-approve
echo "Demo stack destroyed."
