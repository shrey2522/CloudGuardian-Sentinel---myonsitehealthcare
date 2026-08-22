# CloudGuardian Sentinel

# CloudGuardian Sentinel

Title:
CloudGuardian Sentinel

Background:
In cloud-native environments, misconfigurations in infrastructure-as-code (IaC) templates frequently lead to security vulnerabilities and compliance violations. These issues often go undetected until runtime, causing costly outages or breaches. With increasing adoption of multi-cloud and hybrid architectures, real-time detection and automated remediation are critical.

Problem Statement:
A startup deploys a new microservice stack across AWS and GCP using Terraform. During a routine audit, the security team discovers that a critical database instance was exposed to public internet access due to a misconfigured security group. The team lacks a system to detect such misconfigurations in real time and enforce fixes automatically. With only 6 hours until the next production deployment window, they need a system that continuously monitors IaC templates and cloud resources, identifies risky configurations, and triggers remediation actions before deployment.

Scope:
Develop a real-time monitoring and remediation system for IaC templates and cloud resource configurations. The system must detect misconfigurations, generate alerts, and apply fixes automatically. It should support AWS and GCP, integrate with CI/CD pipelines, and provide audit trails. The solution must be cloud-native and scalable.

MVP Scope:
• Implement a cloud-based monitoring service that polls AWS and GCP resource configurations every 30 seconds.
• Detect and flag misconfigurations (e.g., public-facing databases, unencrypted storage) using predefined rules.
• Trigger automated remediation via infrastructure-as-code (Terraform) to fix at least one high-risk misconfiguration.
• Log all detection and remediation events to a centralized audit trail.
• Demonstrate the system in a CI/CD pipeline that blocks deployment if remediation fails.

Advanced/Bonus Scope:
• Support additional cloud providers (Azure) and expand detection rules to include IAM policy violations.
• Implement a dashboard showing risk heatmaps across environments.
• Add a rollback mechanism to revert changes if remediation causes unintended side effects.

Functional Requirements:
- Monitor AWS and GCP cloud resources for security and compliance violations.
- Detect at least three predefined misconfigurations (e.g., public database, open SSH port).
- Trigger automated remediation using Terraform apply commands.
- Log all detection and remediation events with timestamps and user context.
- Integrate with a CI/CD pipeline to block deployments until remediation is complete.
- Provide a command-line interface to simulate and test remediation workflows.
- Support configuration of detection rules via a YAML-based rule engine.

Non-Functional Requirements:
- System must detect and remediate within 60 seconds of configuration change.
- Audit trail must be stored for at least 24 hours with no data loss.
- Remediation process must be idempotent and safe to retry.
- System must handle at least 5 concurrent cloud resource checks per minute.
- All components must be deployable via infrastructure-as-code (Terraform or Pulumi).

Constraints:
- All components must be built and deployed within 6 hours.
- No use of pre-built commercial security tools or third-party SaaS platforms.
- System must be fully cloud-native (no on-premise or hybrid components).
- Only AWS and GCP cloud providers are supported in MVP.
- All remediation actions must be reversible via a rollback command.
- No manual intervention allowed during CI/CD pipeline execution.

Deliverables:
- Deployed cloud monitoring service with real-time detection.
- Working CI/CD pipeline that blocks deployment on misconfigurations.
- Automated remediation script that fixes at least one misconfiguration.
- Audit trail showing detection and remediation events.
- Demo video showing end-to-end workflow in 6 hours.
