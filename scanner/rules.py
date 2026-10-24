"""Security rules. Each rule checks one resource and returns a list of findings."""
import re
from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    severity: str      # HIGH, MEDIUM or LOW
    resource: str      # e.g. "aws_s3_bucket.logs"
    file: str
    message: str
    iso27001: str      # ISO/IEC 27001:2022 Annex A control
    bsi: str           # BSI IT-Grundschutz module


# ISO 27001:2022 Annex A controls and BSI IT-Grundschutz modules we use
ISO_ACCESS = "A.8.3 Information access restriction"
ISO_PRIVILEGED = "A.8.2 Privileged access rights"
ISO_NETWORK = "A.8.20 Networks security"
ISO_CRYPTO = "A.8.24 Use of cryptography"
ISO_BACKUP = "A.8.13 Information backup"
ISO_LOGGING = "A.8.15 Logging"
ISO_MONITORING = "A.8.16 Monitoring activities"

BSI_CLOUD = "OPS.2.2 Cloud-Nutzung"
BSI_NETWORK = "NET.1.1 Netzarchitektur und -design"
BSI_CRYPTO = "CON.1 Kryptokonzept"
BSI_BACKUP = "CON.3 Datensicherungskonzept"
BSI_LOGGING = "OPS.1.1.5 Protokollierung"
BSI_IAM = "ORP.4 Identitäts- und Berechtigungsmanagement"


def finding(r, rule_id, severity, message, iso27001, bsi):
    """Helper so each rule doesn't have to repeat resource name and file."""
    return Finding(rule_id, severity, f"{r['type']}.{r['name']}", r["file"],
                   message, iso27001, bsi)


# ---------------- Access control ----------------

def check_s3_public_acl(r):
    """S3 bucket must not be readable or writable by everyone."""
    if r["type"] == "aws_s3_bucket" and r["config"].get("acl") in ("public-read", "public-read-write"):
        return [finding(r, "S3-001", "HIGH",
                        f"Bucket ACL is '{r['config']['acl']}' - anyone on the internet can read it",
                        ISO_ACCESS, BSI_CLOUD)]
    return []


IAM_POLICY_TYPES = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy")
WILDCARD_ACTION = re.compile(r'"?Action"?\s*[:=]\s*\[?\s*"\*"')


def check_iam_wildcard_action(r):
    """IAM policies must not allow every action ("Action": "*")."""
    if r["type"] in IAM_POLICY_TYPES and WILDCARD_ACTION.search(str(r["config"].get("policy", ""))):
        return [finding(r, "IAM-001", "HIGH",
                        "Policy allows all actions (\"Action\": \"*\") - full admin rights",
                        ISO_PRIVILEGED, BSI_IAM)]
    return []


# ---------------- Network ----------------

def check_sg_open_admin_ports(r):
    """Security groups must not open SSH (22) or RDP (3389) to the whole internet."""
    if r["type"] != "aws_security_group":
        return []
    findings = []
    for rule in r["config"].get("ingress", []):
        open_to_world = "0.0.0.0/0" in rule.get("cidr_blocks", [])
        from_port, to_port = rule.get("from_port", 0), rule.get("to_port", 0)
        for port, name in ((22, "SSH"), (3389, "RDP")):
            if open_to_world and from_port <= port <= to_port:
                findings.append(finding(r, "NET-001", "HIGH",
                                        f"{name} (port {port}) is open to 0.0.0.0/0 (the whole internet)",
                                        ISO_NETWORK, BSI_NETWORK))
    return findings


def check_rds_public(r):
    """Databases must not be reachable from the internet."""
    if r["type"] == "aws_db_instance" and r["config"].get("publicly_accessible", False):
        return [finding(r, "DB-002", "HIGH", "Database is publicly accessible from the internet",
                        ISO_NETWORK, BSI_NETWORK)]
    return []


# ---------------- Encryption ----------------

def check_rds_encryption(r):
    """Databases must be encrypted at rest."""
    if r["type"] == "aws_db_instance" and not r["config"].get("storage_encrypted", False):
        return [finding(r, "DB-001", "HIGH", "Database storage is not encrypted at rest",
                        ISO_CRYPTO, BSI_CRYPTO)]
    return []


def check_sns_encryption(r):
    """SNS topics should be encrypted with a KMS key."""
    if r["type"] == "aws_sns_topic" and not r["config"].get("kms_master_key_id"):
        return [finding(r, "SNS-001", "MEDIUM", "SNS topic is not encrypted with a KMS key",
                        ISO_CRYPTO, BSI_CRYPTO)]
    return []


# ---------------- Backup ----------------

def check_dynamodb_pitr(r):
    """DynamoDB tables should have point-in-time recovery (continuous backups)."""
    if r["type"] != "aws_dynamodb_table":
        return []
    pitr = r["config"].get("point_in_time_recovery", [])
    if not (pitr and pitr[0].get("enabled")):
        return [finding(r, "DDB-001", "MEDIUM", "Point-in-time recovery (backup) is not enabled",
                        ISO_BACKUP, BSI_BACKUP)]
    return []


# ---------------- Logging & monitoring ----------------

def check_apigw_access_logs(r):
    """API Gateway stages should write access logs."""
    if r["type"] in ("aws_apigatewayv2_stage", "aws_api_gateway_stage") \
            and not r["config"].get("access_log_settings"):
        return [finding(r, "API-001", "MEDIUM", "API stage has no access logging",
                        ISO_LOGGING, BSI_LOGGING)]
    return []


def check_log_retention(r):
    """CloudWatch log groups should define how long logs are kept."""
    if r["type"] == "aws_cloudwatch_log_group" and not r["config"].get("retention_in_days"):
        return [finding(r, "LOG-001", "LOW", "Log group has no retention period set",
                        ISO_LOGGING, BSI_LOGGING)]
    return []


def check_lambda_tracing(r):
    """Lambda functions should have X-Ray tracing for monitoring."""
    if r["type"] != "aws_lambda_function":
        return []
    tracing = r["config"].get("tracing_config", [])
    if not (tracing and tracing[0].get("mode") == "Active"):
        return [finding(r, "LAM-001", "LOW", "Lambda X-Ray tracing is not active",
                        ISO_MONITORING, BSI_LOGGING)]
    return []


# The list of all rules. To add a rule: write a function above, then add it here.
ALL_RULES = [
    check_s3_public_acl,
    check_iam_wildcard_action,
    check_sg_open_admin_ports,
    check_rds_public,
    check_rds_encryption,
    check_sns_encryption,
    check_dynamodb_pitr,
    check_apigw_access_logs,
    check_log_retention,
    check_lambda_tracing,
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_rules(resources):
    """Run every rule against every resource; return findings sorted HIGH -> LOW."""
    findings = []
    for resource in resources:
        for rule in ALL_RULES:
            findings.extend(rule(resource))
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])