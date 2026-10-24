"""Security rules. Each rule checks one resource and returns a list of findings."""
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


def check_s3_public_acl(r):
    """S3 bucket must not be readable or writable by everyone."""
    if r["type"] != "aws_s3_bucket":
        return []
    if r["config"].get("acl") in ("public-read", "public-read-write"):
        return [Finding(
            rule_id="S3-001",
            severity="HIGH",
            resource=f"{r['type']}.{r['name']}",
            file=r["file"],
            message=f"Bucket ACL is '{r['config']['acl']}' - anyone on the internet can read it",
            iso27001="A.8.3 Information access restriction",
            bsi="OPS.2.2 Cloud-Nutzung",
        )]
    return []


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
                findings.append(Finding(
                    rule_id="NET-001",
                    severity="HIGH",
                    resource=f"{r['type']}.{r['name']}",
                    file=r["file"],
                    message=f"{name} (port {port}) is open to 0.0.0.0/0 (the whole internet)",
                    iso27001="A.8.20 Networks security",
                    bsi="NET.1.1 Netzarchitektur und -design",
                ))
    return findings


def check_rds_encryption(r):
    """Databases must be encrypted at rest."""
    if r["type"] != "aws_db_instance":
        return []
    if not r["config"].get("storage_encrypted", False):
        return [Finding(
            rule_id="DB-001",
            severity="HIGH",
            resource=f"{r['type']}.{r['name']}",
            file=r["file"],
            message="Database storage is not encrypted at rest",
            iso27001="A.8.24 Use of cryptography",
            bsi="CON.1 Kryptokonzept",
        )]
    return []


def check_rds_public(r):
    """Databases must not be reachable from the internet."""
    if r["type"] != "aws_db_instance":
        return []
    if r["config"].get("publicly_accessible", False):
        return [Finding(
            rule_id="DB-002",
            severity="HIGH",
            resource=f"{r['type']}.{r['name']}",
            file=r["file"],
            message="Database is publicly accessible from the internet",
            iso27001="A.8.20 Networks security",
            bsi="NET.1.1 Netzarchitektur und -design",
        )]
    return []


# The list of all rules. To add a rule: write a function above, then add it here.
ALL_RULES = [
    check_s3_public_acl,
    check_sg_open_admin_ports,
    check_rds_encryption,
    check_rds_public,
]


def run_rules(resources):
    """Run every rule against every resource and collect the findings."""
    findings = []
    for resource in resources:
        for rule in ALL_RULES:
            findings.extend(rule(resource))
    return findings