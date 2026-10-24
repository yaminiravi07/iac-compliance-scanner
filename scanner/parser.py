"""Read Terraform (.tf) files and return the resources they define."""
from pathlib import Path

import hcl2


def clean(value):
    """Tidy up what hcl2 returns so it's easy to work with.

    hcl2 keeps the quotes around strings ('"public-read"') and adds
    '__is_block__' markers. We remove both, recursively.
    """
    if isinstance(value, dict):
        return {clean(k): clean(v) for k, v in value.items() if k != "__is_block__"}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def load_resources(path):
    """Parse every .tf file in `path` (a file or a folder) and return a list of resources.

    Each resource is a dict:
        {"type": "aws_s3_bucket", "name": "logs", "config": {...}, "file": "main.tf"}
    """
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.rglob("*.tf"))

    resources = []
    for tf_file in files:
        with open(tf_file, encoding="utf-8") as f:
            data = clean(hcl2.load(f))

        # data looks like: {"resource": [ {"aws_s3_bucket": {"logs": {...}}}, ... ]}
        for block in data.get("resource", []):
            for resource_type, instances in block.items():
                for name, config in instances.items():
                    resources.append({
                        "type": resource_type,
                        "name": name,
                        "config": config,
                        "file": tf_file.name,
                    })
    return resources