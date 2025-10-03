import sys
import os
import csv
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError


# ---------- Utility & identity ----------

def _utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_identity_stamp():
    """Return account id, caller arn, and a UTC ISO timestamp."""
    sts = boto3.client("sts")
    resp = sts.get_caller_identity()
    account_id = resp.get("Account")
    caller_arn = resp.get("Arn")
    return {"account_id": account_id, "caller_arn": caller_arn, "timestamp": _utc_now_iso()}


# ---------- Inventory helpers ----------

def iter_roles():
    """Yield IAM role dicts using a paginator (read-only)."""
    iam = boto3.client("iam")
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            yield role


def get_attached_managed_policies(role_name: str):
    """Return a list of attached managed policies for a role: [{PolicyName, PolicyArn}]"""
    iam = boto3.client("iam")
    resp = iam.list_attached_role_policies(RoleName=role_name)
    return resp.get("AttachedPolicies", [])


def get_inline_policies(role_name: str):
    """Return a list of inline policy names for a role."""
    iam = boto3.client("iam")
    resp = iam.list_role_policies(RoleName=role_name)
    return resp.get("PolicyNames", [])


def get_role_trust_policy(role_name: str):
    """Return the AssumeRolePolicyDocument (trust policy) for the role."""
    iam = boto3.client("iam")
    resp = iam.get_role(RoleName=role_name)
    return resp["Role"].get("AssumeRolePolicyDocument", {})


# ---------- Policy document fetch ----------

def get_managed_policy_document(policy_arn: str):
    """Return the JSON Document of the default version for a managed policy."""
    iam = boto3.client("iam")
    pol = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    ver_id = pol["DefaultVersionId"]
    doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=ver_id)["PolicyVersion"]["Document"]
    return doc


def get_inline_policy_document(role_name: str, policy_name: str):
    """Return the JSON Document of an inline policy attached to a role."""
    iam = boto3.client("iam")
    resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    return resp["PolicyDocument"]


# ---------- Simple analyzers ----------

def _to_list(val):
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def find_wildcards_in_policy(doc: dict):
    """
    Yield simple findings from a policy document:
    - WILDCARD_ACTION: Action="*" or service:*
    - RESOURCE_STAR:   Resource="*"
    Each item -> {"type","statement","actions","resources"}
    """
    for idx, stmt in enumerate(_to_list(doc.get("Statement")), start=1):
        actions = _to_list(stmt.get("Action"))
        resources = _to_list(stmt.get("Resource"))

        action_wild = any(a == "*" or (isinstance(a, str) and a.endswith(":*")) for a in actions)
        resource_star = any(r == "*" for r in resources)

        if action_wild:
            yield {"type": "WILDCARD_ACTION", "statement": idx, "actions": actions, "resources": resources}
        if resource_star:
            yield {"type": "RESOURCE_STAR", "statement": idx, "actions": actions, "resources": resources}


def trust_has_wildcard_principal(trust_doc: dict) -> bool:
    """
    Return True if any trust policy statement has Principal="*".
    (A simple, strong signal; we’ll keep it minimal for v1.)
    """
    for stmt in _to_list(trust_doc.get("Statement")):
        p = stmt.get("Principal", {})
        # Principal can be string "*" or dict with keys like "AWS","Service","Federated"
        if isinstance(p, str):
            if p == "*":
                return True
        elif isinstance(p, dict):
            for _, v in p.items():
                if (isinstance(v, str) and v == "*") or (isinstance(v, list) and "*" in v):
                    return True
    return False


# ---------- Evidence writers ----------

CSV_COLUMNS = [
    "AccountId", "EntityType", "EntityName",
    "Finding", "Severity", "Details", "Recommendation",
    "ControlMapping", "Timestamp"
]

CONTROL_MAPPING = "SOC2 CC6.1; ISO 27001 A.5.15"


def ensure_evidence_dir():
    os.makedirs("evidence", exist_ok=True)


def write_csv_findings(path: str, rows: list[dict]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_markdown_report(path: str, identity: dict, rows: list[dict]):
    # summary counts
    high = sum(1 for r in rows if r["Severity"] == "High")
    med = sum(1 for r in rows if r["Severity"] == "Medium")
    low = sum(1 for r in rows if r["Severity"] == "Low")

    lines = []
    lines.append(f"# IAM Least-Privilege Evidence Report")
    lines.append("")
    lines.append(f"**Account:** `{identity['account_id']}`  ")
    lines.append(f"**Caller:** `{identity['caller_arn']}`  ")
    lines.append(f"**Timestamp:** `{identity['timestamp']}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Total Findings: **{len(rows)}** (High: **{high}**, Medium: **{med}**, Low: **{low}**)")
    lines.append("")
    lines.append("## Findings (brief)")
    if not rows:
        lines.append("- No findings.")
    else:
        for r in rows:
            lines.append(f"- **{r['Severity']}** — {r['EntityType']} `{r['EntityName']}` — {r['Finding']}: {r['Details']}  ")
            lines.append(f"  - Recommendation: {r['Recommendation']}  ")
            lines.append(f"  - Controls: {r['ControlMapping']}")
    lines.append("")
    lines.append("## Methodology")
    lines.append("- Enumerated IAM roles and fetched attached + inline policy documents (read-only).")
    lines.append("- Checked for `Action:*` / `service:*` and `Resource:*` in policy statements.")
    lines.append("- Checked trust policy for `Principal:\"*\"`.")
    lines.append("- Mapped findings to SOC2/ISO least-privilege controls for audit traceability.")
    lines.append("")
    lines.append("_This report is generated automatically and is intended as starting evidence; human review recommended._")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------- Main scan ----------

def main():
    try:
        identity = get_identity_stamp()
        print("=== IAM Least-Privilege Evidence — Scan ===")
        print(f"Account:   {identity['account_id']}")
        print(f"Caller:    {identity['caller_arn']}")
        print(f"Timestamp: {identity['timestamp']}")
        print("--------------------------------------------")

        # Inventory roles
        print("Scanning IAM roles (read-only)...")
        roles = list(iter_roles())
        print(f"Total roles found: {len(roles)}")

        # Collect findings across ALL roles
        findings_rows: list[dict] = []
        for r in roles:
            role_name = r.get("RoleName")

            # Attached managed policies
            attached = get_attached_managed_policies(role_name)
            for p in attached:
                policy_name = p["PolicyName"]
                policy_arn = p["PolicyArn"]
                try:
                    doc = get_managed_policy_document(policy_arn)
                    for f in find_wildcards_in_policy(doc):
                        # Simple severity: both? High; otherwise Medium
                        sev = "High" if (f["type"] == "WILDCARD_ACTION" and any(res == "*" for res in f["resources"])) else "Medium"
                        details = f"{f['type']} in statement {f['statement']} (policy={policy_name})"
                        findings_rows.append({
                            "AccountId": identity["account_id"],
                            "EntityType": "Role",
                            "EntityName": role_name,
                            "Finding": f["type"],
                            "Severity": sev,
                            "Details": details,
                            "Recommendation": "Replace wildcards with specific actions and resources (ARNs).",
                            "ControlMapping": CONTROL_MAPPING,
                            "Timestamp": _utc_now_iso(),
                        })
                except ClientError as ce:
                    # Non-fatal; skip with a note in console
                    print(f"(skip) Could not fetch managed policy doc {policy_name}: {ce}")

            # Inline policies
            inline_names = get_inline_policies(role_name)
            for name in inline_names:
                try:
                    doc = get_inline_policy_document(role_name, name)
                    for f in find_wildcards_in_policy(doc):
                        sev = "High" if (f["type"] == "WILDCARD_ACTION" and any(res == "*" for res in f["resources"])) else "Medium"
                        details = f"{f['type']} in statement {f['statement']} (inline={name})"
                        findings_rows.append({
                            "AccountId": identity["account_id"],
                            "EntityType": "Role",
                            "EntityName": role_name,
                            "Finding": f["type"],
                            "Severity": sev,
                            "Details": details,
                            "Recommendation": "Replace wildcards with specific actions and resources (ARNs).",
                            "ControlMapping": CONTROL_MAPPING,
                            "Timestamp": _utc_now_iso(),
                        })
                except ClientError as ce:
                    print(f"(skip) Could not fetch inline policy doc {name}: {ce}")

            # Trust policy (basic)
            trust = get_role_trust_policy(role_name)
            if trust_has_wildcard_principal(trust):
                findings_rows.append({
                    "AccountId": identity["account_id"],
                    "EntityType": "Role",
                    "EntityName": role_name,
                    "Finding": "TRUST_WILDCARD_PRINCIPAL",
                    "Severity": "High",
                    "Details": "Trust policy allows Principal:\"*\"",
                    "Recommendation": "Limit Principal to specific accounts/services; avoid wildcard trust.",
                    "ControlMapping": CONTROL_MAPPING,
                    "Timestamp": _utc_now_iso(),
                })

        # Ensure evidence folder, then write artifacts
        ensure_evidence_dir()
        ts_for_name = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        csv_path = os.path.join("evidence", f"iam_least_priv_findings-{ts_for_name}.csv")
        md_path = os.path.join("evidence", f"iam_least_priv_report-{ts_for_name}.md")

        write_csv_findings(csv_path, findings_rows)
        write_markdown_report(md_path, identity, findings_rows)

        print("--------------------------------------------")
        print("Success: Evidence artifacts written.")
        print(f"CSV: {csv_path}")
        print(f"MD : {md_path}")
        return 0

    except ClientError as ce:
        print("AWS ClientError during scan.", file=sys.stderr)
        print(f"Details: {ce}", file=sys.stderr)
        return 1
    except Exception as e:
        print("Unexpected error during scan.", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())