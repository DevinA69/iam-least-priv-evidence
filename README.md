# IAM Least-Privilege Evidence Automation

## Overview
Automates AWS IAM least-privilege evidence collection. Instead of screenshots, this tool generates **timestamped CSV + Markdown** reports that auditors can review and engineers can act on.

**What it does**
- Prints an identity stamp (AWS **Account ID**, **Caller ARN**, **UTC Timestamp**).
- Inventories **all IAM roles**.
- Fetches **attached managed** and **inline** policy documents.
- Flags risky patterns:
  - `Action: "*" or "service:*"` (**wildcard actions**)
  - `Resource: "*"` (**resource star**)
  - Trust policy with `Principal: "*"` (**wildcard trust**)
- Writes audit-ready **CSV** findings and a human-friendly **Markdown** report under `evidence/`.

## Why it matters (GRC / Audit)
- Repeatable, timestamped artifacts (no screenshots).
- Clear mapping to least-privilege controls:
  - **SOC 2**: CC6.1, CC6.6
  - **ISO 27001**: A.5.15 (Least Privilege), A.5.18 (Access Rights)

## Repo Structure
scripts/collect_iam_least_priv_evidence.py # main script (read-only AWS calls)
evidence/ # generated reports (gitignored)
requirements.txt
.gitignore
README.md


## Prereqs
- Python 3.x + virtual environment
- AWS CLI credentials configured (read-only IAM permissions are sufficient):
  - `sts:GetCallerIdentity`
  - `iam:ListRoles`
  - `iam:ListAttachedRolePolicies`
  - `iam:ListRolePolicies`
  - `iam:GetRole`, `iam:GetRolePolicy`
  - `iam:GetPolicy`, `iam:GetPolicyVersion`

Install deps:
```bash
pip install -r requirements.txt

## How to Run
python scripts/collect_iam_least_priv_evidence.py

## Example output
Success: Evidence artifacts written.
CSV: evidence/iam_least_priv_findings-YYYYMMDD-HHMMSS.csv
MD : evidence/iam_least_priv_report-YYYYMMDD-HHMMSS.md

## Sample Finding (console)
[!] Findings in managed policy AWSConfigServiceRolePolicy:
    - RESOURCE_STAR (stmt 1)

## How it works (high level)

1. Identity Stamp via STS get_caller_identity.

2. Role Inventory via IAM list_roles (paginator).

3. Policy Docs

Managed: get_policy → get_policy_version.

Inline: get_role_policy.

4. Checks

Wildcard actions (* or service:*) and resource star (*).

Trust policy wildcard Principal.

5. Evidence Writers

CSV rows: AccountId, EntityType, EntityName, Finding, Severity, Details, Recommendation, ControlMapping, Timestamp.

Markdown report with executive summary + methodology.

## Notes / Safety

The script is read-only (List/Get APIs).

Findings are conservative signals for least privilege. Human review recommended.
