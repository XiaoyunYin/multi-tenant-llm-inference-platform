"""Delegated INF-057 filing after otherwise-ready preparation; never Apply."""

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = json.loads(args.refresh.read_bytes())
    if not summary["estimate_fits"] or not summary["below_150_checkpoint"] or summary["unexpected_project_instances"]:
        raise ValueError("exact preparation cost/inventory halt; no quota request")
    if args.output.exists():
        raise ValueError("retain existing quota receipt; do not overwrite/re-file")

    def aws(operation, *argv):
        return json.loads(subprocess.check_output(["aws", "--profile", summary["aws_profile"],
            "--region", summary["region"], "service-quotas", operation, *argv,
            "--output", "json", "--no-cli-pager"], timeout=60))

    # Always refresh history immediately before submission, not just reuse the
    # earlier read-only snapshot. AWS serializes pending requests for the quota.
    history = aws("list-requested-service-quota-change-history-by-quota", "--service-code", "ec2",
                  "--quota-code", "L-DB2E81BA")["RequestedQuotas"]
    matching = [x for x in history if x["DesiredValue"] >= 48]
    current = aws("get-service-quota", "--service-code", "ec2", "--quota-code", "L-DB2E81BA")["Quota"]["Value"]
    if current >= 48:
        requested, disposition = None, "already_granted_no_duplicate"
    elif any(x["Status"] in {"PENDING", "CASE_OPENED", "APPROVED"} for x in matching):
        requested = next(x for x in matching if x["Status"] in {"PENDING", "CASE_OPENED", "APPROVED"})
        disposition = "existing_request_no_duplicate"
    elif matching:
        raise ValueError("prior >=48 request closed/denied without quota; DEC-041 halt, no re-file")
    else:
        requested = aws("request-service-quota-increase", "--service-code", "ec2", "--quota-code",
                        "L-DB2E81BA", "--desired-value", "48")["RequestedQuota"]
        disposition = "submitted_once"
    allowed = {"Id", "CaseId", "DesiredValue", "Status", "Created", "LastUpdated", "ServiceCode", "QuotaCode"}
    receipt = {"schema": "inf057-delegated-request.v1", "region": summary["region"], "quota_code": "L-DB2E81BA",
               "desired_value": 48, "current_quota": current, "disposition": disposition,
               "recorded_at": dt.datetime.now(dt.UTC).isoformat(),
               "authorization": "Xiaoyun current Round88 task / DEC-041 item3 / DEC-051 procedural record",
               "otherwise_ready_basis": "committed production lifecycle;16 no-AWS cases; native staging/export; fresh cap/usage fit",
               "request": {k:v for k,v in requested.items() if k in allowed} if requested else None,
               "history_before": [{k:v for k,v in x.items() if k in allowed} for x in history],
               "pending_grants_no_capacity": True,
               "justification": "INF-057 approved g6.12xlarge four-L4 hardware shape in us-east-1 requires48 G/VT vCPUs; experiments use two GPUs. Current R1 is two g6.xlarge (8 G/VT vCPUs), with no overlap. No spot, region/shape substitution or new scope. Quota denial halts future paid work under DEC-041."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"disposition": disposition, "request": receipt["request"], "current_quota": current}))


if __name__ == "__main__":
    main()
