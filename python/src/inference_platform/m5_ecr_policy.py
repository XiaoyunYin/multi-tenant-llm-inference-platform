"""Derive the routine writer's ECR permissions from the real zone operator policy."""

import json
import re


def operator_ecr_actions(source):
    # The routine writer uses the original M5 repository. Its policy is
    # the false branch when the composed root also supports the CPU clock.
    source = re.sub(
        r"(?ms)^(\s*policy\s*=\s*)var\.cpu_clock_rehearsal\s*\?\s*"
        r"jsonencode\(\{.*?^\s*\]\s*\}\)\s*:\s*(?=jsonencode\(\{)",
        r"\1",
        source,
    )
    result = {}
    for actions, resource in re.findall(
        r'\{\s*Effect\s*=\s*"Allow",\s*Action\s*=\s*(\[[^\]]+\]),\s*Resource\s*=\s*([^}]+)\}',
        source,
    ):
        values = [x for x in json.loads(actions) if x.startswith("ecr:")]
        if not values:
            continue
        if resource.strip() == '"*"' and values == ["ecr:GetAuthorizationToken"]:
            key = "ecr_token_actions"
        elif resource.strip() == "module.eks.repository_arn" and all("*" not in x for x in values):
            key = "ecr_repository_actions"
        else:
            raise ValueError("routine:ecr_policy_scope")
        if key in result:
            raise ValueError("routine:ecr_policy_ambiguous")
        result[key] = values
    if set(result) != {"ecr_token_actions", "ecr_repository_actions"}:
        raise ValueError("routine:ecr_policy_missing")
    return result
