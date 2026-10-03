import json
import unittest
from pathlib import Path

from inference_platform.stage_c_sizing import check_sizing


class SizingTest(unittest.TestCase):
    def test_round29_fails_and_proposal_brackets_capacity(self):
        root = Path(__file__).resolve().parents[2]
        old = json.loads(
            (root / "docs/evidence/round29-workload-sizing.json").read_text(encoding="utf-8")
        )
        proposed = json.loads(
            (root / "docs/INF011_STAGE_C_R0_PROPOSAL.json").read_text(encoding="utf-8")
        )
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        failed = check_sizing(old, launcher=launcher)
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(failed["maximum_active_prompt_kv_tokens"], 32768)
        self.assertEqual(failed["reference_corpora"][-1]["prompt_blocks"], 864)
        passed = check_sizing(proposed["workload_sizing"], launcher=launcher)
        self.assertEqual(passed["status"], "pass")
        self.assertEqual(passed["maximum_active_prompt_kv_tokens"], 98304)
        self.assertEqual(
            [r["blocks"] for r in passed["reference_corpora"]],
            [2048, 3072, 3584, 3840, 4352, 4864, 5888],
        )
        shallow = {**proposed["workload_sizing"], "saturation_levels": [1, 2, 4]}
        self.assertEqual(check_sizing(shallow)["status"], "fail")
        self.assertEqual(
            check_sizing(
                proposed["workload_sizing"],
                launcher=launcher.replace("--max-num-seqs 16", "--max-num-seqs 4"),
            )["status"],
            "fail",
        )

    def test_decode_blocks_and_prefill_only_exception(self):
        root = Path(__file__).resolve().parents[2]
        inputs = json.loads(
            (root / "docs/INF011_STAGE_C_R0_PROPOSAL.json").read_text(encoding="utf-8")
        )["workload_sizing"]
        baseline = check_sizing(inputs)
        generated = check_sizing({**inputs, "reference_max_tokens": 128})
        self.assertEqual(baseline["reference_decode_blocks_per_request"], 0)
        self.assertEqual(generated["reference_decode_blocks_per_request"], 8)
        for base, full in zip(
            baseline["reference_corpora"], generated["reference_corpora"], strict=True
        ):
            self.assertEqual(full["blocks"] - base["blocks"], 8 * base["prefixes"])
        self.assertEqual(
            check_sizing({**inputs, "reference_max_tokens": 17})[
                "reference_decode_blocks_per_request"
            ],
            2,
        )
        self.assertEqual(
            check_sizing({**inputs, "reference_run_budget_seconds": 100})["status"], "fail"
        )
