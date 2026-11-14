"""Raw startup/clock guards and fixed-order composition, no engine/4d claims."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inf037b_fitness_fixture import attach
from inf037b_setup_fixture import fixture
from test_inf037b_eks_commands import shell

from inference_platform.inf037b_archive import IntegrityError, encode, strict_json
from inference_platform.inf037b_eks_setup import validate_setup_inputs
from inference_platform.inf037b_resolver import startup


class EKSSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = attach(fixture())

    def candidate(self):
        return {
            "raw": encode(self.value["bundle"]),
            "fitness_raw": self.value["fitness_raw"],
            "artifacts": self.value["artifacts"],
        }

    def sample(self):
        return {
            "clock_id": "measurement",
            "boot_id": self.value["bundle"]["raw"][0]["collector_boot_id"],
            "ms": [999999, 999999],
        }

    def validate(self, value=None, sample=None):
        return validate_setup_inputs(
            value or self.candidate(),
            self.value["binding"],
            self.sample() if sample is None else sample,
        )

    def change(self, mutate):
        value = self.candidate()
        raw = strict_json(value["raw"])
        mutate(raw)
        value["raw"] = encode(raw)
        return value

    def test_real_raw_startup_cache_lineage_and_two_restored_slots(self):
        result = self.validate()
        report = startup(result["startup"])
        self.assertEqual(report["D_bind_ms"], 90000)
        self.assertEqual(report["cases"]["cold"]["D_bind_plus_U_ms"], 300000)
        self.assertEqual(report["cases"]["node_cached"]["D_bind_plus_U_ms"], 300000)
        self.assertFalse(result["paid_ready"])

    def test_missing_lineage_and_extra_startup_refuse(self):
        with self.assertRaisesRegex(IntegrityError, "setup:lineage"):
            self.validate(self.change(lambda raw: raw["cases"][0].update(lineage=[])))
        with self.assertRaisesRegex(IntegrityError, "setup:case_order"):
            self.validate(
                self.change(lambda raw: raw["cases"].append(copy.deepcopy(raw["cases"][1])))
            )

    def test_bad_restoration_refuses(self):
        self.validate()

        def mutate(raw):
            next(
                row["payload"]
                for row in raw["raw"]
                if row["source_kind"] == "controller" and row["payload"].get("name") == "restored"
            )["value"] = False

        with self.assertRaisesRegex(IntegrityError, "setup:restoration_ack"):
            self.validate(self.change(mutate))

    def test_missing_stale_or_wrong_boot_clock_refuse(self):
        with self.assertRaisesRegex(IntegrityError, "setup_clock"):
            self.validate(sample={})
        sample = self.sample()
        sample["ms"] = [1000, 1000]
        with self.assertRaisesRegex(IntegrityError, "setup_future_source"):
            self.validate(sample=sample)
        sample = self.sample()
        sample["boot_id"] = "stale"
        with self.assertRaisesRegex(IntegrityError, "setup_clock_boot"):
            self.validate(sample=sample)
        value = self.candidate()
        fitness = strict_json(value["fitness_raw"])
        fitness["raw"] = [row for row in fitness["raw"] if row["source_kind"] != "clocks"]
        value["fitness_raw"] = encode(fitness)
        with self.assertRaisesRegex(IntegrityError, "clock|source_join"):
            self.validate(value)

    def test_d_bind_plus_startup_boundary_and_one_ms_over(self):
        self.assertEqual(
            startup(self.validate()["startup"])["cases"]["cold"]["D_bind_plus_U_ms"], 300000
        )

        def earlier_free(raw):
            row = next(
                row
                for row in raw["raw"]
                if row["source_kind"] == "kubernetes"
                and row["payload"]["event"] == "gpu_free"
                and row["payload"]["pod_uid"] == "cold-uid"
            )
            row["source_time"]["value"] -= 1

        with self.assertRaisesRegex(IntegrityError, "startup:U|D_bind_plus_U"):
            self.validate(self.change(earlier_free))

    def test_factory_sequence_shares_live_row5_and_never_repeats(self):
        with TemporaryDirectory(prefix="r337-setup-") as directory:
            f = shell(Path(directory), "http://localhost:1")
            f.config["pins"]["configuration"] = "a" * 64
            trace = []

            class Live:
                def __init__(self, **args):
                    trace.append("live")

                def row5_stage(self, name, stop):
                    trace.append(name)
                    return [{"stage": name}]

                def row5_control(self, stop, prepared):
                    trace.append("outage_restore")
                    return {"same_prepared": prepared}

            stop = 1767225601000
            binding = {"binding": f.binding}
            runtime = {
                "row5": {},
                "probe_owner": object(),
                "probe_runtime": lambda cutoff: {},
                "collect_inputs": lambda cutoff: {
                    "raw": b"{}",
                    "fitness_raw": b"{}",
                    "artifacts": {},
                },
            }
            f.implementations.update(
                {
                    "4d_device_release_observer": lambda _: binding,
                    "4d_setup_lifecycle": lambda _: binding,
                    "part2_setup_runtime": lambda _: runtime,
                    "4d_startup_observation": lambda name, receipt, cutoff: {
                        "sampler": {},
                        "owner": object(),
                        "capture_start_ns": 0,
                        "capture_stop_ns": 300000000000,
                        "collector_bundle": {},
                        "watches": {},
                        "stop_event": object(),
                    },
                    "clock_sample": lambda: {"ms": [1, 1]},
                }
            )

            def effect(name, key, body, cutoff):
                trace.append(name.removeprefix("eks.setup."))
                return {
                    "uid": "cold" if name == "cold" else "cached",
                    "slot": 0,
                    "node_uid": "same-node",
                }

            with (
                patch("inference_platform.inf037b_eks_setup.LiveRow5", Live),
                patch("inference_platform.inf037b_eks_setup.SamplerComposition") as sampler,
                patch("inference_platform.inf037b_eks_collectors.compose") as composed,
                patch(
                    "inference_platform.inf037b_eks_setup.validate_setup_inputs",
                    return_value={"paid_ready": False},
                ),
                patch("inference_platform.inf037b_eks_setup.join_cluster"),
                patch(
                    "inference_platform.inf037b_eks_setup.ClusterPorts.setup_effect",
                    side_effect=effect,
                ),
                patch.object(f, "run_setup_probe", side_effect=lambda *args: trace.append("probe")),
            ):
                ports = f(f.config)
                result = ports.gpu(stop, ports.row5_stage)
                self.assertEqual(sampler.return_value.run.call_count, 0)
                self.assertEqual(composed.return_value.run.call_count, 2)
                self.assertEqual(len(result["row5_known_requests"]), 5)
                self.assertEqual(
                    ports.row5_control(stop * 1000000, result), {"same_prepared": result}
                )
                with self.assertRaisesRegex(IntegrityError, "setup_interrupted_no_retry"):
                    ports.gpu(stop, ports.row5_stage)
            self.assertEqual(
                trace,
                [
                    "live",
                    "begin",
                    "known0",
                    "cold",
                    "known1",
                    "two_serving",
                    "known2",
                    "probe",
                    "stop_cold_and_drain",
                    "cached_stop_known1",
                    "node_cached",
                    "cached_restore_known2",
                    "outage_restore",
                ],
            )

    def test_absent_independent_device_authority_refuses_before_any_effect(self):
        with TemporaryDirectory(prefix="r337-missing-device-") as directory:
            f = shell(Path(directory), "http://localhost:1")
            ports = f(f.config)
            with patch.object(f.port, "effect") as effect:
                with self.assertRaisesRegex(IntegrityError, "unfinished:4e_device_release_inputs"):
                    ports.gpu(1767225601000, ports.row5_stage)
                effect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
