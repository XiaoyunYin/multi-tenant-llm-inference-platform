"""R389 executed arguments and engine reports; all transports are local fixtures."""

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import inf037b_engine_fixture as engine_fixture
from inf037b_engine_fixture import cache_labels, pod

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_live import (
    KubernetesAdapter,
    LifecycleReceiptProducer,
    LiveRows,
    VLLMAdapter,
)


class ArchivedFixtureTests(unittest.TestCase):
    def test_public_primary_fixture_keeps_the_original_archived_label_bytes(self):
        cache_labels.cache_clear()
        self.addCleanup(cache_labels.cache_clear)
        self.assertEqual(
            hashlib.sha256(cache_labels().encode()).hexdigest(),
            "a3467708a4699118e2cf3662c474e0f166b01cef5d0884b38f80fd240d8c6a07",
        )

    def test_changed_primary_fixture_refuses_before_labels_are_used(self):
        cache_labels.cache_clear()
        self.addCleanup(cache_labels.cache_clear)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "experiments/r0/attempt7/run-1.digest.json.gz"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"changed archive")
            with patch.object(engine_fixture, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "fixture:archived_cache_source"):
                    cache_labels()


class KubernetesEngineTests(unittest.TestCase):
    def adapter(self):
        return KubernetesAdapter(
            LiveRows("test", "collector"),
            None,
            "test",
            slot_names={"vllm-0": 0},
            lifecycle=LifecycleReceiptProducer(),
        )

    def test_first_running_object_retains_exact_arguments_and_resource_version(self):
        obj, adapter = pod(), self.adapter()
        (row,) = adapter.pod_observations(obj)
        p, container = row["payload"], obj["spec"]["containers"][0]
        self.assertEqual(p["engine_args"], container["args"])
        self.assertEqual(p["engine_command"], container["command"])
        self.assertEqual(p["engine_flags"]["--max-num-seqs"], "16")
        self.assertIs(p["engine_flags"]["--enable-prefix-caching"], True)
        self.assertEqual(
            p["engine_argv_sha256"],
            sha(encode({"command": container["command"], "args": container["args"]})),
        )
        self.assertEqual((p["pod_uid"], p["resource_version"]), ("uid0", "17"))
        self.assertEqual(adapter.pod_observations(obj), [])
        obj["spec"]["containers"][0]["args"].append("--later-change")
        self.assertNotIn("--later-change", p["engine_args"])

    def test_invalid_and_duplicate_arguments_refuse(self):
        for args in (["positional"], ["--x", "1", "--x", "2"], ["--x", None]):
            obj = pod()
            obj["spec"]["containers"][0]["args"] = copy.deepcopy(args)
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.adapter().pod_observations(obj)

    def test_missing_command_is_not_inferred_from_image(self):
        obj = pod()
        del obj["spec"]["containers"][0]["command"]
        with self.assertRaises(KeyError):
            self.adapter().pod_observations(obj)

    def test_running_sidecar_cannot_supply_the_engine_observation(self):
        obj = pod()
        sidecar = copy.deepcopy(obj["status"]["containerStatuses"][0])
        sidecar.update(name="sidecar", imageID="sha256:" + "f" * 64)
        engine = obj["status"]["containerStatuses"][0]
        engine["state"] = {"waiting": {}}
        obj["status"]["containerStatuses"].append(sidecar)
        adapter = self.adapter()
        self.assertEqual(adapter.pod_observations(obj), [])
        engine["state"] = {"running": {}}
        (row,) = adapter.pod_observations(obj)
        self.assertEqual(row["payload"]["container_id"], "containerd://engine0")
        self.assertEqual(row["payload"]["image_sha256"], "a" * 64)


class EngineReportTests(unittest.TestCase):
    def adapter(self, *, metrics=None, models=None, during=None):
        lifecycle = LifecycleReceiptProducer()
        lifecycle.created("uid0", 0)
        lifecycle.ingest(
            {
                "pod_uid": "uid0",
                "sequence": 0,
                "boot_id": "process0",
                "mono_ns": 0,
                "event": "supervisor_start",
            }
        )
        metric = ("vllm:cache_config_info{" + cache_labels() + "} 1\n").encode()
        calls, captured = [], []

        class Native:
            def get(self, path):
                calls.append(path)
                if during:
                    during(lifecycle, path)
                return (
                    (metrics if metrics is not None else metric, {})
                    if path == "/metrics"
                    else (
                        encode(
                            models if models is not None else {"data": [{"max_model_len": 8192}]}
                        ),
                        {},
                    )
                )

        adapter = VLLMAdapter(
            LiveRows("test", "collector", sink=captured.append),
            Native(),
            pod_uid="uid0",
            slot=0,
            process_generation="process0",
            model_sha256="a" * 64,
            runtime_sha256="b" * 64,
            semantics_sha256="c" * 64,
            lifecycle=lifecycle,
        )
        return adapter, lifecycle, calls, captured

    def test_exact_archived_labels_models_and_single_emission(self):
        adapter, _, calls, captured = self.adapter()
        row = adapter.engine_config()
        self.assertIsNone(row["error"])
        self.assertEqual(row["payload"]["cache_config_labels"]["num_gpu_blocks"], "3891")
        self.assertEqual(row["payload"]["max_model_len"], 8192)
        self.assertEqual(row["payload"]["process_generation"], "process0")
        self.assertIsNone(adapter.engine_config())
        self.assertEqual(calls, ["/metrics", "/v1/models"])
        self.assertEqual(captured, [row])

    def test_failed_then_serving_sample_emits_the_serving_engine_config(self):
        from inference_platform.inf037b_live import METRICS

        adapter, lifecycle, _, captured = self.adapter()
        metric = ("vllm:cache_config_info{" + cache_labels() + "} 1\n").encode()
        metrics = metric + "".join(f"{name} 0\n" for name in METRICS.values()).encode()

        class RefusesThenServes:
            serving = False

            def get(self, path):
                if not self.serving:
                    raise OSError("connection_refused")
                if path == "/v1/models":
                    return encode({"data": [{"max_model_len": 8192}]}), {}
                if path == "/health":
                    return b"ok", {}
                return metrics, {}

        adapter.http = RefusesThenServes()
        failed_sample = adapter.sample()
        self.assertEqual(failed_sample["payload"]["observation_error"], "OSError")
        self.assertFalse(adapter.engine_emitted)
        adapter.http.serving = True
        served_sample = adapter.sample()
        reports = [r for r in captured if r["payload"]["event"] == "engine_config"]
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]["payload"]["observation_error"], "engine:capture:OSError")
        self.assertIsNone(reports[1]["error"])
        self.assertEqual(reports[1]["payload"]["max_model_len"], 8192)
        self.assertIsNone(served_sample["error"])
        self.assertTrue(adapter.engine_emitted)
        self.assertEqual(lifecycle.process_boot("uid0"), "process0")

    def test_zero_gpu_blocks_is_retained_without_a_capacity_threshold(self):
        metric = (
            "vllm:cache_config_info{"
            + cache_labels().replace('num_gpu_blocks="3891"', 'num_gpu_blocks="0"')
            + "} 1"
        ).encode()
        adapter, _, _, _ = self.adapter(metrics=metric)
        row = adapter.engine_config()
        self.assertIsNone(row["error"])
        self.assertEqual(row["payload"]["cache_config_labels"]["num_gpu_blocks"], "0")

    def test_missing_duplicate_unknown_or_malformed_labels_are_capture_errors(self):
        good = "vllm:cache_config_info{" + cache_labels() + "} 1\n"
        for text in (
            "",
            good * 2,
            good.replace('block_size="16",', ""),
            good.replace("{", '{extra="x",'),
            good.replace('engine="0"', 'engine="1"'),
            good.replace('block_size="16"', 'block_size="None"'),
            good.replace('block_size="16"', 'block_size="16",block_size="16"'),
        ):
            with self.subTest(text=text[:60]):
                adapter, _, _, _ = self.adapter(metrics=text.encode())
                self.assertTrue(adapter.engine_config()["payload"]["observation_error"])

    def test_models_require_one_observed_positive_integer_length(self):
        for models in (
            {},
            {"data": []},
            {"data": [{}, {}]},
            {"data": [{}]},
            {"data": [{"max_model_len": "8192"}]},
            {"data": [{"max_model_len": True}]},
        ):
            with self.subTest(models=models):
                adapter, _, _, _ = self.adapter(models=models)
                self.assertTrue(adapter.engine_config()["payload"]["observation_error"])

    def test_generation_must_join_before_and_after_both_reads(self):
        for path in (None, "/metrics", "/v1/models"):

            def change(lifecycle, seen, path=path):
                if seen == path:
                    lifecycle.pods["uid0"]["boot"] = "new-process"

            adapter, lifecycle, calls, _ = self.adapter(during=change)
            if path is None:
                lifecycle.pods["uid0"]["boot"] = "new-process"
            self.assertEqual(
                adapter.engine_config()["payload"]["observation_error"],
                "engine:generation_unjoined",
            )
            if path is None:
                self.assertEqual(calls, [])


class EngineJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from inf037b_fitness_fixture import attach
        from inf037b_setup_fixture import fixture

        cls.value = attach(fixture())

    def producer(self, change=lambda raw: None, *, value=None):
        from test_inf037b_fitness import reorder

        from inference_platform.inf037b_archive import strict_json
        from inference_platform.inf037b_setup import SetupCollector
        from inference_platform.inf037b_setup_fitness import FitnessProducer

        value = value or self.value
        raw = strict_json(value["fitness_raw"])
        change(raw)
        reorder(raw)
        return FitnessProducer(
            encode(raw),
            binding=value["binding"],
            artifacts=value["artifacts"],
            setup=SetupCollector(encode(value["bundle"]), **value["binding"]),
            allow_offline_fixture=True,
        )

    @staticmethod
    def row(raw, kind, event):
        return next(
            r["payload"]
            for r in raw["raw"]
            if r["source_kind"] == kind and r["payload"]["event"] == event
        )

    @classmethod
    def args(cls, raw, flag, value):
        from inference_platform.r1_spec import parse_engine_argv

        p = cls.row(raw, "kubernetes", "container_state")
        index = p["engine_args"].index(flag)
        p["engine_args"][index + 1] = value
        p["engine_flags"] = parse_engine_argv(p["engine_args"])
        p["engine_argv_sha256"] = sha(
            encode({"command": p["engine_command"], "args": p["engine_args"]})
        )

    def test_engine_values_are_derived_and_capacity_has_no_new_threshold(self):
        def change(raw):
            self.row(raw, "vllm", "engine_config")["cache_config_labels"]["num_gpu_blocks"] = "3358"

        row = self.producer(change).equivalence_row()
        self.assertEqual((row["block_size"], row["length"], row["max_seqs"]), (16, 8192, 16))
        self.assertEqual([r["num_gpu_blocks"] for r in row["engine_observations"]], [3358, 3891])
        self.assertTrue(
            all(r["r0_num_gpu_blocks_reference"] == 3891 for r in row["engine_observations"])
        )
        self.assertNotIn("max_seqs", self.producer().config["equivalence"])

    def test_zero_capacity_is_descriptive_in_the_equivalence_row(self):
        def change(raw):
            self.row(raw, "vllm", "engine_config")["cache_config_labels"]["num_gpu_blocks"] = "0"

        row = self.producer(change).equivalence_row()
        self.assertEqual(row["engine_observations"][0]["num_gpu_blocks"], 0)

    def test_engine_join_does_not_require_native_request_instrumentation(self):
        producer = self.producer()
        for row in producer.c.find("vllm", "engine_config"):
            self.assertEqual(row["source_time"]["clock_id"], "measurement")
            self.assertEqual(row["source_generation"], row["payload"]["process_generation"])
        producer.c.rows = [
            r
            for r in producer.c.rows
            if not (r["source_kind"] == "vllm" and r["payload"]["event"] == "accept")
        ]
        self.assertEqual(len(producer.engine_observations()), 2)

    def test_report_after_running_but_before_startup_refuses(self):
        def before_startup(raw):
            for row in raw["raw"]:
                if row["payload"].get("pod_uid") != "probe-uid0":
                    continue
                event = row["payload"]["event"]
                if row["source_kind"] == "kubernetes" and event == "startup":
                    row["source_time"]["value"] = 3000
                elif row["source_kind"] == "vllm" and event == "engine_config":
                    row["source_time"]["value"] = 2000

        with self.assertRaisesRegex(IntegrityError, "fitness:engine_report_before_startup"):
            self.producer(before_startup).engine_observations()

    def test_missing_uid_report_keeps_missing_source_refusal(self):
        def missing(raw):
            raw["raw"] = [
                row
                for row in raw["raw"]
                if not (
                    row["source_kind"] == "vllm"
                    and row["payload"]["event"] == "engine_config"
                    and row["payload"].get("pod_uid") == "probe-uid0"
                )
            ]

        with self.assertRaisesRegex(IntegrityError, "engine:missing_source"):
            self.producer(missing).engine_observations()

    def test_missing_uid_startup_cannot_be_replaced_by_running(self):
        def missing(raw):
            raw["raw"] = [
                row
                for row in raw["raw"]
                if not (
                    row["source_kind"] == "kubernetes"
                    and row["payload"]["event"] == "startup"
                    and row["payload"].get("pod_uid") == "probe-uid0"
                )
            ]

        with self.assertRaisesRegex(IntegrityError, "fitness:engine_report_before_startup"):
            self.producer(missing).engine_observations()

    def test_engine_join_uses_serving_read_after_retained_failed_observation(self):
        from inference_platform.inf037b_live import LiveRows

        def add_failed_observation(raw):
            for row in raw["raw"]:
                if (
                    row["source_kind"] == "vllm"
                    and row["payload"]["event"] == "engine_config"
                    and row["payload"]["pod_uid"] == "probe-uid0"
                ):
                    row["source_time"]["value"] = 2000
            captured = []
            LiveRows(raw["session_id"], "fixture-boot", attempt="setup", sink=captured.append).row(
                "vllm",
                "vllm:probe-uid0",
                "process-probe-uid0",
                "engine_config",
                {
                    "pod_uid": "probe-uid0",
                    "slot": 0,
                    "process_generation": "process-probe-uid0",
                    "observation_error": "engine:capture:OSError",
                },
                source_ms=1500,
            )
            captured[0]["stage"] = []
            raw["raw"].append(captured[0])

        producer = self.producer(add_failed_observation)
        observations = producer.engine_observations()
        first = next(item for item in observations if item["slot"] == 0)
        self.assertEqual(len(first["failed_config_attempts"]), 1)
        self.assertEqual(first["failed_config_attempts"][0]["error"], "engine:capture:OSError")
        self.assertEqual(first["max_model_len"], 8192)

    def test_engine_join_rejects_a_failed_observation_after_serving_read(self):
        from inference_platform.inf037b_live import LiveRows

        def add_failed_after_success(raw):
            captured = []
            LiveRows(raw["session_id"], "fixture-boot", attempt="setup", sink=captured.append).row(
                "vllm",
                "vllm:probe-uid0",
                "process-probe-uid0",
                "engine_config",
                {
                    "pod_uid": "probe-uid0",
                    "slot": 0,
                    "process_generation": "process-probe-uid0",
                    "observation_error": "engine:capture:OSError",
                },
                source_ms=3000,
            )
            captured[0]["stage"] = []
            raw["raw"].append(captured[0])

        with self.assertRaisesRegex(IntegrityError, "engine:failed_then_serving_order"):
            self.producer(add_failed_after_success).engine_observations()

    def test_mutant_c_executed_256_refuses_even_when_declared_config_says_16(self):
        from inference_platform.inf037b_archive import strict_json

        value = copy.deepcopy(self.value)
        config = strict_json(value["artifacts"]["fitness/config.json"])
        # An obsolete declaration must neither rescue drift nor become its source.
        config["equivalence"].update(max_seqs=16, block_size=16, length=8192)
        value["artifacts"]["fitness/config.json"] = encode(config)
        pin = sha(encode(config))

        def repin(obj):
            if isinstance(obj, dict):
                for key, item in obj.items():
                    if key == "configuration" and isinstance(item, str):
                        obj[key] = pin
                    elif (
                        key in ("config_sha256", "input_sha256")
                        and item == self.value["binding"]["pins"]["configuration"]
                    ):
                        obj[key] = pin
                    else:
                        repin(item)
            elif isinstance(obj, list):
                for item in obj:
                    repin(item)

        repin(value["binding"])
        repin(value["bundle"])
        raw = strict_json(value["fitness_raw"])
        repin(raw)
        value["fitness_raw"] = encode(raw)
        with self.assertRaisesRegex(IntegrityError, "engine:flag_mismatch:max_num_seqs"):
            self.producer(
                lambda raw: self.args(raw, "--max-num-seqs", "256"), value=value
            ).equivalence_row()

    def test_mutant_e_cache_block_32_disagrees_with_executed_16(self):
        def change(raw):
            self.row(raw, "vllm", "engine_config")["cache_config_labels"]["block_size"] = "32"

        with self.assertRaisesRegex(IntegrityError, "engine:source_disagreement:block_size"):
            self.producer(change).equivalence_row()

    def test_mutant_f_other_uid_or_generation_refuses(self):
        for field, value, reason in (
            ("pod_uid", "other", "uid_unjoined"),
            ("process_generation", "other", "generation_unjoined"),
        ):

            def change(raw, field=field, value=value):
                row = next(
                    r
                    for r in raw["raw"]
                    if r["source_kind"] == "vllm" and r["payload"]["event"] == "engine_config"
                )
                row["payload"][field] = value
                # Model a well-formed report from an actual foreign source,
                # rather than only an internally inconsistent envelope.
                if field == "pod_uid":
                    row["source_identity"] = "vllm:" + value
                    row["payload"]["process_generation"] = "foreign-process"
                row["source_generation"] = row["payload"]["process_generation"]

            with (
                self.subTest(field=field),
                self.assertRaisesRegex(IntegrityError, "engine:" + reason),
            ):
                self.producer(change).equivalence_row()

    def test_missing_each_source_and_duplicate_each_source_refuse(self):
        for kind, event in (("kubernetes", "container_state"), ("vllm", "engine_config")):
            for mode in ("missing", "duplicate"):

                def change(raw, kind=kind, event=event, mode=mode):
                    row = next(
                        r
                        for r in raw["raw"]
                        if r["source_kind"] == kind and r["payload"]["event"] == event
                    )
                    if mode == "missing":
                        raw["raw"].remove(row)
                    else:
                        raw["raw"].append(copy.deepcopy(row))

                reason = "missing_source" if mode == "missing" else "ambiguous_source"
                with (
                    self.subTest(kind=kind, mode=mode),
                    self.assertRaisesRegex(IntegrityError, "engine:" + reason),
                ):
                    self.producer(change).equivalence_row()

    def test_all_registered_flags_and_unregistered_extra_refuse(self):
        for flag, value in (
            ("--dtype", "float16"),
            ("--max-num-queued-reqs", "33"),
            ("--generation-config", "auto"),
            ("--max-num-seqs", "256"),
        ):
            with (
                self.subTest(flag=flag),
                self.assertRaisesRegex(IntegrityError, "engine:flag_mismatch"),
            ):
                self.producer(
                    lambda raw, flag=flag, value=value: self.args(raw, flag, value)
                ).equivalence_row()
        for name, value in (
            ("block_size", "32"),
            ("gpu_memory_utilization", "0.8"),
            ("enable_prefix_caching", "False"),
            ("max_model_len", 4096),
        ):

            def change(raw, name=name, value=value):
                p = self.row(raw, "vllm", "engine_config")
                if name == "max_model_len":
                    p[name] = value
                else:
                    p["cache_config_labels"][name] = value

            with (
                self.subTest(name=name),
                self.assertRaisesRegex(IntegrityError, "engine:source_disagreement"),
            ):
                self.producer(change).equivalence_row()

        def extra(raw):
            from inference_platform.r1_spec import parse_engine_argv

            p = self.row(raw, "kubernetes", "container_state")
            p["engine_args"].append("--enforce-eager")
            p["engine_flags"] = parse_engine_argv(p["engine_args"])
            p["engine_argv_sha256"] = sha(
                encode({"command": p["engine_command"], "args": p["engine_args"]})
            )

        with self.assertRaisesRegex(IntegrityError, "engine:flag_mismatch:flag_set"):
            self.producer(extra).equivalence_row()

        def both_wrong(raw):
            self.args(raw, "--block-size", "32")
            self.row(raw, "vllm", "engine_config")["cache_config_labels"]["block_size"] = "32"

        with self.assertRaisesRegex(IntegrityError, "engine:flag_mismatch:block_size"):
            self.producer(both_wrong).equivalence_row()

    def test_hash_supervisor_and_process_joins_refuse(self):
        for field, value, reason in (
            ("engine_argv_sha256", "0" * 64, "argv_hash"),
            ("restart_count", 1, "generation_unjoined"),
            ("node_pseudonym", "other", "uid_unjoined"),
        ):

            def change(raw, field=field, value=value):
                self.row(raw, "kubernetes", "container_state")[field] = value

            with (
                self.subTest(field=field),
                self.assertRaisesRegex(IntegrityError, "engine:" + reason),
            ):
                self.producer(change).equivalence_row()

        def missing(raw):
            raw["supervisors"].pop("probe-uid0")

        with self.assertRaisesRegex(IntegrityError, "engine:missing_source"):
            self.producer(missing).equivalence_row()
