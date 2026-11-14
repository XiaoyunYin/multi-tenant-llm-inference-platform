"""Fixed setup composition over accepted samplers, raw joins and LiveRow5.

No cluster/device authority, raw-source producer or success fixture is supplied
here. Those named ports refuse until the 4d/campaign source slices exist.
"""

from .inf037b_archive import encode, sha
from .inf037b_composition import SamplerComposition
from .inf037b_eks_cluster import ClusterPorts, join_cluster
from .inf037b_resolver import exact, require, span
from .inf037b_row5_live import LiveRow5
from .inf037b_setup import SetupCollector, startup_row
from .inf037b_setup_fitness import FitnessProducer


def validate_setup_inputs(value, binding, sample):
    """Re-derive cold/cache/GPU/D_bind/restoration and continuous clock joins.

    Final SetupCommands.fitness_rows runs FitnessProducer.produce after
    ConcurrentPreparation merges LiveRow5's outage/restoration capture. Do not
    invent an intermediate equivalence/A/renewal result before those rows exist.
    """
    setup = SetupCollector(value["raw"], **binding)
    require(
        type(sample) is dict and {"clock_id", "boot_id", "ms"} <= sample.keys(), "eks:setup_clock"
    )
    span(sample["ms"], "eks:setup_clock")
    exact(sample["clock_id"], "measurement", "eks:setup_clock")
    exact(sample["boot_id"], setup.rows[0]["collector_boot_id"], "eks:setup_clock_boot")
    startup = startup_row(setup, pins=binding["pins"], artifacts=value["artifacts"])
    producer = FitnessProducer(
        value["fitness_raw"], binding=binding, artifacts=value["artifacts"], setup=setup
    )
    clocks = producer.clock_row()
    require(
        max(
            setup.row(binding["pins"])["selected_ms"],
            producer.c.row(binding["pins"])["selected_ms"],
        )
        <= sample["ms"][1],
        "eks:setup_future_source",
    )
    return {"startup": startup, "clocks": clocks, "paid_ready": False}


class SetupLifecycleScope:
    def __init__(self, factory):
        self.factory, self.live, self.runtime = factory, None, None

    def bind(self, stop):
        if self.runtime is None:
            f = self.factory
            # Independent GPU/device-release data cannot come from a Pod exit,
            # metrics disappearance, Ready, or an inferred Boolean. v4 :41/:44.
            device = f.dependency("4d_device_release_observer")(stop)
            authority = f.dependency("4d_setup_lifecycle")(stop)
            runtime = f.dependency("part2_setup_runtime")(stop)
            require(
                type(device) is dict and type(authority) is dict and type(runtime) is dict,
                "eks:setup_binding",
            )
            exact(device["binding"], f.binding, "eks:device_binding")
            exact(authority["binding"], f.binding, "eks:setup_authority_binding")
            join_cluster(device, f, "4d_device_release_observer")
            join_cluster(authority, f, "4d_setup_lifecycle")
            join_cluster(runtime, f, "part2_setup_runtime")
            live = LiveRow5(**runtime["row5"])
            self.runtime, self.authority, self.device, self.live = runtime, authority, device, live
        return self.runtime

    def stage(self, name, stop_ns):
        self.bind(stop_ns // 1_000_000)
        return self.live.row5_stage(name, stop_ns)

    def effect(self, name, stop):
        f = self.factory
        return ClusterPorts(f).setup_effect(
            name,
            f.port.driver_key + ":preparation:gpu:" + name,
            {
                "binding": f.binding,
                "pins": f.config["pins"],
                "stop_ms": stop,
                "authority": self.authority,
                "device_observer": self.device,
            },
            stop,
        )

    def startup(self, name, receipt, stop):
        # The later host adapter supplies the already-running owner's node
        # lifecycle collection and the retained same-UID startup view. The
        # accepted composition gates sample/engine_config on that startup edge.
        inputs = self.factory.dependency("4d_startup_observation")(name, receipt, stop)
        join_cluster(
            inputs, self.factory, "4d_startup_observation", {"name": name, "receipt": receipt}
        )
        from .inf037b_eks_collectors import ScopeWindow, compose

        scope = "cold_startup" if name == "cold" else "cached_startup"
        require(
            "capture_start_ns" in inputs and "capture_stop_ns" in inputs,
            "capture:unresolved:collector_window:" + scope,
        )
        window = ScopeWindow(
            scope,
            inputs["capture_start_ns"],
            inputs["capture_stop_ns"],
            self.factory.config["pins"]["configuration"],
        )
        require(window.stop_ns <= stop * 1000000, "collectors:original_cutoff")
        sampler = SamplerComposition(**inputs["sampler"])
        bundle = inputs.get("collector_bundle")
        require(type(bundle) is dict, "capture:unresolved:collector_bindings:" + scope)
        bundle = {
            **bundle,
            "metrics": {"metrics:slot" + str(receipt["slot"]): (sampler, receipt["uid"])},
        }
        collectors = compose(inputs["owner"], window, bundle)
        return collectors.run(watches=inputs.get("watches", {}))

    def gpu(self, stop, row5_stage):
        f = self.factory
        f.port.deadline(stop)
        runtime = self.bind(stop)
        require(row5_stage == self.stage, "eks:shared_row5_stage")
        key = f.port.driver_key + ":preparation:gpu"
        with f.port.store.lock():
            state = f.port.store.read()
            require(
                sha(encode(["eks.setup.capture", key])) not in state["operations"],
                "eks:setup_interrupted_no_retry",
            )
            f.port.intent(state, "eks.setup.capture", key, {"binding": f.binding, "stop_ms": stop})
        # Existing Port intent/settlement prohibits repeating interrupted work;
        # no second lifecycle loop or replacement startup/probe is created.
        self.effect("begin", stop)
        known = list(row5_stage("known0", stop * 1_000_000))
        cold = self.effect("cold", stop)
        self.startup("cold", cold, stop)
        known.extend(row5_stage("known1", stop * 1_000_000))
        self.effect("two_serving", stop)
        known.extend(row5_stage("known2", stop * 1_000_000))
        probe_runtime = runtime["probe_runtime"](stop)
        f.run_setup_probe(runtime["probe_owner"], probe_runtime, stop)
        self.effect("stop_cold_and_drain", stop)
        known.extend(row5_stage("cached_stop_known1", stop * 1_000_000))
        cached = self.effect("node_cached", stop)
        exact(cached["node_uid"], cold["node_uid"], "eks:cached_same_node")
        exact(cached["slot"], cold["slot"], "eks:cached_same_slot")
        require(cached["uid"] != cold["uid"], "eks:cached_fresh_uid")
        self.startup("node_cached", cached, stop)
        known.extend(row5_stage("cached_restore_known2", stop * 1_000_000))
        value = runtime["collect_inputs"](stop)
        # Keep refused raw candidates before joins, in the existing operation
        # store. Final setup persistence and report production remain unchanged.
        with f.port.store.lock():
            state = f.port.store.read()
            state["values"]["setup/candidate"] = {
                "raw_hex": value["raw"].hex(),
                "fitness_raw_hex": value["fitness_raw"].hex(),
            }
            f.port.store.write(state)
        binding = {
            "session_id": f.binding["session_id"],
            "pins": f.config["pins"],
            "t0_ms": f.binding["t0_ms"],
        }
        evidence = validate_setup_inputs(value, binding, f.dependency("clock_sample")())
        with f.port.store.lock():
            state = f.port.store.read()
            state["values"]["setup/validated"] = {
                "raw_sha256": sha(value["raw"]),
                "evidence": evidence,
            }
            f.port.store.write(state)
        f.port.deadline(stop, completed=True)
        return {**value, "row5_known_requests": known}

    def control(self, stop_ns, prepared):
        require(self.live is not None, "eks:setup_gpu_required")
        # LiveRow5 owns KnownStage, OutageSequence, restoration and capture.
        # ConcurrentPreparation performs the accepted raw join; SetupCommands
        # then derives equivalence, A/renewal, ingress and restoration hold.
        return self.live.row5_control(stop_ns, prepared)
