"""Factory binding for the existing single setup probe, not another runner."""

import time
from collections import ChainMap

from .inf037b_archive import encode, sha
from .inf037b_capture import DeadlineHTTP
from .inf037b_controls import book_probe
from .inf037b_live import ClientSSEAdapter, GatewayAdapter
from .inf037b_probe import NativeRequestAdapter, SingleProbe
from .inf037b_resolver import exact, require


def compose_probe(factory, owner, runtime):
    """Deployment supplies endpoints/CA/credentials and retained native origins.

    The same owner must already observe Pod UID -> slot on Kubernetes. Native
    abort/provenance validation stays in NativeRequestAdapter, never in a mock
    endpoint's claim. Missing deployment/source inputs have no success default.
    """
    exact(owner.binding["session_id"], factory.binding["session_id"], "eks:probe_session")
    exact(owner.binding["pins"], factory.config["pins"], "eks:probe_pins")
    gateways, slots = runtime["gateways"], runtime["slots"]
    exact(set(gateways), {"gateway0", "gateway1"}, "eks:probe_gateways")
    exact(set(slots), {0, 1}, "eks:probe_slots")
    require(
        len({slot["origin"]["pod_uid"] for slot in slots.values()}) == 2, "eks:probe_distinct_uids"
    )
    require(
        runtime.get("signals") is not None and len(runtime["signals"]) == 2,
        "transport:unresolved:setup_signal_launcher",
    )
    booking = book_probe(**runtime["booking"])
    stop_ns = booking["stop_ns"]
    config_hash = factory.config["pins"]["configuration"]
    clients = {
        g: ClientSSEAdapter(
            owner.rows("client:" + g), g, config_hash, retain=owner.retainer("client:" + g)
        )
        for g in gateways
    }
    gateway_adapters = {
        g: GatewayAdapter(
            owner.rows(g),
            DeadlineHTTP(**spec["http"], stop_ns=stop_ns, retain=owner.retainer(g)),
            g,
            slot_names=runtime["slot_names"],
            config_sha256=config_hash,
            request_ids=clients[g].request_ids,
            reservations=runtime["reservations"],
            defer_request_bindings=True,
        )
        for g, spec in gateways.items()
    }
    aliases = ChainMap(*(client.request_ids for client in clients.values()))
    native = []
    for slot, spec in slots.items():
        origin = spec["origin"]
        exact(origin["slot"], slot, "eks:probe_native_slot")
        exact(
            getattr(owner, "lineage_admissions", {}).get(origin["pod_uid"], {}).get("slot"),
            slot,
            "eks:probe_uid_not_observed",
        )
        exact(
            sha(encode(spec["manifest"])),
            factory.config["native_manifest_sha256"],
            "eks:probe_native_pin",
        )
        source = "native:slot" + str(slot)
        native.append(
            NativeRequestAdapter(
                owner.rows(source),
                DeadlineHTTP(
                    **spec["http"],
                    stop_ns=stop_ns,
                    retain=owner.retainer(
                        source, uid=origin["pod_uid"], process_generation=origin["boot_id"]
                    ),
                ),
                origin=origin,
                manifest=spec["manifest"],
                slot=slot,
                request_ids=aliases,
                clock_rows=owner.clock_rows,
                clock_id="node:" + origin["node"],
            )
        )
    return SingleProbe(
        owner=owner,
        clients=clients,
        endpoints={g: s["endpoint"] for g, s in gateways.items()},
        credentials={g: s["credential"] for g, s in gateways.items()},
        control_credentials=runtime["control_credentials"],
        contexts={g: s["context"] for g, s in gateways.items()},
        tls={g: s["tls"] for g, s in gateways.items()},
        controller_rows=owner.rows(runtime["controller_source"]),
        payloads=runtime["payloads"],
        payloads_sha256=factory.config["probe_payloads_sha256"],
        start_ns=booking["start_ns"],
        stop_ns=stop_ns,
        native=native,
        gateway_adapters=gateway_adapters,
        signals=runtime["signals"],
        clock=runtime.get("clock", time.monotonic_ns),
        sleep=runtime.get("sleep", time.sleep),
    )


def compose_probe_collectors(factory, owner, runtime, *, actions, resources):
    from .inf037b_eks_collectors import ScopeWindow, compose

    booking = book_probe(**runtime["booking"])
    window = ScopeWindow(
        "fitness_probe_and_signal",
        runtime["booking"]["ready_ns"],
        booking["stop_ns"],
        factory.config["pins"]["configuration"],
        0,
    )
    require(
        runtime.get("collector_bundle") is not None,
        "capture:unresolved:collector_bindings:fitness_probe_and_signal",
    )
    collectors = compose(
        owner,
        window,
        runtime["collector_bundle"],
        resources={a.source: a for a in resources.adapters.values()},
    )
    # Probe is a traffic action, not a fixed infrastructure effect.
    collectors.boundary()
    return owner.run(
        periodic=collectors.periodic,
        watches=runtime.get("watches", {}),
        actions=actions,
        action_sources={"diagnostic": ["diagnostic", "client:gateway0", "client:gateway1"]},
        stop_ns=window.stop_ns,
    )
