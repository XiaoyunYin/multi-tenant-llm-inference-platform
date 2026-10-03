"""Real transport regression for pinned vLLM v0.29.0 PUB socket selection."""

import json
import re
import socket
import threading
import time
import unittest
from pathlib import Path

import msgspec
import zmq
from test_kv_event_capture import BlockStored, KVEventBatch

from inference_platform.kv_event_capture import capture_zmq_event_stream
from inference_platform.stage_c_fitness import vllm_publisher_binds


class RealPublisherCaptureTest(unittest.TestCase):
    def capture(self, planned_endpoint, topic):
        """Keep planned address/semantics; substitute only an ephemeral TCP port."""
        ready = threading.Event()
        subscribed = threading.Event()
        state = {}

        def publish():
            context = zmq.Context()
            publisher = context.socket(zmq.PUB)
            publisher.setsockopt(zmq.LINGER, 0)
            try:
                host = planned_endpoint.rsplit(":", 1)[0]
                if vllm_publisher_binds(planned_endpoint):
                    port = publisher.bind_to_random_port(host)
                    state["operation"] = "bind"
                else:
                    # Reserve/release a vacant port, then connect without providing a binder.
                    with socket.socket() as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        port = reservation.getsockname()[1]
                    publisher.connect(f"{host}:{port}")
                    state["operation"] = "connect"
                state["capture_endpoint"] = f"tcp://127.0.0.1:{port}"
                ready.set()
                if not subscribed.wait(3):
                    raise RuntimeError("capture did not subscribe")
                # PUB/SUB subscription propagation is asynchronous (slow joiner).
                time.sleep(0.5)
                batch = KVEventBatch(
                    ts=time.time(),
                    events=[BlockStored([123], None, list(range(16)), 16, None, "GPU", None)],
                )
                payload = msgspec.msgpack.encode(batch)
                for sequence in range(20):
                    publisher.send_multipart([topic.encode(), sequence.to_bytes(8, "big"), payload])
                    time.sleep(0.025)
                time.sleep(0.1)
            except BaseException as error:
                state["error"] = error
                ready.set()
            finally:
                publisher.close(linger=0)
                context.term()

        worker = threading.Thread(target=publish, name="real-kv-test-publisher")
        worker.start()
        try:
            self.assertTrue(ready.wait(3), "publisher did not initialize")
            if "error" in state:
                raise state["error"]
            observations = capture_zmq_event_stream(
                state["capture_endpoint"],
                topic=topic,
                duration_seconds=2.5,
                on_subscribed=subscribed.set,
            )
        finally:
            subscribed.set()
            worker.join(4)
        self.assertFalse(worker.is_alive(), "publisher thread leaked")
        if "error" in state:
            raise state["error"]
        return observations, state["operation"]

    def test_planned_binding_publisher_delivers_to_real_connecting_capture(self):
        root = Path(__file__).resolve().parents[2]
        launcher = (root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(encoding="utf-8")
        config = json.loads(re.search(r"--kv-events-config\s+'([^']+)'", launcher)[1])
        observations, operation = self.capture(config["endpoint"], config["topic"])
        self.assertEqual(len(observations), 20, "planned publisher cannot deliver all batches")
        self.assertEqual(operation, "bind")
        self.assertEqual([event["sequence"] for event in observations], list(range(20)))
        self.assertTrue(all(event["event_type"] == "BlockStored" for event in observations))
        self.assertTrue(all("token_ids" not in event for event in observations))
        print("Real ZMQ planned bind/connect: 20/20 decoded BlockStored batches")

    def test_old_connecting_publisher_cannot_deliver_to_connecting_capture(self):
        observations, operation = self.capture("tcp://127.0.0.1:5557", "kv-events")
        self.assertEqual(operation, "connect")
        self.assertEqual(observations, [])
        # The same delivery acceptance assertion fails for the old planned endpoint.
        with self.assertRaises(AssertionError):
            self.assertEqual(len(observations), 20, "planned publisher cannot deliver all batches")
        print("Real ZMQ old connect/connect: 0/20; delivery acceptance rejected")
