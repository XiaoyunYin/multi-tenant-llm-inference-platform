"""Real socket, POSIX and MinIO coverage for the bounded export store path."""

import multiprocessing
import os
import socket
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from inf037b_observations_fixture import attach
from inf037b_setup_fixture import fixture

from inference_platform.inf037b_archive import IntegrityError, encode, file_facts, sha, strict_json
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_setup import persist_archive_artifacts
from inference_platform.inf037b_setup_observations import validate_export_archives
from inference_platform.inf037b_transfer import (
    S3ArchiveStore,
    SocketArchiveReceiver,
    SocketArchiveTransfer,
    _artifact_facts,
    _read_frame,
    _write_frame,
    persist_to_both,
    retrieve_posix_artifacts,
)

S3_URL = os.environ.get("S3_ENDPOINT_URL")
TEST_BUCKET = os.environ.get("S3_TEST_BUCKET", "inf037b-transfer-tests")
RECOVERY_ROOT = Path(os.environ.get("RECOVERY_ROOT", "/recovery"))
RESTART_ROOT = RECOVERY_ROOT / "minio-restart-checkpoint"
RESTART_PHASE = os.environ.get("TRANSFER_RESTART_PHASE", "during")
OBJECT_LIMIT = 128
BYTE_LIMIT = 64 * 1024 * 1024
MAX_ARCHIVE_AS_WIRE_BYTES = 1_615_101_807


class CountingHasher:
    def __init__(self, counter, inner=None):
        import hashlib

        self.counter = counter
        self.inner = inner or hashlib.sha256()

    def update(self, data):
        self.counter[0] += len(data)
        self.inner.update(data)
        return self

    def copy(self):
        return CountingHasher(self.counter, self.inner.copy())

    def hexdigest(self):
        return self.inner.hexdigest()


def counting_factory(counter):
    return lambda: CountingHasher(counter)


def _send_chunk(address, transfer_id, key, offset, data):
    request_id = uuid.uuid4().hex
    with socket.create_connection(address, timeout=5) as connection:
        connection.settimeout(5)
        stream = connection.makefile("rwb")
        try:
            _write_frame(
                stream,
                {
                    "op": "chunk",
                    "transfer_id": transfer_id,
                    "request_id": request_id,
                    "key": key,
                    "offset": offset,
                    "data_length": len(data),
                },
            )
            stream.write(data)
            stream.flush()
            return _read_frame(stream)
        finally:
            stream.close()


def _crash_receiver_process(root, transfer_id, manifest, ready, chunk_bytes, exit_on_call):
    calls = 0

    def crash_after_sync(key, offset, length):
        nonlocal calls
        calls += 1
        if calls == exit_on_call:
            os._exit(79)

    receiver = SocketArchiveReceiver(
        root,
        transfer_id=transfer_id,
        manifest=manifest,
        max_total_bytes=2 * 1024 * 1024,
        max_objects=4,
        chunk_bytes=chunk_bytes,
        after_data_fsync=crash_after_sync,
    ).start()
    ready.put(receiver.address)
    receiver.thread.join()


def s3_ready(client, bucket):
    from botocore.exceptions import ClientError, EndpointConnectionError

    for attempt in range(40):
        try:
            client.create_bucket(Bucket=bucket)
            return
        except EndpointConnectionError:
            if attempt == 39:
                raise
            time.sleep(0.25)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {
                "BucketAlreadyExists",
                "BucketAlreadyOwnedByYou",
            }:
                return
            raise


def make_store(root, *, prefix=None, max_total_bytes=BYTE_LIMIT, max_objects=OBJECT_LIMIT):
    client = S3ArchiveStore.client_for_endpoint(S3_URL)
    return S3ArchiveStore(
        client,
        bucket=TEST_BUCKET,
        prefix=prefix or f"integration/{uuid.uuid4().hex}",
        max_total_bytes=max_total_bytes,
        max_objects=max_objects,
    )


def make_capture_artifacts(root, *, wire_bytes=0):
    value = attach(fixture())
    export_value = strict_json(value["export_raw"])
    artifacts = dict(value["export_artifacts"])
    if wire_bytes:
        raw_path = root / "client-response.bin"
        block = bytes(range(256)) * 4096
        remaining = wire_bytes
        with raw_path.open("xb") as stream:
            while remaining:
                chunk = block[: min(len(block), remaining)]
                stream.write(chunk)
                remaining -= len(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        index_path = root / "client-response.jsonl"
        index_path.write_bytes(encode({"offset": 0, **file_facts(raw_path), "source": "client"}))
        artifacts["wire/client-response.bin"] = raw_path
        artifacts["wire/client-response.jsonl"] = index_path
    return export_value, artifacts


@unittest.skipUnless(os.name == "posix", "receiver durability requires Linux/POSIX")
class TransferAlgorithmTests(unittest.TestCase):
    def test_incremental_hashing_and_status_do_not_rehash_saved_file(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-hash-meter-") as temporary:
            root = Path(temporary)
            size = 1024 * 1024
            payload = bytes(range(256)) * (size // 256)
            sender_count, receiver_count = [0], [0]
            source = root / "payload.bin"
            source.write_bytes(payload)
            transfer_id = uuid.uuid4().hex
            manifest = _artifact_facts(
                {"wire/payload.bin": source},
                max_total_bytes=size,
                max_objects=1,
            )
            receiver = SocketArchiveReceiver(
                root / "receiver",
                transfer_id=transfer_id,
                manifest=manifest,
                max_total_bytes=size,
                max_objects=1,
                chunk_bytes=256 * 1024,
                hasher_factory=counting_factory(receiver_count),
            ).start()
            self.addCleanup(receiver.close)
            receiver.inject_once("drop_ack")
            receipt = SocketArchiveTransfer(
                chunk_bytes=256 * 1024,
                hasher_factory=counting_factory(sender_count),
            ).transfer(
                {"wire/payload.bin": source},
                receiver.address,
                transfer_id=transfer_id,
                max_total_bytes=size,
                max_objects=1,
            )
            reconnect_allowance = size * receipt["reconnect_attempts"]
            self.assertLessEqual(sender_count[0], 2 * size + reconnect_allowance)
            self.assertLessEqual(receiver_count[0], 2 * size + reconnect_allowance)
            self.assertEqual(receiver_count[0], 2 * size)
            self.assertEqual(receipt["reconnect_attempts"], 1)
            self.assertGreaterEqual(receipt["attempts"], 6)
            self.assertGreaterEqual(receipt["reconnect_seconds"], 0)

    @unittest.skipUnless(
        os.environ.get("INF037B_RUN_TIMING") == "1",
        "opt-in receipt-only socket timing pair",
    )
    def test_linear_socket_timing_256_and_512_mib(self):
        timings = []
        block = bytes(range(256)) * 4096
        for size_mib in (256, 512):
            with tempfile.TemporaryDirectory(prefix="inf037b-scale-") as temporary:
                root = Path(temporary)
                source = root / "payload.bin"
                remaining = size_mib * 1024 * 1024
                with source.open("xb") as stream:
                    while remaining:
                        chunk = block[: min(len(block), remaining)]
                        stream.write(chunk)
                        remaining -= len(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                transfer_id = uuid.uuid4().hex
                manifest = _artifact_facts(
                    {"wire/payload.bin": source},
                    max_total_bytes=size_mib * 1024 * 1024,
                    max_objects=1,
                )
                receiver = SocketArchiveReceiver(
                    root / "receiver",
                    transfer_id=transfer_id,
                    manifest=manifest,
                    max_total_bytes=size_mib * 1024 * 1024,
                    max_objects=1,
                    chunk_bytes=4 * 1024 * 1024,
                ).start()
                try:
                    start = time.perf_counter()
                    SocketArchiveTransfer(
                        chunk_bytes=4 * 1024 * 1024,
                        timeout_s=30,
                        transfer_timeout_s=600,
                    ).transfer(
                        {"wire/payload.bin": source},
                        receiver.address,
                        transfer_id=transfer_id,
                        max_total_bytes=size_mib * 1024 * 1024,
                        max_objects=1,
                    )
                    timings.append(time.perf_counter() - start)
                finally:
                    receiver.close()
        ratio = timings[1] / timings[0]
        print(
            f"R437 socket scaling: 256 MiB={timings[0]:.3f}s, "
            f"512 MiB={timings[1]:.3f}s, ratio={ratio:.3f}x",
            flush=True,
        )

    def test_deadline_and_transfer_wide_reconnect_budget_refuse_with_receipts(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-budget-") as temporary:
            root = Path(temporary)
            source = root / "payload.bin"
            source.write_bytes(b"x" * (32 * 1024))
            with self.assertRaisesRegex(IntegrityError, "transfer:deadline") as deadline_error:
                SocketArchiveTransfer().transfer(
                    {"wire/payload.bin": source},
                    ("127.0.0.1", 1),
                    transfer_id="deadline-control",
                    max_total_bytes=64 * 1024,
                    max_objects=1,
                    deadline_monotonic=time.monotonic() - 1,
                )
            self.assertEqual(deadline_error.exception.receipt["attempts"], 0)

            transfer_id = uuid.uuid4().hex
            manifest = _artifact_facts(
                {"wire/payload.bin": source}, max_total_bytes=64 * 1024, max_objects=1
            )
            receiver = SocketArchiveReceiver(
                root / "receiver",
                transfer_id=transfer_id,
                manifest=manifest,
                max_total_bytes=64 * 1024,
                max_objects=1,
                chunk_bytes=4096,
            ).start()
            self.addCleanup(receiver.close)
            receiver.inject_n("drop_ack", 8)
            with self.assertRaisesRegex(
                IntegrityError, "transfer:reconnect_budget"
            ) as budget_error:
                SocketArchiveTransfer(
                    chunk_bytes=4096,
                    max_reconnects=2,
                    max_reconnect_seconds=10,
                ).transfer(
                    {"wire/payload.bin": source},
                    receiver.address,
                    transfer_id=transfer_id,
                    max_total_bytes=64 * 1024,
                    max_objects=1,
                )
            receipt = budget_error.exception.receipt
            self.assertEqual(receipt["reconnect_attempts"], 3)
            self.assertGreater(receipt["attempts"], receipt["reconnect_attempts"])
            self.assertGreaterEqual(receipt["reconnect_seconds"], 0)

            seconds_id = uuid.uuid4().hex
            seconds_receiver = SocketArchiveReceiver(
                root / "seconds-receiver",
                transfer_id=seconds_id,
                manifest=manifest,
                max_total_bytes=64 * 1024,
                max_objects=1,
                chunk_bytes=4096,
            ).start()
            self.addCleanup(seconds_receiver.close)
            seconds_receiver.inject_once("drop_ack")
            original_handle = seconds_receiver._handle

            def delayed_status(request, stream):
                response = original_handle(request, stream)
                if request.get("op") == "status":
                    time.sleep(0.1)
                return response

            seconds_receiver._handle = delayed_status
            with self.assertRaisesRegex(
                IntegrityError, "transfer:reconnect_budget"
            ) as seconds_error:
                SocketArchiveTransfer(
                    chunk_bytes=4096,
                    timeout_s=1,
                    max_reconnects=5,
                    max_reconnect_seconds=0.05,
                ).transfer(
                    {"wire/payload.bin": source},
                    seconds_receiver.address,
                    transfer_id=seconds_id,
                    max_total_bytes=64 * 1024,
                    max_objects=1,
                )
            self.assertGreater(seconds_error.exception.receipt["reconnect_seconds"], 0.05)

    def test_receiver_crash_window_truncates_first_and_later_unacknowledged_chunks(self):
        context = multiprocessing.get_context("fork")
        chunk_bytes = 256 * 1024
        payload = bytes(range(256)) * 4096
        for acknowledged_chunks, crash_on_call in ((0, 1), (1, 1)):
            with self.subTest(acknowledged_chunks=acknowledged_chunks):
                with tempfile.TemporaryDirectory(prefix="inf037b-crash-") as temporary:
                    root = Path(temporary)
                    source = root / "source.bin"
                    source.write_bytes(payload)
                    artifacts = {"wire/source.bin": source}
                    manifest = _artifact_facts(
                        artifacts, max_total_bytes=len(payload), max_objects=1
                    )
                    transfer_id = uuid.uuid4().hex
                    offset = acknowledged_chunks * chunk_bytes
                    if acknowledged_chunks:
                        seed = SocketArchiveReceiver(
                            root / "receiver",
                            transfer_id=transfer_id,
                            manifest=manifest,
                            max_total_bytes=len(payload),
                            max_objects=1,
                            chunk_bytes=chunk_bytes,
                        ).start()
                        _send_chunk(
                            seed.address,
                            transfer_id,
                            "wire/source.bin",
                            0,
                            payload[:chunk_bytes],
                        )
                        seed.close()
                    ready = context.Queue()
                    process = context.Process(
                        target=_crash_receiver_process,
                        args=(
                            root / "receiver",
                            transfer_id,
                            manifest,
                            ready,
                            chunk_bytes,
                            crash_on_call,
                        ),
                    )
                    process.start()
                    address = ready.get(timeout=10)
                    with self.assertRaises((EOFError, OSError, ConnectionError, TimeoutError)):
                        _send_chunk(
                            address,
                            transfer_id,
                            "wire/source.bin",
                            offset,
                            payload[offset : offset + chunk_bytes],
                        )
                    process.join(timeout=10)
                    self.assertFalse(process.is_alive())
                    self.assertEqual(process.exitcode, 79)
                    ready.close()
                    ready.join_thread()
                    reopened = SocketArchiveReceiver(
                        root / "receiver",
                        transfer_id=transfer_id,
                        manifest=manifest,
                        max_total_bytes=len(payload),
                        max_objects=1,
                        chunk_bytes=chunk_bytes,
                    ).start()
                    try:
                        event = reopened.events[-1]
                        self.assertEqual(event["event"], "truncated_unacknowledged_bytes")
                        self.assertEqual(event["from_bytes"], offset + chunk_bytes)
                        self.assertEqual(event["to_bytes"], offset)
                        SocketArchiveTransfer(chunk_bytes=chunk_bytes).transfer(
                            artifacts,
                            reopened.address,
                            transfer_id=transfer_id,
                            max_total_bytes=len(payload),
                            max_objects=1,
                        )
                        self.assertEqual(
                            file_facts(reopened.artifact_paths()["wire/source.bin"]),
                            file_facts(source),
                        )
                    finally:
                        reopened.close()

    def test_reopen_refuses_shorter_recorded_file(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-short-file-") as temporary:
            root = Path(temporary)
            payload = b"a" * (128 * 1024)
            source = root / "source.bin"
            source.write_bytes(payload)
            manifest = _artifact_facts(
                {"wire/source.bin": source}, max_total_bytes=len(payload), max_objects=1
            )
            transfer_id = uuid.uuid4().hex
            receiver = SocketArchiveReceiver(
                root / "receiver",
                transfer_id=transfer_id,
                manifest=manifest,
                max_total_bytes=len(payload),
                max_objects=1,
                chunk_bytes=64 * 1024,
            ).start()
            _send_chunk(
                receiver.address,
                transfer_id,
                "wire/source.bin",
                0,
                payload[: 64 * 1024],
            )
            receiver.close()
            target = root / "receiver" / "objects" / "wire" / "source.bin"
            target.write_bytes(payload[: 64 * 1024 - 1])
            with self.assertRaisesRegex(IntegrityError, "transfer:resume_length"):
                SocketArchiveReceiver(
                    root / "receiver",
                    transfer_id=transfer_id,
                    manifest=manifest,
                    max_total_bytes=len(payload),
                    max_objects=1,
                    chunk_bytes=64 * 1024,
                )
            target.write_bytes(b"b" * 64 * 1024)
            with self.assertRaisesRegex(IntegrityError, "transfer:resume_hash"):
                SocketArchiveReceiver(
                    root / "receiver",
                    transfer_id=transfer_id,
                    manifest=manifest,
                    max_total_bytes=len(payload),
                    max_objects=1,
                    chunk_bytes=64 * 1024,
                )


@unittest.skipUnless(S3_URL, "real MinIO endpoint is required")
class TransferIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        RECOVERY_ROOT.mkdir(parents=True, exist_ok=True)
        cls.client = S3ArchiveStore.client_for_endpoint(S3_URL)
        s3_ready(cls.client, TEST_BUCKET)

    def temp_root(self):
        temporary = tempfile.TemporaryDirectory(prefix="inf037b-transfer-", dir=RECOVERY_ROOT)
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_capture_tcp_resume_both_stores_retrieve_and_reopen(self):
        root = self.temp_root()
        export_value, artifacts = make_capture_artifacts(root, wire_bytes=32 * 1024 * 1024)
        manifest = _artifact_facts(artifacts, max_total_bytes=BYTE_LIMIT, max_objects=OBJECT_LIMIT)
        transfer_id = uuid.uuid4().hex
        receiver = SocketArchiveReceiver(
            root / "receiver",
            transfer_id=transfer_id,
            manifest=manifest,
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
            chunk_bytes=2 * 1024 * 1024,
        ).start()
        self.addCleanup(receiver.close)
        receiver.inject_once("drop_ack")
        transfer_receipt = SocketArchiveTransfer(
            chunk_bytes=2 * 1024 * 1024, timeout_s=10, retries=3
        ).transfer(
            artifacts,
            receiver.address,
            transfer_id=transfer_id,
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
        )
        self.assertEqual(transfer_receipt["bytes"], sum(x["bytes"] for x in manifest.values()))
        self.assertTrue(any(x["event"] == "ack_dropped" for x in receiver.events))
        self.assertGreater(receiver.state.read()["files"]["wire/client-response.bin"]["bytes"], 0)
        transferred = receiver.artifact_paths()

        # Reopen the real POSIX offset journal and files after stopping the socket service.
        receiver.close()
        reopened_receiver = SocketArchiveReceiver(
            root / "receiver",
            transfer_id=transfer_id,
            manifest=manifest,
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
            chunk_bytes=2 * 1024 * 1024,
        )
        transferred = reopened_receiver.artifact_paths()
        self.assertEqual(set(transferred), set(manifest))

        recovery = DurableStore(root / "recovery-state", {"ready": True}, initialize=True)
        store = make_store(root)
        persisted = persist_to_both(
            recovery_store=recovery,
            s3_store=store,
            artifacts=transferred,
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
            recovery_readback=root / "recovery-readback",
            s3_readback=root / "s3-readback",
        )
        validate_export_archives(export_value, persisted["recovery"]["readback"])
        validate_export_archives(export_value, persisted["s3"]["readback"])
        self.assertEqual(
            file_facts(persisted["s3"]["readback"]["wire/client-response.bin"]),
            manifest["wire/client-response.bin"],
        )

        # Reopen both adapters as a new process would, then retrieve again by receipt.
        reopened_recovery = DurableStore(root / "recovery-state", {}, initialize=False)
        self.assertEqual(reopened_recovery.read(), {"ready": True})
        reopened_s3 = make_store(root, prefix=store.prefix)
        retrieved = reopened_s3.retrieve_archive_artifacts(
            persisted["s3"]["receipt"], root / "s3-reopened"
        )
        validate_export_archives(export_value, retrieved)

    def test_declared_allowance_file_through_sockets_and_both_stores(self):
        root = self.temp_root()
        source = root / "maximum-archive-wire.bin"
        block = bytes(range(256)) * 4096
        remaining = MAX_ARCHIVE_AS_WIRE_BYTES
        with source.open("xb") as stream:
            while remaining:
                chunk = block[: min(len(block), remaining)]
                stream.write(chunk)
                remaining -= len(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        artifacts = {"wire/maximum-archive-wire.bin": source}
        transfer_id = uuid.uuid4().hex
        byte_limit, object_limit = MAX_ARCHIVE_AS_WIRE_BYTES + 1, 1
        manifest = _artifact_facts(artifacts, max_total_bytes=byte_limit, max_objects=object_limit)
        receiver = SocketArchiveReceiver(
            root / "maximum-receiver",
            transfer_id=transfer_id,
            manifest=manifest,
            max_total_bytes=byte_limit,
            max_objects=object_limit,
            chunk_bytes=16 * 1024 * 1024,
        ).start()
        start = time.perf_counter()
        try:
            transfer_receipt = SocketArchiveTransfer(
                chunk_bytes=16 * 1024 * 1024,
                timeout_s=60,
                transfer_timeout_s=3600,
            ).transfer(
                artifacts,
                receiver.address,
                transfer_id=transfer_id,
                max_total_bytes=byte_limit,
                max_objects=object_limit,
            )
            socket_seconds = time.perf_counter() - start
            recovery = DurableStore(
                root / "maximum-recovery-state", {"ready": True}, initialize=True
            )
            s3_store = make_store(
                root,
                max_total_bytes=byte_limit,
                max_objects=object_limit,
            )
            persisted = persist_to_both(
                recovery_store=recovery,
                s3_store=s3_store,
                artifacts=receiver.artifact_paths(),
                max_total_bytes=byte_limit,
                max_objects=object_limit,
                recovery_readback=root / "maximum-recovery-readback",
                s3_readback=root / "maximum-s3-readback",
            )
            whole_seconds = time.perf_counter() - start
            expected = manifest["wire/maximum-archive-wire.bin"]
            self.assertEqual(transfer_receipt["bytes"], MAX_ARCHIVE_AS_WIRE_BYTES)
            self.assertEqual(
                file_facts(persisted["recovery"]["readback"]["wire/maximum-archive-wire.bin"]),
                expected,
            )
            self.assertEqual(
                file_facts(persisted["s3"]["readback"]["wire/maximum-archive-wire.bin"]),
                expected,
            )
            print(
                f"R437 maximum archive-as-wire: bytes={MAX_ARCHIVE_AS_WIRE_BYTES}, "
                f"socket={socket_seconds:.3f}s, both-stores-and-retrieval={whole_seconds:.3f}s, "
                f"attempts={transfer_receipt['attempts']}, "
                f"reconnects={transfer_receipt['reconnect_attempts']}, "
                f"reconnect_seconds={transfer_receipt['reconnect_seconds']:.6f}",
                flush=True,
            )
        finally:
            receiver.close()

    def test_late_ack_is_ignored_after_persisted_offset_query(self):
        root = self.temp_root()
        source = root / "payload.bin"
        source.write_bytes(b"payload" * 4096)
        manifest = _artifact_facts(
            {"wire/payload.bin": source}, max_total_bytes=BYTE_LIMIT, max_objects=OBJECT_LIMIT
        )
        transfer_id = uuid.uuid4().hex
        receiver = SocketArchiveReceiver(
            root / "receiver",
            transfer_id=transfer_id,
            manifest=manifest,
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
            chunk_bytes=1024 * 1024,
        ).start()
        self.addCleanup(receiver.close)
        receiver.inject_once("late_ack")
        result = SocketArchiveTransfer(chunk_bytes=1024 * 1024, timeout_s=0.05, retries=3).transfer(
            {"wire/payload.bin": source},
            receiver.address,
            transfer_id=transfer_id,
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
        )
        self.assertEqual(result["bytes"], source.stat().st_size)
        self.assertTrue(any(x["event"] == "ack_late" for x in receiver.events))

    def test_duplicate_and_stale_acknowledgements_refuse(self):
        for fault, expected in (
            ("duplicate_ack", "transfer:duplicate_ack"),
            ("stale_ack", "transfer:ack_join"),
        ):
            with self.subTest(fault=fault):
                root = self.temp_root()
                source = root / "payload.bin"
                source.write_bytes(b"x" * (64 * 1024))
                artifacts = {"wire/payload.bin": source}
                manifest = _artifact_facts(
                    artifacts, max_total_bytes=BYTE_LIMIT, max_objects=OBJECT_LIMIT
                )
                transfer_id = uuid.uuid4().hex
                receiver = SocketArchiveReceiver(
                    root / "receiver",
                    transfer_id=transfer_id,
                    manifest=manifest,
                    max_total_bytes=BYTE_LIMIT,
                    max_objects=OBJECT_LIMIT,
                    chunk_bytes=64 * 1024,
                ).start()
                self.addCleanup(receiver.close)
                receiver.inject_once(fault)
                with self.assertRaisesRegex(IntegrityError, expected):
                    SocketArchiveTransfer(chunk_bytes=64 * 1024, timeout_s=2, retries=1).transfer(
                        artifacts,
                        receiver.address,
                        transfer_id=transfer_id,
                        max_total_bytes=BYTE_LIMIT,
                        max_objects=OBJECT_LIMIT,
                    )

    def test_s3_readback_rejects_length_and_hash_mismatch(self):
        root = self.temp_root()
        source = root / "artifact.bin"
        source.write_bytes(b"a real object-store payload")
        store = make_store(root)
        receipt = persist_archive_artifacts(store, {"source/artifact.bin": source})
        ack = receipt["objects"]["source/artifact.bin"]

        self.client.put_object(
            Bucket=TEST_BUCKET,
            Key=ack["key"],
            Body=b"short",
            Metadata={"sha256": ack["sha256"]},
        )
        with self.assertRaisesRegex(IntegrityError, "transfer:s3_length"):
            store.retrieve_archive_artifacts(receipt, root / "wrong-length")

        self.client.put_object(
            Bucket=TEST_BUCKET,
            Key=ack["key"],
            Body=b"z" * ack["bytes"],
            Metadata={"sha256": ack["sha256"]},
        )
        with self.assertRaisesRegex(IntegrityError, "transfer:s3_hash_length"):
            store.retrieve_archive_artifacts(receipt, root / "wrong-hash")

    def test_dual_store_call_refuses_when_one_store_is_missing(self):
        root = self.temp_root()
        source = root / "artifact.bin"
        source.write_bytes(b"bounded")
        recovery = DurableStore(root / "recovery-state", {"ready": True}, initialize=True)
        with self.assertRaisesRegex(IntegrityError, "transfer:both_stores_required"):
            persist_to_both(
                recovery_store=recovery,
                s3_store=None,
                artifacts={"source/artifact.bin": source},
                max_total_bytes=BYTE_LIMIT,
                max_objects=OBJECT_LIMIT,
                recovery_readback=root / "recovery-readback",
                s3_readback=root / "s3-readback",
            )


@unittest.skipUnless(S3_URL and RESTART_PHASE == "before", "pre-restart MinIO phase only")
class MinioRestartWriteTests(unittest.TestCase):
    def test_write_durable_two_store_restart_checkpoint(self):
        client = S3ArchiveStore.client_for_endpoint(S3_URL)
        s3_ready(client, TEST_BUCKET)
        self.assertFalse(RESTART_ROOT.exists(), "recovery volume must be fresh for restart test")
        RESTART_ROOT.mkdir(parents=True)
        source = RESTART_ROOT / "source.bin"
        source.write_bytes(b"minio-container-restart-proof" * 4096)
        state = DurableStore(RESTART_ROOT / "recovery-state", {"checkpoint": 1}, initialize=True)
        store = S3ArchiveStore(
            S3ArchiveStore.client_for_endpoint(S3_URL),
            bucket=TEST_BUCKET,
            prefix="restart-checkpoint/round317",
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
        )
        persisted = persist_to_both(
            recovery_store=state,
            s3_store=store,
            artifacts={"wire/source.bin": source},
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
            recovery_readback=RESTART_ROOT / "recovery-first-readback",
            s3_readback=RESTART_ROOT / "s3-first-readback",
        )
        (RESTART_ROOT / "receipt.json").write_bytes(encode(persisted["s3"]["receipt"]))
        (RESTART_ROOT / "posix-manifest.json").write_bytes(
            encode(persisted["recovery"]["manifest"])
        )
        self.assertEqual(
            persisted["source_manifest_sha256"],
            sha(encode({"wire/source.bin": file_facts(source)})),
        )


@unittest.skipUnless(S3_URL and RESTART_PHASE == "after", "post-restart MinIO phase only")
class MinioRestartReadTests(unittest.TestCase):
    def test_retrieve_both_stores_after_minio_container_restart(self):
        client = S3ArchiveStore.client_for_endpoint(S3_URL)
        s3_ready(client, TEST_BUCKET)
        receipt = strict_json((RESTART_ROOT / "receipt.json").read_bytes())
        posix_manifest = strict_json((RESTART_ROOT / "posix-manifest.json").read_bytes())
        state = DurableStore(RESTART_ROOT / "recovery-state", {}, initialize=False)
        self.assertEqual(state.read(), {"checkpoint": 1})
        store = S3ArchiveStore(
            client,
            bucket=TEST_BUCKET,
            prefix="restart-checkpoint/round317",
            max_total_bytes=BYTE_LIMIT,
            max_objects=OBJECT_LIMIT,
        )
        s3_files = store.retrieve_archive_artifacts(receipt, RESTART_ROOT / "s3-after-restart")
        posix_files = retrieve_posix_artifacts(
            posix_manifest, RESTART_ROOT / "recovery-after-restart"
        )
        expected = {
            "bytes": (RESTART_ROOT / "source.bin").stat().st_size,
            "sha256": file_facts(RESTART_ROOT / "source.bin")["sha256"],
        }
        self.assertEqual(file_facts(s3_files["wire/source.bin"]), expected)
        self.assertEqual(file_facts(posix_files["wire/source.bin"]), expected)
