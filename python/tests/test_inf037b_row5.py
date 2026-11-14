import unittest

from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_row5 import (
    RecoveryAgreement,
    check_reservation_partition,
    expired_window,
)

LAST_APPLIED_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"
REVIEWED_ROLE_SHA256 = "10ddb8dbdebc9622cd02be459a5e199446bfb32f42986a9563de3f3a6a88c4ba"
PAID_BINDING_LAST_APPLIED = (
    '{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":'
    '{"annotations":{},"labels":{"m5-session":"mti-m5-row5-package-a"},'
    '"name":"gateway-endpoints","namespace":"mti-m5-row5-package-a"},"roleRef":'
    '{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"endpoint-reader"},'
    '"subjects":[{"kind":"ServiceAccount","name":"gateway",'
    '"namespace":"mti-m5-row5-package-a"}]}\n'
)


def role_control_fixture():
    import copy
    from types import SimpleNamespace

    from inference_platform.inf037b_row5 import RoleControl

    namespace = "mti-m5-row5-package-a"
    labels = {"m5-session": namespace}
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "name": "endpoint-reader",
            "namespace": namespace,
            "labels": copy.deepcopy(labels),
        },
        "rules": [
            {
                "apiGroups": ["discovery.k8s.io"],
                "resources": ["endpointslices"],
                "verbs": ["list"],
            }
        ],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": "gateway-endpoints",
            "namespace": namespace,
            "labels": copy.deepcopy(labels),
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "endpoint-reader",
        },
        "subjects": [{"kind": "ServiceAccount", "name": "gateway", "namespace": namespace}],
    }

    def server_shape(rendered, *, uid, resource_version):
        import json

        applied = copy.deepcopy(rendered)
        applied["metadata"]["annotations"] = {}
        applied_configuration = json.dumps(applied, sort_keys=True, separators=(",", ":")) + "\n"
        field_paths = {
            "f:metadata": {
                "f:annotations": {".": {}, f"f:{LAST_APPLIED_ANNOTATION}": {}},
                "f:labels": {".": {}, "f:m5-session": {}},
            }
        }
        if rendered["kind"] == "Role":
            field_paths["f:rules"] = {}
        else:
            field_paths["f:roleRef"] = {}
            field_paths["f:subjects"] = {}
        result = copy.deepcopy(rendered)
        result["metadata"].update(
            {
                "uid": uid,
                "resourceVersion": resource_version,
                "creationTimestamp": "2026-10-30T03:08:38Z",
                "annotations": {LAST_APPLIED_ANNOTATION: applied_configuration},
                "managedFields": [
                    {
                        "manager": "kubectl-client-side-apply",
                        "operation": "Update",
                        "apiVersion": "rbac.authorization.k8s.io/v1",
                        "time": "2026-10-30T03:08:38Z",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": field_paths,
                    }
                ],
            }
        )
        return result

    server_role = server_shape(role, uid="role-1", resource_version="590")
    server_binding = server_shape(binding, uid="binding-1", resource_version="591")
    server_binding["metadata"]["annotations"][LAST_APPLIED_ANNOTATION] = PAID_BINDING_LAST_APPLIED

    class FakeClock:
        now = 0

        def __call__(self):
            return self.now

        def sleep(self, seconds):
            self.now += round(seconds * 1_000_000_000)

    clock = FakeClock()

    class Port:
        def __init__(port):
            port.lag = {"revoke": [], "restore": []}
            port.role = copy.deepcopy(server_role)
            port.binding = copy.deepcopy(server_binding)
            port.calls = []
            port.echo_empty_rules_as_null = True

        def read_binding(port, namespace):
            return copy.deepcopy(port.binding)

        def read_role(port, namespace):
            return copy.deepcopy(port.role)

        def replace_role(port, namespace, role_update):
            if (
                role_update["metadata"]["resourceVersion"]
                != port.role["metadata"]["resourceVersion"]
            ):
                raise IntegrityError("conflict")
            server_metadata = port.role["metadata"]
            port.calls.append(copy.deepcopy(role_update))
            port.role = copy.deepcopy(role_update)
            for field in ("uid", "creationTimestamp", "managedFields"):
                if field not in port.role["metadata"]:
                    port.role["metadata"][field] = copy.deepcopy(server_metadata[field])
            if port.echo_empty_rules_as_null and port.role.get("rules") == []:
                port.role["rules"] = None
            port.role["metadata"]["resourceVersion"] = str(
                int(port.role["metadata"]["resourceVersion"]) + 1
            )

        def access_review(port, namespace, service_account, verb, *, deadline_ns=None):
            phase = "restore" if port.role["rules"] else "revoke"
            if deadline_ns is not None and verb == "list" and port.lag[phase]:
                value = port.lag[phase].pop(0)
                if isinstance(value, Exception):
                    raise value
                return value
            return verb == "list" and bool(port.role["rules"])

    port = Port()
    fixture = SimpleNamespace(
        role=role,
        binding=binding,
        namespace=namespace,
        clock=clock,
        deadline=30_000_000_000,
        port=port,
    )
    fixture.control = RoleControl(
        port,
        namespace,
        role,
        binding,
        REVIEWED_ROLE_SHA256,
        clock=clock,
        sleep=clock.sleep,
    )
    return fixture


class Row5TimingTests(unittest.TestCase):
    def test_expired_window_accounts_for_spread_and_snapshot_latency(self):
        self.assertEqual(expired_window([100, 100], 8000, 2000, 50), (8100, 10100))
        self.assertEqual(expired_window([100, 2000], 8000, 2000, 50), (10000, 10100))
        with self.assertRaisesRegex(IntegrityError, "fitness:expired_snapshot_window"):
            expired_window([100, 2200], 8000, 2000, 0)
        with self.assertRaisesRegex(IntegrityError, "fitness:expired_snapshot_window"):
            expired_window([100, 2000], 8000, 2000, 100)
        with self.assertRaisesRegex(IntegrityError, "fitness:expired_snapshot_inputs"):
            expired_window([100], 8000, 2000, 0)

    def test_restore_403_restarts_observation_and_respects_deadline(self):
        observation = RecoveryAgreement(7000)
        self.assertFalse(observation.observe(1000, known=True))
        self.assertFalse(observation.observe(2500, known=False, reason="403"))
        self.assertFalse(observation.observe(2600, known=True))
        self.assertFalse(observation.observe(4500, known=True))
        self.assertTrue(observation.observe(4600, known=True))
        self.assertEqual(observation.restarts, [2500])
        self.assertEqual(observation.restart_reasons, ["403"])
        with self.assertRaisesRegex(IntegrityError, "fitness:agreement_order"):
            observation.observe(4500, known=True)
        with self.assertRaisesRegex(IntegrityError, "fitness:agreement_deadline"):
            observation.observe(7001, known=True)
        with self.assertRaisesRegex(IntegrityError, "fitness:agreement_inputs"):
            RecoveryAgreement(0, 0)

    def test_reservation_classes_are_disjoint(self):
        gateway = "rsv_" + "0" * 32
        diagnostic = "rsv_d1a6" + "0" * 28
        check_reservation_partition([gateway], [{"reservation_id": diagnostic}])
        chance_prefixed = "rsv_d1a6" + "1" * 28
        check_reservation_partition(
            [gateway, chance_prefixed], [{"reservation_id": diagnostic}], control_ids=[gateway]
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            check_reservation_partition([diagnostic], [{"reservation_id": diagnostic}])
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            check_reservation_partition([chance_prefixed], [], control_ids=[chance_prefixed])
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_id_in_diagnostic"):
            check_reservation_partition([gateway], [{"reservation_id": gateway}])
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_receipt_duplicate"):
            check_reservation_partition(
                [gateway], [{"reservation_id": diagnostic}, {"reservation_id": diagnostic}]
            )
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_reservation_invalid"):
            check_reservation_partition([["invalid"]], [])
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_reservation_invalid"):
            check_reservation_partition(None, [])
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_reservation_invalid"):
            check_reservation_partition([gateway], [], control_ids=["rsv_" + "3" * 32])
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_id_in_diagnostic"):
            check_reservation_partition([gateway], None)
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_id_in_diagnostic"):
            check_reservation_partition([gateway], ["invalid"])


class RoleControlTests(unittest.TestCase):
    def setUp(self):
        fixture = role_control_fixture()
        self.role = fixture.role
        self.binding = fixture.binding
        self.namespace = fixture.namespace
        self.clock = fixture.clock
        self.deadline = fixture.deadline
        self.port = fixture.port
        self.control = fixture.control

    def test_revoke_restore_normalize_api_server_null_rules(self):
        import hashlib

        from inference_platform.inf037b_row5 import canonical_role

        self.control.revoke(envelope_deadline_ns=self.deadline)
        self.assertEqual(self.port.calls[0]["metadata"]["resourceVersion"], "590")
        self.assertIsNone(self.port.role["rules"])
        self.control.restore(envelope_deadline_ns=self.deadline)
        self.assertEqual(self.port.calls[1]["metadata"]["resourceVersion"], "591")
        self.assertEqual(canonical_role(self.port.role), canonical_role(self.role))
        self.assertEqual([item["phase"] for item in self.control.actuations], ["revoke", "restore"])
        self.assertTrue(self.control.actuations[1]["restored_matches_reviewed_sha256"])
        self.assertEqual(
            self.control.actuations[1]["canonical_projection_sha256"],
            hashlib.sha256(canonical_role(self.role)).hexdigest(),
        )
        self.assertEqual(self.control.actuations[1]["precondition_resource_version"], "591")
        self.assertEqual(self.control.actuations[1]["readback_resource_version"], "592")
        self.assertEqual(
            self.port.binding["metadata"]["annotations"][LAST_APPLIED_ANNOTATION],
            PAID_BINDING_LAST_APPLIED,
        )
        self.assertTrue(self.port.binding["metadata"]["managedFields"])
        self.assertTrue(self.port.role["metadata"]["managedFields"])
        self.assertNotIn(LAST_APPLIED_ANNOTATION, self.port.role["metadata"].get("annotations", {}))

    def test_reviewed_role_sha256_is_unchanged(self):
        import hashlib

        from inference_platform.inf037b_row5 import canonical_role

        self.assertEqual(
            hashlib.sha256(canonical_role(self.role)).hexdigest(), REVIEWED_ROLE_SHA256
        )

    def test_projection_keeps_labels_and_non_apply_annotations(self):
        import copy

        from inference_platform.inf037b_row5 import canonical_binding, canonical_role

        for obj, project in (
            (self.role, canonical_role),
            (self.binding, canonical_binding),
        ):
            changed_label = copy.deepcopy(obj)
            changed_label["metadata"]["labels"]["example.com/x"] = "y"
            self.assertNotEqual(project(changed_label), project(obj))

            changed_annotation = copy.deepcopy(obj)
            changed_annotation["metadata"]["annotations"] = {"example.com/x": "y"}
            self.assertNotEqual(project(changed_annotation), project(obj))

            apply_annotated = copy.deepcopy(obj)
            apply_annotated["metadata"]["annotations"] = {
                LAST_APPLIED_ANNOTATION: "kubectl snapshot"
            }
            self.assertEqual(project(apply_annotated), project(obj))

    def test_extra_server_binding_annotation_still_refuses(self):
        self.port.binding["metadata"]["annotations"]["example.com/x"] = "y"
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_binding"):
            self.control.revoke(envelope_deadline_ns=self.deadline)

    def test_extra_server_role_annotation_still_refuses(self):
        self.port.role["metadata"]["annotations"]["example.com/x"] = "y"
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_initial_readback"):
            self.control.revoke(envelope_deadline_ns=self.deadline)

    def test_mutant_without_last_applied_exclusion_fails_at_binding(self):
        from unittest.mock import patch

        import inference_platform.inf037b_row5 as row5

        with patch.object(
            row5,
            "_projected_annotations",
            side_effect=lambda metadata: metadata.get("annotations", {}),
        ):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_binding"):
                self.control.revoke(envelope_deadline_ns=self.deadline)

    def test_revoke_restore_also_accept_fake_empty_list_echo(self):
        from inference_platform.inf037b_row5 import canonical_role

        self.port.echo_empty_rules_as_null = False
        self.control.revoke(envelope_deadline_ns=self.deadline)
        self.assertEqual(self.port.role["rules"], [])
        self.control.restore(envelope_deadline_ns=self.deadline)
        self.assertEqual(canonical_role(self.port.role), canonical_role(self.role))

    def test_canonical_role_normalizes_missing_and_null_optional_lists(self):
        import copy

        from inference_platform.inf037b_row5 import canonical_role

        empty = copy.deepcopy(self.role)
        empty["rules"] = []
        missing = copy.deepcopy(empty)
        del missing["rules"]
        null = copy.deepcopy(empty)
        null["rules"] = None
        null["metadata"].update(ownerReferences=None, finalizers=None)
        self.assertEqual(canonical_role(empty), canonical_role(missing))
        self.assertEqual(canonical_role(empty), canonical_role(null))

    def test_effective_watch_grant_outside_reviewed_role_refuses(self):
        from unittest.mock import patch

        with patch.object(self.port, "access_review", return_value=True):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_initial_access"):
                self.control.revoke(envelope_deadline_ns=self.deadline)

    def test_role_put_must_advance_resource_version(self):
        import copy

        original = self.port.replace_role

        def no_increment(namespace, role):
            self.port.calls.append(copy.deepcopy(role))
            self.port.role = copy.deepcopy(role)

        self.port.replace_role = no_increment
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_revoke_resource_version"):
            self.control.revoke(envelope_deadline_ns=self.deadline)
        self.port.replace_role = original

    def test_revoke_and_restore_poll_lagging_reviews_and_record_each(self):
        self.port.lag["revoke"] = [True, OSError("transient"), False]
        self.control.revoke(envelope_deadline_ns=self.deadline)
        revoke = [r for r in self.control.reviews if r["phase"] == "revoke"]
        self.assertEqual(
            [r.get("allowed") for r in revoke if r["verb"] == "list"], [True, None, False]
        )
        self.assertEqual(
            [r.get("error_class") for r in revoke if r.get("error_class")], ["OSError"]
        )
        self.assertGreaterEqual(self.clock.now, 200_000_000)
        self.port.lag["restore"] = [False, True]
        self.control.restore(envelope_deadline_ns=self.deadline)
        restore = [r for r in self.control.reviews if r["phase"] == "restore"]
        self.assertEqual([r.get("allowed") for r in restore if r["verb"] == "list"], [False, True])
        self.assertGreaterEqual(self.clock.now, 300_000_000)

    def test_review_deadline_refuses_after_bounded_polling(self):
        self.port.lag["revoke"] = [True] * 20
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_revoke_access"):
            self.control.revoke(envelope_deadline_ns=250_000_000)
        self.assertEqual(self.clock.now, 250_000_000)
        self.assertGreaterEqual(len(self.control.reviews), 4)
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_envelope_deadline"):
            self.control.restore(envelope_deadline_ns=self.clock.now)

    def test_five_second_review_subbound_is_not_extended_by_envelope(self):
        self.port.lag["revoke"] = [True] * 100
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_revoke_access"):
            self.control.revoke(envelope_deadline_ns=self.deadline)
        self.assertEqual(self.clock.now, 5_000_000_000)

    def test_capture_failure_cannot_be_hidden_by_later_review(self):
        self.port.lag["revoke"] = [IntegrityError("capture:lost"), False]
        with self.assertRaisesRegex(IntegrityError, "capture:lost"):
            self.control.revoke(envelope_deadline_ns=self.deadline)
        self.assertEqual(len(self.port.lag["revoke"]), 1)
        self.assertEqual(self.clock.now, 0)

    def test_restore_review_timeout_uses_envelope_bound(self):
        self.control.revoke(envelope_deadline_ns=self.deadline)
        self.port.lag["restore"] = [False] * 20
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_restore_access"):
            self.control.restore(envelope_deadline_ns=250_000_000)
        self.assertEqual(self.clock.now, 250_000_000)
        self.assertTrue(
            any(r["phase"] == "restore" and r.get("allowed") is False for r in self.control.reviews)
        )

    def test_restore_refuses_intervening_role_change(self):
        self.control.revoke(envelope_deadline_ns=self.deadline)
        self.port.role["rules"] = [{"verbs": ["*"]}]
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_restore_precondition"):
            self.control.restore(envelope_deadline_ns=self.deadline)
        self.assertEqual(len(self.port.calls), 1)

    def test_rbac_refusals_are_named(self):
        import copy
        import hashlib
        from unittest.mock import patch

        from inference_platform.inf037b_row5 import RoleControl, canonical_role

        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_review_hash"):
            RoleControl(self.port, self.namespace, self.role, self.binding, "bad")
        wrong = copy.deepcopy(self.role)
        wrong["rules"] = []
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_review_role"):
            RoleControl(
                self.port,
                self.namespace,
                wrong,
                self.binding,
                hashlib.sha256(canonical_role(wrong)).hexdigest(),
            )
        wrong_binding = copy.deepcopy(self.binding)
        wrong_binding["subjects"] = []
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_review_binding"):
            RoleControl(
                self.port,
                self.namespace,
                self.role,
                wrong_binding,
                hashlib.sha256(canonical_role(self.role)).hexdigest(),
            )
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_no_revoke"):
            self.control.restore(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "read_binding", return_value={}):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_binding"):
                self.control.revoke(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "read_role", return_value=wrong):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_initial_readback"):
                self.control.revoke(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "access_review", return_value=None):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_access_indeterminate"):
                self.control.revoke(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "access_review", return_value=False):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_initial_access"):
                self.control.revoke(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "replace_role"):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_revoke_readback"):
                self.control.revoke(envelope_deadline_ns=self.deadline)

        def lagging_grant(namespace, service_account, verb, *, deadline_ns=None):
            if self.port.role["rules"]:
                return verb == "list"
            return True

        with patch.object(self.port, "access_review", side_effect=lagging_grant):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_revoke_access"):
                self.control.revoke(envelope_deadline_ns=self.deadline)

    def test_restore_readback_and_access_fail_closed(self):
        from unittest.mock import patch

        self.control.revoke(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "replace_role"):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_restore_readback"):
                self.control.restore(envelope_deadline_ns=self.deadline)
        with patch.object(self.port, "access_review", return_value=False):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_restore_access"):
                self.control.restore(envelope_deadline_ns=self.deadline)


class RBACTransportTests(unittest.TestCase):
    def test_real_local_http_roundtrip_and_subject_access_review(self):
        import json
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from inference_platform.inf037b_row5 import BoundedRBACHTTP, KubernetesRolePort

        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/conflict":
                    self.send_response(409)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                elif self.path == "/oversize":
                    data = b"x" * 8_388_609
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    try:
                        self.wfile.write(data)
                    except (ConnectionResetError, BrokenPipeError):
                        pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, body))
                response = json.dumps({"status": {"allowed": True}}).encode()
                self.send_response(201)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        captured = []
        try:
            http = BoundedRBACHTTP(
                f"http://127.0.0.1:{server.server_port}",
                token=lambda: "local",
                deadline_ns=time.monotonic_ns() + 5_000_000_000,
                retain=lambda *args: captured.append(args),
                local_test=True,
            )
            port = KubernetesRolePort(http)
            self.assertTrue(port.access_review("test", "gateway", "list"))
            self.assertEqual(requests[0][1]["spec"]["user"], "system:serviceaccount:test:gateway")
            self.assertEqual(
                requests[0][1]["spec"]["resourceAttributes"]["resource"], "endpointslices"
            )
            self.assertGreaterEqual(len(captured), 2)
            self.assertTrue(
                any(
                    item[3].get("direction") == "response_headers" and item[3].get("status") == 201
                    for item in captured
                )
            )
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_response"):
                http.json_request("GET", "/conflict")
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_size"):
                http.json_request("GET", "/oversize")
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_namespace"):
                port.read_role("../bad")
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_review_request"):
                port.access_review("test", "wrong", "list")
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_request"):
                http.json_request("PATCH", "/")
            http.deadline_ns = time.monotonic_ns() - 1
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_deadline"):
                http.json_request("GET", "/")
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_endpoint"):
                BoundedRBACHTTP(
                    "http://example.com",
                    token=lambda: "x",
                    deadline_ns=0,
                    retain=lambda *args: None,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_real_http_role_updates_poll_lagging_reviews(self):
        import copy
        import hashlib
        import json
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from inference_platform.inf037b_row5 import (
            BoundedRBACHTTP,
            KubernetesRolePort,
            RoleControl,
            canonical_role,
        )

        fixture = role_control_fixture()
        state = {
            "role": copy.deepcopy(fixture.port.role),
            "binding": copy.deepcopy(fixture.port.binding),
            "lag": 0,
            "reviews": [],
        }

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, obj, status=200):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.reply(state["binding"] if "/rolebindings/" in self.path else state["role"])

            def do_PUT(self):
                role = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                server_metadata = state["role"]["metadata"]
                if role["metadata"]["resourceVersion"] != server_metadata["resourceVersion"]:
                    self.reply({}, 409)
                    return
                for field in ("uid", "creationTimestamp", "managedFields"):
                    if field not in role["metadata"]:
                        role["metadata"][field] = copy.deepcopy(server_metadata[field])
                role["metadata"]["resourceVersion"] = str(
                    int(role["metadata"]["resourceVersion"]) + 1
                )
                state["role"], state["lag"] = role, 2
                self.reply(role)

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                verb = request["spec"]["resourceAttributes"]["verb"]
                allowed = verb == "list" and bool(state["role"]["rules"])
                if verb == "list" and state["lag"]:
                    allowed = not allowed
                    state["lag"] -= 1
                state["reviews"].append((verb, allowed))
                self.reply({"status": {"allowed": allowed}}, 201)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        retained = []
        deadline = time.monotonic_ns() + 5_000_000_000
        try:
            http = BoundedRBACHTTP(
                f"http://127.0.0.1:{server.server_port}",
                token=lambda: "fixture",
                deadline_ns=deadline,
                retain=lambda *args: retained.append(args),
                local_test=True,
            )
            control = RoleControl(
                KubernetesRolePort(http),
                fixture.namespace,
                fixture.role,
                fixture.binding,
                hashlib.sha256(canonical_role(fixture.role)).hexdigest(),
            )
            control.revoke(envelope_deadline_ns=deadline)
            control.restore(envelope_deadline_ns=deadline)
            self.assertEqual(canonical_role(state["role"]), canonical_role(fixture.role))
            self.assertEqual(
                sum(r["phase"] == "revoke" and r["verb"] == "list" for r in control.reviews), 3
            )
            self.assertEqual(
                sum(r["phase"] == "restore" and r["verb"] == "list" for r in control.reviews), 3
            )
            self.assertEqual(
                sum(
                    item[3].get("direction") == "response_headers" and item[3].get("status") == 201
                    for item in retained
                ),
                len(state["reviews"]),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_access_review_forwards_subdeadline(self):
        from unittest.mock import Mock

        from inference_platform.inf037b_row5 import KubernetesRolePort

        http = Mock()
        http.json_request.return_value = {"status": {"allowed": True}}
        self.assertTrue(
            KubernetesRolePort(http).access_review("test", "gateway", "list", deadline_ns=123)
        )
        self.assertEqual(http.json_request.call_args.kwargs["deadline_ns"], 123)

    def test_access_review_indeterminate_is_refused(self):
        from inference_platform.inf037b_row5 import KubernetesRolePort

        class HTTP:
            def json_request(self, *args):
                return {"status": {"allowed": False, "evaluationError": "unavailable"}}

        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_access_indeterminate"):
            KubernetesRolePort(HTTP()).access_review("test", "gateway", "list")

    def test_transport_enforces_deadline_during_and_after_read(self):
        from unittest.mock import MagicMock, patch

        from inference_platform.inf037b_row5 import BoundedRBACHTTP

        for ticks in ([0, 0, 100, 100], [0, 0, 0, 100, 100], [0, 0, 0, 0, 0, 100, 100]):
            http = BoundedRBACHTTP(
                "http://localhost",
                token=lambda: "x",
                deadline_ns=50,
                retain=lambda *args: None,
                local_test=True,
            )
            connection = MagicMock()
            response = connection.getresponse.return_value
            response.status = 200
            response.isclosed.return_value = False
            response.read1.return_value = b"{}"
            with (
                patch("http.client.HTTPConnection", return_value=connection),
                patch("time.monotonic_ns", side_effect=ticks),
            ):
                with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_deadline"):
                    http.json_request("GET", "/")

        http = BoundedRBACHTTP(
            "http://localhost",
            token=lambda: "x",
            deadline_ns=50,
            retain=lambda *args: None,
            local_test=True,
        )
        connection = MagicMock()
        connection.getresponse.return_value.isclosed.return_value = True
        connection.getresponse.return_value.status = 200
        with (
            patch("http.client.HTTPConnection", return_value=connection),
            patch("time.monotonic_ns", side_effect=[0, 0, 100, 100]),
        ):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_deadline"):
                http.json_request("GET", "/")

        http = BoundedRBACHTTP(
            "http://localhost",
            token=lambda: "x",
            deadline_ns=500,
            retain=lambda *args: None,
            local_test=True,
        )
        connection = MagicMock()
        connection.getresponse.return_value.isclosed.return_value = False
        with (
            patch("http.client.HTTPConnection", return_value=connection),
            patch("time.monotonic_ns", side_effect=[0, 0, 0, 100, 100]),
        ):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_transport_deadline"):
                http.json_request("GET", "/", deadline_ns=50)


if __name__ == "__main__":
    unittest.main()
