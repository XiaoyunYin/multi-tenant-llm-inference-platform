"""Synthetic retained-record checks for the row5 capture replay."""

import copy
import tempfile
import unittest
from pathlib import Path

from inference_platform.inf037b_archive import IntegrityError, encode
from inference_platform.inf037b_row5_replay import (
    CONTROL_ORDER,
    GATEWAYS,
    _client_requests,
    _gateway_reservation_map,
    _prepare_saved_composition_inputs,
    _reconstruct_recovery_observations,
    _reconstruct_wrapper_times,
)


def transaction(sequence, method, path, start_ns):
    request = {"kind": "SubjectAccessReview", "spec": {"resourceAttributes": {"verb": "list"}}}
    response = {"status": {"allowed": True}}
    return {
        "sequence": sequence,
        "method": method,
        "path": path,
        "request": request,
        "response": response,
        "request_start_ns": start_ns,
        "response_end_ns": start_ns + 10,
    }


def install_poll(gateway, start_ns, end_ns, header_sequence, poll_seq, *, known):
    members = [
        {"ready": known, "sampled": True, "healthy": True},
        {"ready": known, "sampled": True, "healthy": True},
    ]
    raw = {
        "event": "install",
        "mono_ns": start_ns + 1,
        "data": {
            "poll_seq": poll_seq,
            "error_class": "" if known else "403 Forbidden",
            "membership_known": known,
            "members": members,
        },
    }
    return {
        "gateway": gateway,
        "start_ns": start_ns,
        "last_end_ns": end_ns,
        "header_sequence": header_sequence,
        "raw_records": [raw],
    }


class ReplayRecordTests(unittest.TestCase):
    def rbac_inputs(self):
        role = "/apis/rbac.authorization.k8s.io/v1/namespaces/ns/roles/endpoint-reader"
        binding = "/apis/rbac.authorization.k8s.io/v1/namespaces/ns/rolebindings/gateway-endpoints"
        review_path = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
        transactions = [
            transaction(100, "GET", binding, 1000),
            transaction(101, "POST", review_path, 1100),
            transaction(102, "POST", review_path, 1200),
            transaction(103, "GET", role, 1300),
            transaction(104, "PUT", role, 1400),
            transaction(105, "GET", role, 1500),
            transaction(106, "POST", review_path, 1600),
            transaction(107, "POST", review_path, 1700),
            transaction(108, "GET", role, 1800),
            transaction(109, "GET", binding, 1900),
            transaction(110, "PUT", role, 2000),
            transaction(111, "GET", role, 2100),
            transaction(112, "GET", role, 2200),
            transaction(113, "POST", review_path, 2300),
            transaction(114, "POST", review_path, 2400),
            transaction(115, "GET", binding, 2500),
        ]
        reviews = [
            ("initial", "list", True),
            ("initial", "watch", False),
            ("revoke", "list", False),
            ("revoke", "watch", False),
            ("restore", "list", True),
            ("restore", "watch", False),
        ]
        for tx, (_, verb, allowed) in zip(
            [transactions[i] for i in (1, 2, 6, 7, 13, 14)], reviews, strict=True
        ):
            tx["request"]["spec"]["resourceAttributes"]["verb"] = verb
            tx["response"]["status"]["allowed"] = allowed
        semantics = {
            "reviewed_sha256": "b" * 64,
            "actions": [{"phase": "revoke"}, {"phase": "restore"}],
            "reviews": [
                {"phase": phase, "verb": verb, "allowed": allowed}
                for phase, verb, allowed in reviews
            ],
            "restore_success": True,
        }
        polls = {
            "gateway0": [
                install_poll("gateway0", 1000, 1500, 1, 1, known=True),
                install_poll("gateway0", 1600, 1800, 2, 2, known=True),
                install_poll("gateway0", 2010, 2060, 6, 3, known=True),
            ],
            "gateway1": [
                install_poll("gateway1", 1100, 1550, 3, 1, known=True),
                install_poll("gateway1", 1700, 1890, 4, 2, known=True),
                install_poll("gateway1", 2000, 2050, 5, 3, known=True),
            ],
        }
        return semantics, transactions, polls

    def replayed_inputs(self):
        grouped = {}
        proofs = {}
        for name in CONTROL_ORDER:
            offers = [
                {"request_id": f"{name}-{gateway}", "gateway_uid": gateway} for gateway in GATEWAYS
            ]
            grouped[name] = offers
            proofs[name] = {
                "gateways": {gateway: {"proof": name} for gateway in GATEWAYS},
                "diagnostic": {"proof": name},
            }
        return {
            "grouped_offers": grouped,
            "proofs_by_control": proofs,
            "runtime_descriptor_sha256": "a" * 64,
        }

    def test_client_request_end_uses_last_client_row_and_keeps_wire_time_for_snapshots(self):
        rows, wire = [], []
        gateway_sequences = {gateway: 0 for gateway in GATEWAYS}
        for index in range(len(CONTROL_ORDER) * len(GATEWAYS)):
            gateway = GATEWAYS[index % len(GATEWAYS)]
            request_id = f"offer-{index}"
            start_ns = 10_000 + index * 100
            row_end_ns = start_ns + 10
            wire_end_ns = start_ns + 15
            sequence = gateway_sequences[gateway]
            gateway_sequences[gateway] += 2
            rows.extend(
                [
                    {
                        "source_kind": "client",
                        "source_seq": sequence,
                        "capture_start_mono_ns": start_ns,
                        "capture_end_mono_ns": start_ns + 1,
                        "payload": {
                            "event": "offer",
                            "request_id": request_id,
                            "gateway_uid": gateway,
                            "offer_index": index,
                            "prefix_id": "row5",
                            "config_sha256": "a" * 64,
                            "scheduled_ms": start_ns // 1_000_000,
                        },
                    },
                    {
                        "source_kind": "client",
                        "source_seq": sequence + 1,
                        "capture_start_mono_ns": start_ns,
                        "capture_end_mono_ns": row_end_ns,
                        "payload": {"event": "terminal", "request_id": request_id},
                    },
                ]
            )
            source = "client:" + gateway
            request_header = f"gateway-{index}"
            wire.extend(
                [
                    (
                        {
                            "source": source,
                            "start_ns": start_ns,
                            "end_ns": start_ns + 2,
                            "metadata": {"headers": [["X-Request-ID", request_header]]},
                        },
                        b"",
                    ),
                    (
                        {
                            "source": source,
                            "start_ns": start_ns,
                            "end_ns": wire_end_ns,
                            "metadata": {"client_request_end": True},
                        },
                        b"",
                    ),
                ]
            )

        _, requests, request_times = _client_requests(rows, wire)
        first = rows[0]
        request_id = first["payload"]["request_id"]
        self.assertEqual(requests[request_id]["end_ns"], first["capture_start_mono_ns"] + 10)
        self.assertEqual(
            request_times[request_id],
            (first["capture_start_mono_ns"], first["capture_start_mono_ns"] + 15),
        )

    def test_saved_control_offer_id_mismatch_refuses(self):
        replayed = self.replayed_inputs()
        all_offers = [offer for name in CONTROL_ORDER for offer in replayed["grouped_offers"][name]]
        controls = [
            offer
            for name in ("unknown", "expired", "post_outage_known2")
            for offer in replayed["grouped_offers"][name]
        ]
        evidence = {
            "gateway_config_captures": {
                gateway: {
                    "root": "C:\\host\\captures\\runtime",
                    "expected_descriptor_sha256": replayed["runtime_descriptor_sha256"],
                }
                for gateway in GATEWAYS
            }
        }
        saved = {"row5_evidence": evidence, "row5_control_requests": copy.deepcopy(controls)}
        saved["row5_control_requests"][0]["request_id"] = "changed-control-id"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IntegrityError, "row5_replay:offer_ids"):
                _prepare_saved_composition_inputs(replayed, directory, saved, all_offers)

    def test_saved_offer_duplicates_refuse_with_specific_reason(self):
        replayed = self.replayed_inputs()
        all_offers = [offer for name in CONTROL_ORDER for offer in replayed["grouped_offers"][name]]
        controls = [
            offer
            for name in ("unknown", "expired", "post_outage_known2")
            for offer in replayed["grouped_offers"][name]
        ]
        evidence = {
            "gateway_config_captures": {
                gateway: {
                    "root": "C:\\host\\captures\\runtime",
                    "expected_descriptor_sha256": replayed["runtime_descriptor_sha256"],
                }
                for gateway in GATEWAYS
            }
        }
        duplicate = copy.deepcopy(all_offers)
        duplicate[-1] = copy.deepcopy(duplicate[0])
        saved = {"row5_evidence": evidence, "row5_control_requests": controls}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IntegrityError, "row5_replay:offer_duplicate"):
                _prepare_saved_composition_inputs(replayed, directory, saved, duplicate)

    def test_rbac_split_review_zip_restore_cursor_and_install_order(self):
        rbac, transactions, polls = self.rbac_inputs()
        timed, restore, cursor = _reconstruct_wrapper_times(rbac, transactions, polls)

        self.assertEqual(timed["actions"][0]["end_ns"], transactions[8]["response_end_ns"])
        self.assertEqual(timed["actions"][1]["start_ns"], transactions[9]["request_start_ns"])
        self.assertEqual(timed["envelope_start_ns"], transactions[0]["request_start_ns"])
        self.assertEqual(
            [review["start_ns"] for review in timed["reviews"]],
            [transactions[index]["request_start_ns"] for index in (1, 2, 6, 7, 13, 14)],
        )
        self.assertEqual(restore["start_ns"], 1600)
        self.assertEqual(cursor, 1890)

        observations = _reconstruct_recovery_observations(polls, cursor)
        self.assertEqual([item["gateway_uid"] for item in observations], ["gateway1", "gateway0"])
        self.assertEqual([item["known"] for item in observations], [False, True])
        self.assertEqual(observations[0]["reason"], "unknown")
        self.assertIsNone(observations[1]["reason"])
        self.assertTrue(
            all(item["time_ms"] == item["read_mono_ns"] // 1_000_000 for item in observations)
        )

    def test_terminal_only_reservation_is_registered_and_conflicts_refuse(self):
        terminal_id = "rsv_terminal"
        prefixes = {
            "gateway0": encode(
                {
                    "event": "terminal",
                    "data": {"reservation_id": terminal_id, "request_id": "req_a"},
                }
            ),
            "gateway1": b"",
        }
        self.assertEqual(_gateway_reservation_map(prefixes), {terminal_id: "req_a"})
        prefixes["gateway1"] = encode(
            {
                "event": "terminal",
                "data": {"reservation_id": terminal_id, "request_id": "req_b"},
            }
        )
        with self.assertRaisesRegex(IntegrityError, "row5_replay:gateway_reservation"):
            _gateway_reservation_map(prefixes)

    def test_saved_inputs_merge_proofs_rebase_roots_and_check_offer_ids(self):
        replayed = self.replayed_inputs()
        all_offers = [offer for name in CONTROL_ORDER for offer in replayed["grouped_offers"][name]]
        controls = [
            offer
            for name in ("unknown", "expired", "post_outage_known2")
            for offer in replayed["grouped_offers"][name]
        ]
        evidence = {
            "gateway_config_captures": {
                gateway: {
                    "root": "C:\\host\\captures\\runtime",
                    "expected_descriptor_sha256": replayed["runtime_descriptor_sha256"],
                }
                for gateway in GATEWAYS
            },
            "known": {"stale": True},
            "refusals": {"stale": True},
            "diagnostics": {"stale": True},
        }
        saved = {"row5_evidence": evidence, "row5_control_requests": controls}
        with tempfile.TemporaryDirectory() as directory:
            requests, merged = _prepare_saved_composition_inputs(
                replayed, directory, saved, all_offers
            )
            self.assertEqual(
                [item["request_id"] for item in requests],
                [item["request_id"] for item in all_offers],
            )
            self.assertEqual(
                merged["gateway_config_captures"]["gateway0"]["root"],
                str(Path(directory).resolve() / "captures" / "runtime"),
            )
            self.assertEqual(merged["known"]["known0"]["gateway0"], {"proof": "known0"})
            self.assertEqual(merged["refusals"]["unknown"]["gateway1"], {"proof": "unknown"})
            self.assertEqual(merged["diagnostics"]["expired"], {"proof": "expired"})

            bad_descriptor = {
                "row5_evidence": {
                    **evidence,
                    "gateway_config_captures": {
                        **evidence["gateway_config_captures"],
                        "gateway1": {
                            **evidence["gateway_config_captures"]["gateway1"],
                            "expected_descriptor_sha256": "f" * 64,
                        },
                    },
                },
                "row5_control_requests": controls,
            }
            with self.assertRaisesRegex(IntegrityError, "row5_replay:descriptor_hash"):
                _prepare_saved_composition_inputs(replayed, directory, bad_descriptor, all_offers)

            with self.assertRaisesRegex(IntegrityError, "row5_replay:offer_ids"):
                _prepare_saved_composition_inputs(replayed, directory, saved, all_offers[:-1])


if __name__ == "__main__":
    unittest.main()
