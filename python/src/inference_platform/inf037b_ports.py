"""V4 gate/capacity/backstop adapters with durable intents and injected byte I/O.

Transport is an authenticated, bounded authority/executor protocol, NOT an EC2
Describe response. It must settle operation fences durably and deduplicate keys.
Direct eventually consistent SDK responses cannot implement this interface.
No transport implementation, AWS client, CLI or paid entry point is enabled here.
"""

import copy
import re
import secrets
import subprocess
from dataclasses import dataclass

from .inf037b_archive import encode, sha, strict_json
from .inf037b_authority import validate_cancel_receipt
from .inf037b_controller import ApplyNotExecuted, ReviewedPlan
from .inf037b_durable_ports import DurableStore
from .inf037b_resolver import exact, integer, require
from .m5_infra_safety import verify_gpu_plan


class AuthorityUnavailable(OSError):
    """Unknown is never converted into absence, permission to retry, or cleanup."""


class Authority:
    def __init__(self, identity, namespace, transport, timeout_ms=2000):
        require(type(identity) is str and bool(identity), "ports:authority_identity")
        require(callable(transport), "ports:transport")
        require(integer(timeout_ms) and 0 < timeout_ms <= 10_000, "ports:timeout")
        self.identity, self.namespace = identity, namespace
        self.transport, self.timeout_ms = transport, timeout_ms

    def call(self, operation, key, minimum, body):
        request = encode(
            {
                "schema": "inf037b-authority-v1",
                "authority_id": self.identity,
                "namespace": self.namespace,
                "operation": operation,
                "key": key,
                "minimum_sequence": minimum,
                "nonce": secrets.token_hex(16),
                "body": body,
            }
        )
        try:
            answer = strict_json(self.transport(request, self.timeout_ms))
            exact(answer["request_sha256"], sha(request), "ports:response_request")
            exact(answer["authority_id"], self.identity, "ports:response_authority")
            exact(answer["namespace"], self.namespace, "ports:response_namespace")
            exact(answer["status"], "confirmed", "ports:response_unknown")
            exact(answer["complete"], True, "ports:response_complete")
            require(
                integer(answer["settled_sequence"]) and answer["settled_sequence"] >= minimum,
                "ports:response_lag",
            )
            require(type(answer["proof_id"]) is str and bool(answer["proof_id"]), "ports:proof_id")
            if operation == "application.apply":
                require(type(answer["executed"]) is bool, "ports:execution_proof")
                if answer["executed"] is False:
                    exact(answer["result"], None, "ports:fenced_apply_result")
                    raise ApplyNotExecuted("ports:apply_durably_fenced")
            return copy.deepcopy(answer["result"])
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise AuthorityUnavailable("ports:unavailable_or_ambiguous:" + str(exc)) from exc


class Port:
    def __init__(self, directory, authority, *, initialize=False):
        self.store = DurableStore(
            directory, {"sequence": 0, "operations": {}, "values": {}}, initialize=initialize
        )
        self.authority = authority

    def intent(self, state, operation, key, body):
        label = sha(encode([operation, key]))
        previous = state["operations"].get(label)
        if previous is None:
            state["sequence"] += 1
            previous = {
                "operation": operation,
                "key": key,
                "body": body,
                "sequence": state["sequence"],
            }
            state["operations"][label] = copy.deepcopy(previous)
            self.store.write(state)
        exact(previous["body"], body, "ports:operation_binding")
        return previous["sequence"]

    def settle(self, state, operation, key, *, retry=False):
        intent = state["operations"].get(sha(encode([operation, key])))
        if intent is None:
            return None
        return self.authority.call(
            "intent.settle",
            key,
            intent["sequence"],
            {"operation": operation, "body": intent["body"], "retry": retry},
        )

    def query(self, state, operation, key, body=None):
        return self.authority.call(operation, key, state["sequence"], body)


@dataclass(frozen=True)
class PlanArtifact:
    plan: ReviewedPlan
    show_json: bytes
    payload: bytes
    pins: bytes
    source_commit: str
    review_commit: str

    def hashes(self):
        self.plan.descriptor()
        exact(
            vars(verify_gpu_plan(strict_json(self.show_json))),
            vars(self.plan.capacity),
            "ports:show_binding",
        )
        for commit in (self.source_commit, self.review_commit):
            require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit), "ports:commit")
        pins = strict_json(self.pins)
        exact(pins["source_commit"], self.source_commit, "ports:source_pin")
        result = {
            "plan_sha256": sha(self.plan.saved_plan),
            "show_sha256": sha(self.show_json),
            "payload_sha256": sha(self.payload),
            "pins_sha256": sha(self.pins),
            "target": self.source_commit,
        }
        exact(
            {key: pins[key] for key in ("plan_sha256", "show_sha256", "payload_sha256")},
            {key: result[key] for key in ("plan_sha256", "show_sha256", "payload_sha256")},
            "ports:artifact_pins",
        )
        return result


class GitReviewSource:
    """Read only exact local Git objects, never the worktree or a remote."""

    def __init__(self, repository):
        self.repository = repository

    def __call__(self, commit, source):
        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.repository), *args])

        exact(git("cat-file", "-t", commit).strip(), b"commit", "ports:review_commit")
        git("merge-base", "--is-ancestor", source, commit)
        return git("show", commit + ":REVIEW.md")


def committed_marker(artifact, read_review, marker_count=None):
    hashes = artifact.hashes()
    text = read_review(artifact.review_commit, artifact.source_commit).decode("utf-8")
    start, finish = "\n## Claude review rounds\n", "\n## Findings\n"
    require(start in text and finish in text, "ports:review_sections")
    span = text.split(start, 1)[1].split(finish, 1)[0]
    rounds = list(re.finditer(r"(?m)^### Round ([1-9][0-9]*)\b", span))
    require(bool(rounds), "ports:review_round")
    latest = span[rounds[-1].start() :]
    require(re.search(r"(?m)^- Review basis: \*\*COMMITTED\*\*", latest), "ports:committed_review")
    require(
        re.search(r"(?m)^- Verdict: \*\*NO_BLOCKING_FINDINGS\*\*", latest), "ports:review_verdict"
    )
    # Test fixtures use a synthetic review document; this parser writes no marker.
    prefix = "- M5 V4 " + "PLAN APPROVED: "
    expected = prefix + "; ".join(f"{key}={value}" for key, value in hashes.items())
    expected += "; review_round=" + rounds[-1].group(1)
    candidates = [line for line in latest.splitlines() if line.startswith(prefix)]
    if marker_count is not None:
        exact(len(candidates), marker_count, "ports:marker_count")
    plan_markers = [line for line in candidates if artifact.plan.plan_hash in line]
    exact(plan_markers, [expected], "ports:exact_marker")
    outside = text.split(start, 1)[0] + text.split(finish, 1)[1] + span[: rounds[-1].start()]
    require(
        not any(
            line.startswith(prefix) and artifact.plan.plan_hash in line
            for line in outside.splitlines()
        ),
        "ports:marker_replay",
    )
    return {
        "binding": artifact.plan.descriptor(),
        "committed": True,
        "review_commit": artifact.review_commit,
    }


class FileGate(Port):
    def __init__(self, directory, authority, artifacts, read_review, *, initialize=False):
        self.artifacts = {a.plan.plan_hash: a for a in artifacts}
        require(bool(self.artifacts), "ports:artifacts_required")
        exact(len(self.artifacts), len(artifacts), "ports:distinct_artifacts")
        self.read_review = read_review
        super().__init__(directory, authority, initialize=initialize)

    def approved(self, binding):
        markers = {}
        first = next(iter(self.artifacts.values()))

        def shared(a):
            return [
                a.plan.session_id,
                a.plan.C,
                a.plan.D_session,
                a.plan.capacity.group_arn,
                a.source_commit,
                a.review_commit,
            ]

        for key, artifact in self.artifacts.items():
            exact(shared(artifact), shared(first), "ports:shared_artifacts")
            exact(
                strict_json(artifact.pins)["ordered_plan_hashes"],
                list(self.artifacts),
                "ports:ordered_artifacts",
            )
            markers[key] = committed_marker(artifact, self.read_review, len(self.artifacts))
        marker = markers[binding["plan_hash"]]
        exact(marker["binding"], binding, "ports:marker_descriptor")
        return marker

    def marker(self, binding):
        marker = self.approved(binding)
        with self.store.lock():
            state = self.store.read()
            key = "marker/" + binding["plan_hash"]
            if key in state["values"]:
                exact(state["values"][key], marker, "ports:immutable_marker")
            state["values"][key] = marker
            self.store.write(state)
        return marker

    def consumption(self, session_id):
        with self.store.lock():
            return self.store.read()["values"].get("consume/" + session_id)

    def consume(self, binding, admission_check):
        # The OS lock covers admission, duplicate detection and durable commit.
        with self.store.lock():
            state = self.store.read()
            marker = self.approved(binding)
            exact(
                state["values"].get("marker/" + binding["plan_hash"]),
                marker,
                "ports:marker_required",
            )
            key = "consume/" + binding["session_id"]
            previous = state["values"].get(key)
            if previous is not None:
                exact(previous["plan_hash"], binding["plan_hash"], "ports:one_consume")
                return previous
            now = admission_check()
            require(integer(now) and now >= 0, "ports:consume_clock")
            result = {
                "session_id": binding["session_id"],
                "plan_hash": binding["plan_hash"],
                "consumed_ms": now,
            }
            state["values"][key] = result
            self.store.write(state)
            return result

    def application(self, session_id):
        with self.store.lock():
            state = self.store.read()
            self.settle(state, "application.apply", session_id)
            result = self.query(state, "application.lookup", session_id)
            consumed = state["values"].get("consume/" + session_id)
            if result is not None:
                require(consumed is not None, "ports:application_without_consume")
                result = self.application_receipt(result, consumed)
            require(
                result is not None or "applied/" + session_id not in state["values"],
                "ports:application_disappeared",
            )
            if result is not None:
                state["values"]["applied/" + session_id] = result
                self.store.write(state)
            return result

    def application_receipt(self, result, binding):
        expected = {key: binding[key] for key in ("session_id", "plan_hash")}
        exact({key: result.get(key) for key in expected}, expected, "ports:application_binding")
        exact(
            result["artifacts"],
            self.artifacts[binding["plan_hash"]].hashes(),
            "ports:application_artifacts",
        )
        return expected

    def apply_once(self, binding):
        with self.store.lock():
            state = self.store.read()
            session = binding["session_id"]
            consumed = state["values"].get("consume/" + session)
            require(consumed is not None, "ports:apply_without_consume")
            exact(consumed["plan_hash"], binding["plan_hash"], "ports:apply_hash")
            marker = self.approved(binding)
            exact(
                state["values"].get("marker/" + binding["plan_hash"]), marker, "ports:apply_marker"
            )
            expected = {k: binding[k] for k in ("session_id", "plan_hash")}
            if "applied/" + session in state["values"]:
                exact(state["values"]["applied/" + session], expected, "ports:applied_binding")
                return
            body = {"binding": binding, "artifacts": self.artifacts[binding["plan_hash"]].hashes()}
            sequence = self.intent(state, "application.apply", session, body)
            receipt = self.authority.call("application.apply", session, sequence, body)
            result = self.application_receipt(receipt, binding)
            state["values"]["applied/" + session] = result
            self.store.write(state)


class CapacityPort(Port):
    def __init__(self, directory, authority, micros_per_ms, *, initialize=False):
        require(integer(micros_per_ms) and micros_per_ms > 0, "ports:cost_rate")
        super().__init__(directory, authority, initialize=initialize)
        self.rate = micros_per_ms

    def _lookup(self, state, token):
        # Settle in original sequence order before demanding a watermark. An
        # abandoned acquire/add is fenced; a cancel retries its identical body.
        for intent in sorted(state["operations"].values(), key=lambda i: i["sequence"]):
            operation, key = intent["operation"], intent["key"]
            receipt = self.settle(state, operation, key, retry=operation == "odcr.cancel")
            if operation == "odcr.acquire" and receipt is not None:
                state["values"].setdefault("reservation/" + key, receipt)
                self.store.write(state)
            if operation == "odcr.cancel":
                self._cancel_receipt(state, key, intent["body"]["expected_ids"], receipt)
        result = self.query(state, "odcr.lookup", token)
        known = state["values"].get("reservation/" + token)
        if result is None:
            require(
                known is None or "cancel/" + token in state["values"],
                "ports:reservation_disappeared",
            )
        else:
            require(
                type(result) is dict
                and type(result.get("reservation_id")) is str
                and bool(result["reservation_id"]),
                "ports:reservation_shape",
            )
            if known is not None:
                exact(
                    result["reservation_id"], known["reservation_id"], "ports:reservation_identity"
                )
                require(
                    known["state"] != "cancelled" or result["state"] == "cancelled",
                    "ports:cancel_regression",
                )
            state["values"]["reservation/" + token] = result
            self.store.write(state)
        return result

    def lookup(self, token):
        with self.store.lock():
            return self._lookup(self.store.read(), token)

    def acquire(self, token, binding):
        with self.store.lock():
            state = self.store.read()
            body = vars(binding)
            sequence = self.intent(state, "odcr.acquire", token, body)
            result = self.authority.call("odcr.acquire", token, sequence, body)
            if result is not None:
                require(
                    type(result) is dict
                    and type(result.get("reservation_id")) is str
                    and bool(result["reservation_id"]),
                    "ports:acquire_shape",
                )
                state["values"]["reservation/" + token] = result
            self.store.write(state)
            return result

    def add(self, group, reservation_id):
        with self.store.lock():
            state = self.store.read()
            body = {"group": group, "reservation_id": reservation_id}
            sequence = self.intent(state, "odcr.add", reservation_id, body)
            exact(
                self.authority.call("odcr.add", reservation_id, sequence, body),
                body,
                "ports:add_receipt",
            )

    def members(self, group):
        with self.store.lock():
            result = self.query(self.store.read(), "odcr.members", group)
            require(
                type(result) is list and all(type(i) is str and i for i in result),
                "ports:members_shape",
            )
            exact(len(result), len(set(result)), "ports:member_duplicates")
            return result

    def cancel(self, token, group):
        with self.store.lock():
            state = self.store.read()
            key = "cancel/" + token
            if key in state["values"]:
                return copy.deepcopy(state["values"][key])
            reservation = self._lookup(state, token)
            ids = [] if reservation is None else [reservation["reservation_id"]]
            body = {"group": group, "expected_ids": ids}
            sequence = self.intent(state, "odcr.cancel", token, body)
            result = self.authority.call("odcr.cancel", token, sequence, body)
            return self._cancel_receipt(state, token, ids, result)

    def _cancel_receipt(self, state, token, ids, result):
        validate_cancel_receipt(ids, result)
        state["values"]["cancel/" + token] = result
        reservation = state["values"].get("reservation/" + token)
        if reservation is not None:
            reservation["state"] = "cancelled"
        self.store.write(state)
        return result

    def cancellation(self, token):
        with self.store.lock():
            return self.store.read()["values"].get("cancel/" + token)

    def ledger(self, token, t0):
        with self.store.lock():
            state = self.store.read()
            stop = state["values"]["cancel/" + token]["stop_ms"]
            require(integer(t0) and 0 <= t0 <= stop, "ports:ledger_time")
            existed = "reservation/" + token in state["values"]
            return {
                "t0_ms": t0,
                "stop_ms": stop,
                "billed_ms": stop - t0,
                "cost_micros": (stop - t0) * self.rate if existed else 0,
            }


class BackstopPort(Port):
    def __init__(self, directory, authority, clock, operator_id, *, initialize=False):
        require(authority.identity != operator_id, "ports:independent_backstop")
        super().__init__(directory, authority, initialize=initialize)
        self.clock = clock

    def _confirmed(self, state, session, deadline):
        self.settle(state, "backstop.arm", session)
        result = self.query(state, "backstop.lookup", session)
        if result is None:
            return False
        exact(result["session_id"], session, "ports:backstop_session")
        exact(result["deadline_ms"], deadline, "ports:backstop_deadline")
        exact(result["durable"], True, "ports:backstop_durable")
        require(type(result["arm_id"]) is str and bool(result["arm_id"]), "ports:backstop_arm_id")
        return result["armed"] is True and result["alive"] is True and self.clock() < deadline

    def arm(self, session, deadline):
        with self.store.lock():
            state = self.store.read()
            key = "deadline/" + session
            if key in state["values"]:
                exact(state["values"][key], deadline, "ports:immutable_backstop")
                return self._confirmed(state, session, deadline)
            require(integer(deadline) and self.clock() < deadline, "ports:backstop_expired")
            state["values"][key] = deadline
            body = {"session_id": session, "deadline_ms": deadline}
            sequence = self.intent(state, "backstop.arm", session, body)
            exact(
                self.authority.call("backstop.arm", session, sequence, body),
                body,
                "ports:arm_receipt",
            )
            return self._confirmed(state, session, deadline)

    def confirmed(self, session, deadline):
        with self.store.lock():
            state = self.store.read()
            exact(state["values"].get("deadline/" + session), deadline, "ports:backstop_not_armed")
            return self._confirmed(state, session, deadline)
