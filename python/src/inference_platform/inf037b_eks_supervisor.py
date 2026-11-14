"""Independent absolute backstop service over the accepted fenced byte protocol.

The deployment must supply a genuinely independent termination/reconciliation
authority. No cloud provider or host launcher is installed by this module.
"""

import copy
import hmac
import http.client
import ssl
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from .inf037b_archive import encode, sha
from .inf037b_authority import FencedAuthority
from .inf037b_durable_ports import DurableStore
from .inf037b_ports import AuthorityUnavailable
from .inf037b_resolver import SessionDeadline, exact, integer, require

SETTLEMENT_INITIAL_MS = 50
SETTLEMENT_CAP_MS = 3200


class SupervisorTimer:
    def __init__(self, directory, *, terminate, reconcile, clock, store=None):
        self.store = (
            store if store is not None else DurableStore(directory, {"arms": {}}, initialize=True)
        )
        self.terminate, self.reconcile, self.clock = terminate, reconcile, clock
        self.stop, self.thread = threading.Event(), None

    def arm(self, body):
        session, deadline = body["session_id"], body["deadline_ms"]
        require(type(session) is str and bool(session) and integer(deadline), "supervisor:arm")
        with self.store.lock():
            state = self.store.read()
            old = state["arms"].get(session)
            if old is not None:
                exact(old["deadline_ms"], deadline, "supervisor:immutable_deadline")
            else:
                require(self.clock() < deadline, "supervisor:expired")
                state["arms"][session] = {
                    "deadline_ms": deadline,
                    "arm_id": sha(encode(body)),
                    "arm_effects": 1,
                }
                self.store.write(state)
        return copy.deepcopy(body)

    def lookup(self, session):
        with self.store.lock():
            old = self.store.read()["arms"].get(session)
        if old is None:
            return None
        return {
            "session_id": session,
            "deadline_ms": old["deadline_ms"],
            "arm_id": old["arm_id"],
            "durable": True,
            "armed": "result" not in old,
            "termination_pending": "fire_intent" in old and "result" not in old,
            "alive": bool(self.thread and self.thread.is_alive() and not self.stop.is_set()),
        }

    def tick(self):
        with self.store.lock():
            state = self.store.read()
            for session, arm in state["arms"].items():
                if (
                    self.clock() < arm["deadline_ms"]
                    or "result" in arm
                    or self.clock() < arm.get("next_settlement_ms", 0)
                ):
                    continue
                interval = arm.get("settlement_interval_ms", SETTLEMENT_INITIAL_MS)
                arm["next_settlement_ms"] = self.clock() + interval
                arm["settlement_interval_ms"] = min(interval * 2, SETTLEMENT_CAP_MS)
                body = {
                    "session_id": session,
                    "deadline_ms": arm["deadline_ms"],
                    "arm_id": arm["arm_id"],
                }
                attempts = arm.setdefault("termination_attempts", [])
                reconciliations = arm.setdefault("reconciliations", [])
                if "error" in arm:
                    attempts.append({"error": arm.pop("error"), "legacy": True})
                    self.store.write(state)
                if "fire_intent" in arm:
                    # Unknown is not permission to repeat an external effect.
                    try:
                        recovered = self.reconcile(body)
                    except Exception as exc:
                        recovered = {"known": False, "error": type(exc).__name__ + ":" + str(exc)}
                    if reconciliations and reconciliations[-1]["receipt"] == recovered:
                        record = reconciliations[-1]
                        record["count"] = record.get("count", 1) + 1
                        record["last_seen_ms"] = self.clock()
                    else:
                        reconciliations.append(
                            {
                                "at_ms": self.clock(),
                                "last_seen_ms": self.clock(),
                                "count": 1,
                                "receipt": copy.deepcopy(recovered),
                            }
                        )
                    self.store.write(state)
                    if recovered.get("known") is not True:
                        continue
                    if recovered.get("executed") is True:
                        arm["result"] = recovered["result"]
                        self.store.write(state)
                        continue
                    if recovered.get("executed") is not False:
                        continue
                    exact(recovered["result"], None, "supervisor:not_executed_result")
                else:
                    arm["fire_intent"] = body
                    self.store.write(state)
                attempt = {"begin_ms": self.clock(), "body": body}
                attempts.append(attempt)
                self.store.write(state)
                try:
                    arm["result"] = self.terminate(body)
                    attempt["result"] = copy.deepcopy(arm["result"])
                except Exception as exc:
                    attempt["error"] = type(exc).__name__ + ":" + str(exc)
                attempt["end_ms"] = self.clock()
                self.store.write(state)

    def start(self):
        def run():
            while not self.stop.is_set():
                try:
                    self.tick()
                except Exception:
                    # An unreadable journal stops confirmation; never fake alive.
                    self.stop.set()
                    return
                self.stop.wait(0.05)

        self.thread = threading.Thread(target=run, name="independent-backstop")
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=1)


def fenced_supervisor(directory, identity, timer, *, effect_hook=None):
    def effect(operation, key, body):
        exact(operation, "backstop.arm", "supervisor:operation")
        result = timer.arm(body)
        if effect_hook:
            effect_hook()
        return result

    def read(operation, key, body):
        exact(operation, "backstop.lookup", "supervisor:read")
        return timer.lookup(key)

    def reconcile(operation, key, body):
        known = timer.lookup(key)
        return {
            "known": True,
            "executed": known is not None,
            "result": body if known is not None else None,
        }

    return FencedAuthority(
        directory,
        identity,
        "backstop",
        effect=effect,
        read=read,
        reconcile=reconcile,
        initialize=True,
    )


def supervisor_handler(authority, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path != "/authority" or not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + token()
            ):
                self.send_error(403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1_048_576:
                self.send_error(413)
                return
            try:
                body = authority(self.rfile.read(length), 2000)
            except Exception:
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionError):
                pass

    return Handler


class AuthorityHTTP:
    """One bounded exchange; settlement/retry policy stays in existing ports."""

    def __init__(self, url, *, token, ca=None, local_test=False):
        self.url, self.token = urlsplit(url), token
        require(
            self.url.scheme == "https"
            or (
                local_test
                and self.url.scheme == "http"
                and self.url.hostname in ("127.0.0.1", "localhost")
            ),
            "supervisor:https",
        )
        require(
            self.url.path == "/authority"
            and not (self.url.query or self.url.fragment or self.url.username or self.url.password),
            "supervisor:url",
        )
        self.context = ssl.create_default_context(cafile=ca)

    def __call__(self, request, timeout_ms):
        cls = (
            http.client.HTTPSConnection
            if self.url.scheme == "https"
            else http.client.HTTPConnection
        )
        kwargs = {"context": self.context} if self.url.scheme == "https" else {}
        connection = cls(self.url.hostname, self.url.port, timeout=timeout_ms / 1000, **kwargs)
        try:
            connection.request(
                "POST",
                self.url.path,
                body=request,
                headers={
                    "Authorization": "Bearer " + self.token(),
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            body = response.read(8_388_609)
            require(response.status == 200 and len(body) <= 8_388_608, "supervisor:response")
            return body
        except (OSError, http.client.HTTPException) as exc:
            raise AuthorityUnavailable("supervisor:unavailable:" + type(exc).__name__) from exc
        finally:
            connection.close()


class RecoveryBinding:
    """Final parent join calls this; it never consumes/adopts a new session."""

    def __init__(self, factory):
        self.factory = factory
        b = factory.binding
        self.deadline = SessionDeadline(b["C_ms"], b["D_session_ms"], b["t0_ms"])

    def confirm(self, stop):
        f = self.factory
        f.port.deadline(stop)
        persisted = f.dependency("4c_recovery_supervisor")(stop)
        independent = f.dependency("4d_independent_recovery")(stop)
        from .inf037b_eks_execution import join_execution

        join_execution(independent, f, "4d_independent_recovery")
        for proof in (persisted, independent):
            exact(proof["binding"], f.binding, "eks:recovery_binding")
            exact(proof["D_eff_ms"], self.deadline.effective_ms, "eks:recovery_deadline")
        require(
            independent["controller_host"] != independent["supervisor_host"],
            "eks:recovery_independence",
        )
        require(
            f.controller.backstop.confirmed(f.binding["session_id"], self.deadline.effective_ms)
            is True,
            "eks:backstop_unconfirmed",
        )
        f.port.deadline(stop, completed=True)
        return {"D_eff_ms": self.deadline.effective_ms, "paid_ready": False}

    def settle(self, driver, operation, key, stop):
        self.confirm(stop)
        exact(
            driver.deadline.effective_ms, self.deadline.effective_ms, "eks:recovery_driver_deadline"
        )
        driver._fence_pending()  # Existing Linux identity/group fencing, no substitute.
        f = self.factory
        f.port.deadline(stop)
        with f.port.store.lock():
            result = f.port.settle(f.port.store.read(), operation, key, retry=False)
        f.port.deadline(stop, completed=True)
        require(result is not None, "eks:remote_effect_unsettled")
        return result
