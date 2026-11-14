"""Fresh independent host joins over the existing provider/identity readers."""

import copy
import json
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .inf037b_eks_provider_client import AccountReadClient
from .inf037b_resolver import SessionDeadline, exact, require


def local_host_identity(
    *,
    binding,
    pins,
    account,
    region,
    clock,
    stop,
    boot_path=Path("/proc/sys/kernel/random/boot_id"),
    metadata_base="http://169.254.169.254",
    local_test=False,
):
    """Read the actual host via IMDSv2 and proc, for the authenticated role transport.

    Account IDs/tokens are compared in memory and are not included in the peer
    receipt. This function installs no new server or credential route.
    """
    url = urlsplit(metadata_base)
    require(
        url.scheme == "http"
        and (url.hostname == "169.254.169.254" or (local_test and url.hostname == "127.0.0.1"))
        and url.path in ("", "/")
        and not url.username
        and not url.query
        and not url.fragment,
        "host_binding:metadata_endpoint",
    )
    deadline = SessionDeadline(
        binding["C_ms"], binding["D_session_ms"], binding["t0_ms"]
    ).effective_ms
    require(stop <= deadline, "host_binding:original_deadline")

    def read(path, *, method="GET", headers=None):
        remaining = (stop - clock()) / 1000
        require(remaining > 0, "host_binding:identity_deadline")
        request = urllib.request.Request(
            metadata_base.rstrip("/") + path, method=method, headers=headers or {}
        )

        # IMDS must never be sent through a user-configured HTTP proxy.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError("host_binding:metadata_redirect")

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=min(5, remaining)) as response:
            body = response.read(4097)
        require(len(body) <= 4096, "host_binding:identity_document_bytes")
        require(clock() <= stop, "host_binding:identity_deadline")
        return body

    token = read(
        "/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}
    ).decode("ascii")
    require(bool(token) and "\n" not in token and "\r" not in token, "host_binding:metadata_token")
    document = json.loads(
        read(
            "/latest/dynamic/instance-identity/document",
            headers={"X-aws-ec2-metadata-token": token},
        )
    )
    exact(document["accountId"], account, "host_binding:local_account")
    exact(document["region"], region, "host_binding:local_region")
    boot = Path(boot_path).read_text(encoding="ascii").strip()
    require(bool(boot) and bool(document["instanceId"]), "host_binding:identity")
    require(clock() <= stop, "host_binding:identity_deadline")
    return {
        "instance_id": document["instanceId"],
        "boot_id": boot,
        "session_id": binding["session_id"],
        "pins": copy.deepcopy(pins),
    }


class IndependentHosts:
    def __init__(self, *, binding, pins, hosts, account_reader, witness_read):
        self.binding, self.pins, self.hosts = copy.deepcopy((binding, pins, hosts))
        self.account_reader, self.witness_read = account_reader, witness_read
        require(isinstance(account_reader, AccountReadClient), "host_binding:account_reader")
        exact(set(hosts), {"controller", "export", "supervisor"}, "host_binding:roles")
        exact(account_reader.session_id, binding["session_id"], "host_binding:account_scope")
        supervisor = hosts["supervisor"]["instance_id"]
        require(
            supervisor not in {hosts[r]["instance_id"] for r in ("controller", "export")},
            "host_binding:physical_independence",
        )
        for role in hosts:
            require(
                bool(hosts[role]["instance_id"]) and bool(hosts[role]["boot_id"]),
                "host_binding:identity",
            )

    def observe(self, stop):
        exact(
            self.account_reader.session_id, self.binding["session_id"], "host_binding:account_scope"
        )
        deadline = SessionDeadline(
            self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
        ).effective_ms
        require(stop <= deadline, "host_binding:original_deadline")
        facts = self.account_reader.hosts(
            sorted({h["instance_id"] for h in self.hosts.values()}), stop
        )
        result = {}
        for role, expected in self.hosts.items():
            identity = expected["instance_id"]
            exact(facts[identity]["state"], "running", "host_binding:not_running")
            before = self.account_reader.clock()
            # Deployment supplies the authenticated accepted host transport;
            # a static source document is never a fresh identity observation.
            observed = self.witness_read(identity, stop)
            after = self.account_reader.clock()
            require(before <= after <= stop, "host_binding:observation_deadline")
            exact(observed["instance_id"], identity, "host_binding:instance")
            exact(observed["boot_id"], expected["boot_id"], "host_binding:boot")
            exact(observed["session_id"], self.binding["session_id"], "host_binding:session")
            exact(observed["pins"], self.pins, "host_binding:pins")
            result[role] = {
                **facts[identity],
                "boot_id": observed["boot_id"],
                "read_ms": [before, after],
            }
        # Different instances reporting the same boot identity is not accepted
        # as physical independence (e.g. a misrouted witness endpoint).
        require(
            result["supervisor"]["boot_id"]
            not in {result[r]["boot_id"] for r in ("controller", "export")},
            "host_binding:boot_independence",
        )
        return {"binding": self.binding, "pins": self.pins, "D_eff_ms": deadline, "hosts": result}
