"""Account-scoped AWS read bindings; no resource creation or absence inference.

The final sealed M5 effect/resource map is not present in this repository yet.
These actual SDK reads can bind existing host identities. They cannot turn a
partial EC2 listing into the accepted provider's complete terminal inventory.
"""

import re
from urllib.parse import urlsplit

from .inf037b_resolver import exact, require


class AccountReadClient:
    def __init__(
        self, session, *, account, region, session_id, clock, endpoint=None, local_test=False
    ):
        require(re.fullmatch(r"[0-9]{12}", account) is not None, "provider_client:account")
        require(bool(region) and bool(session_id), "provider_client:scope")
        if endpoint is not None:
            url = urlsplit(endpoint)
            require(
                local_test and url.scheme == "http" and url.hostname == "127.0.0.1",
                "provider_client:test_endpoint",
            )
        self.session, self.account, self.region, self.session_id, self.clock, self.endpoint = (
            session,
            account,
            region,
            session_id,
            clock,
            endpoint,
        )

    def client(self, service, stop):
        from botocore.config import Config

        remaining = (stop - self.clock()) / 1000
        require(remaining > 0, "provider_client:deadline")
        return self.session.client(
            service,
            region_name=self.region,
            endpoint_url=self.endpoint,
            config=Config(
                connect_timeout=min(5, remaining),
                read_timeout=min(5, remaining),
                retries={"max_attempts": 0},
            ),
        )

    def hosts(self, instance_ids, stop):
        ids = list(instance_ids)
        require(bool(ids) and len(ids) == len(set(ids)), "provider_client:host_ids")
        identity = self.client("sts", stop).get_caller_identity()
        exact(identity["Account"], self.account, "provider_client:caller_account")
        ec2 = self.client("ec2", stop)
        result, seen_tokens, token = {}, set(), None
        while True:
            require(self.clock() < stop, "provider_client:deadline")
            page = ec2.describe_instances(
                InstanceIds=ids, **({"NextToken": token} if token else {})
            )
            for reservation in page.get("Reservations", []):
                exact(reservation["OwnerId"], self.account, "provider_client:resource_account")
                for instance in reservation["Instances"]:
                    key = instance["InstanceId"]
                    require(
                        key in ids and key not in result,
                        "provider_client:foreign_or_duplicate_host",
                    )
                    tags = {r["Key"]: r["Value"] for r in instance.get("Tags", [])}
                    exact(tags.get("Session"), self.session_id, "provider_client:session_tag")
                    zone = instance["Placement"]["AvailabilityZone"]
                    require(zone.startswith(self.region), "provider_client:region")
                    result[key] = {
                        "instance_id": key,
                        "state": instance["State"]["Name"],
                        "region": self.region,
                        "availability_zone": zone,
                        "session_id": self.session_id,
                    }
            token = page.get("NextToken")
            if not token:
                break
            require(token not in seen_tokens, "provider_client:pagination_cycle")
            seen_tokens.add(token)
        require(self.clock() <= stop, "provider_client:deadline")
        # Explicit known IDs must all be described. Missing rows are unknown,
        # including terminated instances which have aged out of Describe.
        exact(set(result), set(ids), "provider_client:host_inventory_unknown")
        return result

    def execute(self, request):
        raise ValueError("eks_provider:unfinished:sealed_effect_resource_map")

    def read(self, request):
        raise ValueError("eks_provider:unfinished:complete_scoped_resource_inventory")

    def reconcile(self, request):
        # Without that independent map/readback an ambiguous write is unknown;
        # neither an empty list nor a lost reply authorizes another effect.
        return {"known": False, "executed": False, "result": None}
