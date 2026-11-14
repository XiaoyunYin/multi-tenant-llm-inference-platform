"""Bounded administrative Redis fixture operations, never a capture adapter.

Production RedisWire only dispatches its four pinned capture commands. These
existing integration tests also seed/damage/query the real test Redis store.
Keep those fixture operations explicit and outside the production dispatcher.
"""

from inference_platform.inf037b_live import RedisWire
from inference_platform.inf037b_producer_limits import RESP_BULK_BYTES


class AdminRedisWire(RedisWire):
    def command(self, *args):
        if args and args[0] in {
            "DEL",
            "INCR",
            "HGET",
            "HGETALL",
            "GET",
            "XRANGE",
            "XREVRANGE",
            "XDEL",
        }:
            return self._exchange(
                args, {"bytes": RESP_BULK_BYTES + 65536, "elements": 100001, "depth": 8}
            )
        return super().command(*args)
