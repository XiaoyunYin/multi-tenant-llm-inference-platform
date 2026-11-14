"""Sourced reader contracts only; this is not a deployed capture envelope.

Round 366 leaves aggregate SSE, audit and control/metadata limits unresolved.
The constants below preserve existing acceptance ceilings. Fixed RESP command
shapes permit an aggregate bound without inventing a deployment capacity.
"""

from .inf037b_archive import IntegrityError

CLIENT_DENIAL_BYTES = 8192
CLIENT_PENDING_BYTES = 1_048_576
RESP_BULK_BYTES = 8_388_608
RESP_LINE_BYTES = RESP_BULK_BYTES + 1
RESP_ARRAY_ELEMENTS = 100_000
# '$' + decimal length + CRLF + body + CRLF, including the largest bulk header.
RESP_BULK_WIRE_BYTES = RESP_BULK_BYTES + len(str(RESP_BULK_BYTES)) + 5


class ProducerLimit(IntegrityError):
    """Named capture refusal, distinct from a normal failed HTTP request."""


def refuse(retain, reason, start, end):
    """The offending read was retained first; settle custody and mark loss.

    No body is sliced, substituted or accepted as a complete response. Retainer
    overflow keeps its existing refusal; explicit loss survives that failure.
    """
    try:
        retain(start, end, b"", {"error": reason, "producer_limit": True})
    finally:
        try:
            getattr(retain, "barrier", lambda: None)()
        finally:
            getattr(retain, "loss", lambda reason: None)(reason)
    raise ProducerLimit(reason)


def resp_contract(args, snapshot):
    """Only the three pinned scalar/pair/script shapes; element caps stay."""
    from .inf037b_redis_shapes import fixed_contract

    if args and args[0] == "AUTH":
        return fixed_contract("AUTH")
    if args == ("TIME",):
        return fixed_contract("TIME")
    if len(args) >= 2 and args[:2] == ("EVAL", snapshot):
        return fixed_contract("snapshot")
    return None


class ReplyBudget:
    def __init__(self, contract):
        self.contract = contract
        self.bytes = self.elements = 0

    def remaining(self):
        return self.contract["bytes"] - self.bytes

    def add(self, size):
        self.bytes += size
        return "capture:producer:resp_bytes" if self.remaining() < 0 else None

    def node(self, depth):
        self.elements += 1
        if self.elements > self.contract["elements"]:
            return "capture:producer:resp_elements"
        if depth > self.contract["depth"]:
            return "capture:producer:resp_depth"
        return None
