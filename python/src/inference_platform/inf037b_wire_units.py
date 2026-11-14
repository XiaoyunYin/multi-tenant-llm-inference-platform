"""Protocol-unit index custody. Raw reads keep their original physical order.

An owner-backed retainer writes each read immediately and indexes completed
units by physical spans. Interleaved connections do not reorder the raw spool.
The fallback is for standalone non-owner transport users, not capture admission.
"""

from .inf037b_archive import IntegrityError


class UnitRecorder:
    def __init__(self, retain, *, kind, metadata=None):
        self.retain, self.kind = retain, kind
        self.metadata = dict(metadata or {})
        self.buffer = bytearray()
        self.spans = []
        self.token = None
        self.start = self.end = self.last_start = None
        self.reads = 0
        self.native = getattr(retain, "supports_units", False) is True

    def feed(self, start, end, body):
        if self.token is None and self.start is None:
            self.start = start
            if self.native:
                self.token = self.retain.unit_begin(self.metadata, self.finish)
        self.last_start, self.end = start, end
        self.reads += 1
        # The same signed-64-bit, ordered bracket contract is checked on every
        # input, including reads which complete no protocol unit.
        if not (type(start) is int and type(end) is int and 0 <= start <= end < 2**63):
            raise IntegrityError("capture:unit_read_time")
        self.buffer.extend(body)
        if self.native:
            offset = self.retain.unit_read(start, end, body, self.metadata)
            if body:
                if self.spans and self.spans[-1][0] + self.spans[-1][1] == offset:
                    self.spans[-1][1] += len(body)
                else:
                    self.spans.append([offset, len(body)])

    def emit(self, length=None, *, kind=None, extra=None):
        if self.start is None:
            return
        length = len(self.buffer) if length is None else length
        if not 0 <= length <= len(self.buffer):
            raise IntegrityError("capture:unit_length")
        data = bytes(self.buffer[:length])
        tail = self.buffer[length:]
        used, rest, left = [], [], length
        for offset, size in self.spans:
            n = min(size, left)
            if n:
                used.append([offset, n])
                left -= n
            if size > n:
                rest.append([offset + n, size - n])
        metadata = {
            **self.metadata,
            **(extra or {}),
            "unit": kind or self.kind,
            "read_count": self.reads,
        }
        token, start, end = self.token, self.start, self.end
        last_start, last_end = self.last_start, self.end
        self.buffer, self.spans, self.token = bytearray(tail), rest, None
        self.start = self.end = self.last_start = None
        self.reads = 0
        if self.native:
            self.retain.unit_finish(token, start, end, data, used, metadata)
        else:
            self.retain(start, end, data, metadata)
        if tail:
            # A prefix is emitted only after the parser has consumed it. Any
            # buffered suffix was received by the final read (the parser never
            # requests another read while a complete reply is already buffered).
            self.start = self.last_start = last_start
            self.end, self.reads = last_end, 1
            if self.native:
                self.token = self.retain.unit_begin(self.metadata, self.finish)

    def finish(self, kind=None):
        self.emit(kind=kind)

    def lines(self, start, end, body, *, delimiter=b"\n"):
        """Keep physical write atomic even when one read completes many lines."""
        self.feed(start, end, body)
        while (at := self.buffer.find(delimiter)) >= 0:
            self.emit(at + len(delimiter))


class UnitReads:
    """Retainer routing for complete HTTP bodies and watch/SSE protocol units."""

    def __init__(self, retain, *, mode):
        self.base, self.mode, self.active = retain, mode, None

    def __getattr__(self, name):
        return getattr(self.base, name)

    def __call__(self, start, end, body, metadata):
        transport_body = (
            metadata.get("direction") != "request"
            and bool(body)
            and not any(
                k in metadata
                for k in (
                    "headers",
                    "error",
                    "rejected_headers",
                    "client_rejected_error_text",
                    "tls",
                )
            )
        )
        if transport_body or (not body and self.active is not None and not metadata.get("error")):
            if self.active is None:
                self.active = UnitRecorder(self.base, kind=self.mode, metadata=metadata)
            self.active.feed(start, end, body)
            return
        self.finish("refusal" if metadata.get("error") else None)
        self.base(
            start,
            end,
            body,
            {
                **metadata,
                "unit": "headers"
                if "headers" in metadata or metadata.get("rejected_headers")
                else "record",
                "read_count": 1 if body or "headers" in metadata else 0,
            },
        )

    def units(self):
        if self.active is None:
            return
        while True:
            delimiters = (b"\n",) if self.mode == "watch_line" else (b"\n\n", b"\n\r\n")
            endings = [n + len(d) for d in delimiters if (n := self.active.buffer.find(d)) >= 0]
            if not endings:
                return
            self.active.emit(min(endings))

    def line(self, length):
        if self.active is not None:
            self.active.emit(length)

    def finish(self, kind=None):
        if self.active is not None:
            active, self.active = self.active, None
            active.finish(kind)
