"""One persistent, UID-bound pod-network clock stream per engine replica."""

import json
import os
import socket
import time
import uuid

PORT = 8765
EXCHANGES = 10
STAMP_NS = 1_000
IDLE_TIMEOUT_SECONDS = 750


class ClockRefusal(ValueError):
    pass


def send(stream, value):
    stream.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
    stream.flush()


def receive(stream):
    line = stream.readline(512)
    if not line.endswith(b"\n"):
        raise ClockRefusal("clock_frame")
    try:
        return json.loads(line)
    except ValueError:
        raise ClockRefusal("clock_frame") from None


def serve_stream(reader, writer, identity, wall=time.time_ns):
    send(writer, identity)
    for sequence in range(EXCHANGES * 2):
        request = receive(reader)
        if type(request) is not int or request != sequence:
            raise ClockRefusal("clock_sequence")
        instant = wall()
        send(writer, [sequence, instant])


def wall_mapping(monotonic=time.monotonic_ns, wall=time.time_ns):
    before = monotonic()
    epoch = wall()
    after = monotonic()
    return epoch - (before + after) // 2, after - before


class ClockStream:
    def __init__(self, ip, identity, deadline):
        self.deadline = deadline
        self.sequence = 0
        self.socket = socket.create_connection((ip, PORT), timeout=self.timeout())
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.stream = self.socket.makefile("rwb")
            self.socket.settimeout(self.timeout())
            hello = receive(self.stream)
            if (
                not isinstance(hello, list)
                or len(hello) != 2
                or hello[0] != identity
                or not isinstance(hello[1], str)
                or len(hello[1]) != 32
                or any(char not in "0123456789abcdef" for char in hello[1])
            ):
                raise ClockRefusal("clock_generation")
        except BaseException:
            self.close()
            raise

    def timeout(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise ClockRefusal("clock_deadline")
        return min(3, left)

    def exchange(self, monotonic=time.monotonic_ns):
        rows = []
        for _ in range(EXCHANGES):
            self.socket.settimeout(self.timeout())
            c1 = monotonic()
            send(self.stream, self.sequence)
            response = receive(self.stream)
            c4 = monotonic()
            if (
                not isinstance(response, list)
                or len(response) != 2
                or type(response[0]) is not int
                or response[0] != self.sequence
                or type(response[1]) is not int
                or response[1] <= 0
                or c4 < c1
            ):
                raise ClockRefusal("clock_exchange")
            stamp = response[1]
            rows.append({"c1": c1, "c4": c4, "e2": stamp, "e3": stamp})
            self.sequence += 1
        return rows

    def close(self):
        try:
            if hasattr(self, "stream"):
                self.stream.close()
        finally:
            self.socket.close()


def bracket(before, after, mapping, *, same_generation):
    if not same_generation:
        raise ClockRefusal("clock_generation")
    if len(before) != EXCHANGES or len(after) != EXCHANGES:
        raise ClockRefusal("clock_count")
    variation = max(offset for offset, _ in mapping) - min(offset for offset, _ in mapping)
    if variation > 5_000_000:
        raise ClockRefusal("clock_step")
    padding = variation + max(width for _, width in mapping)

    def narrowest(rows):
        bounds = [(r["e3"] - r["c4"], r["e2"] - r["c1"]) for r in rows]
        if any(hi < lo for lo, hi in bounds) or any(
            right["e2"] < left["e3"] or right["c1"] < left["c4"]
            for left, right in zip(rows, rows[1:], strict=False)
        ):
            raise ClockRefusal("clock_inversion")
        return min(range(len(bounds)), key=lambda i: bounds[i][1] - bounds[i][0]), bounds

    first, starts = narrowest(before)
    last, ends = narrowest(after)
    a, b = starts[first], ends[last]
    if min(a[1], b[1]) + padding < max(a[0], b[0]):
        raise ClockRefusal("clock_disagreement")
    lo, hi = min(a[0], b[0]) - padding, max(a[1], b[1]) + padding
    return {
        "before_index": first,
        "after_index": last,
        "offset_lo_ns": lo,
        "offset_hi_ns": hi,
        "width_ns": hi - lo,
        "stamp_resolution_ns": STAMP_NS,
        "precision_floor_ns": hi - lo + STAMP_NS,
        "variation_ns": variation,
    }


def interval(stamp, close, bounds):
    sec, fraction = stamp.split(".")
    epoch = int(sec) * 10**9 + int(fraction) * 1000
    half = bounds["stamp_resolution_ns"] // 2
    return [
        epoch - half - bounds["offset_hi_ns"] - close,
        epoch + half - bounds["offset_lo_ns"] - close,
    ]


def main():
    from socketserver import StreamRequestHandler, ThreadingTCPServer

    identity = [os.environ["POD_UID"], uuid.uuid4().hex]

    class Handler(StreamRequestHandler):
        timeout = IDLE_TIMEOUT_SECONDS
        wbufsize = 512

        def handle(self):
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                serve_stream(self.rfile, self.wfile, identity)
            except (OSError, ClockRefusal):
                pass

    class Server(ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with Server(("0.0.0.0", PORT), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
