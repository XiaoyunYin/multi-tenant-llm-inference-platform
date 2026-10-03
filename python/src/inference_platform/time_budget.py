"""Absolute monotonic deadlines for bounded HTTP experiment work."""

from __future__ import annotations

import http.client
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class BudgetExhausted(TimeoutError):
    """A run's absolute wall-time budget has elapsed."""


def remaining_seconds(deadline: float | None, maximum: float) -> float:
    if deadline is None:
        return maximum
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise BudgetExhausted("run_time_budget_exhausted")
    return min(maximum, remaining)


@contextmanager
def deadline_urlopen(
    request: urllib.request.Request, *, timeout: float, deadline: float | None = None
) -> Iterator[Any]:
    """Bound connect/header waits and interrupt even continuously trickling bodies.

    urllib's timeout alone applies to individual socket operations. A deadline
    timer shuts down the response socket so a long/trickling stream cannot
    extend the run indefinitely. Shutdown unblocks readers; close happens in
    their owning thread after the read exits.
    """
    response = urllib.request.urlopen(request, timeout=remaining_seconds(deadline, timeout))
    timer = None
    try:
        if deadline is not None:
            # urllib HTTPResponse keeps its transport here on pinned CPython 3.12.
            transport = response.fp.raw._sock

            def expire() -> None:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(max(0, deadline - time.perf_counter()), expire)
            timer.daemon = True
            timer.start()
        try:
            yield response
        except (OSError, http.client.HTTPException) as error:
            if deadline is not None and time.perf_counter() >= deadline:
                raise BudgetExhausted("run_time_budget_exhausted") from error
            raise
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        response.close()
