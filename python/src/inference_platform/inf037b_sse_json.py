"""One host-independent nesting policy for raw and redacted SSE JSON values."""

import json

MAX_SSE_JSON_DEPTH = 64


def sse_json_loads(data: bytes):
    """Allow at most 64 open objects/arrays, ignoring delimiters inside strings.

    Scan iteratively before invoking the recursive decoder. Keep json.loads'
    byte-encoding detection; let it validate syntax after the depth check.
    """
    text = data.decode(json.detect_encoding(data), "surrogatepass")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_SSE_JSON_DEPTH:
                raise ValueError("invalid_sse_json")
        elif char in "]}":
            depth -= 1
    try:
        return json.loads(text)
    except RecursionError:
        # Also contain a decoder failure under an unusually small call budget.
        raise ValueError("invalid_sse_json") from None
