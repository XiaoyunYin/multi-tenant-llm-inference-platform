"""Registered literal-only DEFLATE carrier. No zlib heuristics for (a)/(b)."""

import base64
import binascii
import heapq
import struct
import zlib
from collections import Counter


class Bits:
    def __init__(self):
        self.data = bytearray()
        self.value = self.count = self.position = 0

    def put(self, value, count):
        self.value |= value << self.count
        self.count += count
        self.position += count
        while self.count >= 8:
            self.data.append(self.value & 255)
            self.value >>= 8
            self.count -= 8

    def align(self):
        if self.count:
            self.put(0, 8 - self.count)

    def finish(self):
        self.align()
        return bytes(self.data)


def lengths(frequencies, limit=15):
    """Binary package-merge: optimal length-limited Huffman lengths."""
    leaves = sorted((weight, (symbol,)) for symbol, weight in frequencies.items())
    if len(leaves) == 1:
        return {leaves[0][1][0]: 1}
    if len(leaves) > 1 << limit:
        raise ValueError("Huffman alphabet exceeds length limit")
    current = leaves
    for _ in range(limit - 1):
        packages = sorted(
            (left[0] + right[0], left[1] + right[1])
            for left, right in zip(current[::2], current[1::2], strict=False)
        )
        current = list(heapq.merge(leaves, packages))
    result = Counter()
    for _, symbols in current[: 2 * len(leaves) - 2]:
        result.update(symbols)
    return dict(result)


def codes(sizes):
    """Canonical codes, reversed for the DEFLATE least-significant-bit stream."""
    value = previous = 0
    result = {}
    for symbol, size in sorted(sizes.items(), key=lambda pair: (pair[1], pair[0])):
        if not size:
            continue
        value <<= size - previous
        result[symbol] = (int(f"{value:0{size}b}"[::-1], 2), size)
        value += 1
        previous = size
    return result


def stored(bits, data, *, final=False):
    chunks = [data[i : i + 65535] for i in range(0, len(data), 65535)] or [b""]
    for i, chunk in enumerate(chunks):
        bits.put(int(final and i == len(chunks) - 1), 1)
        bits.put(0, 2)
        bits.align()
        bits.put(len(chunk), 16)
        bits.put(len(chunk) ^ 65535, 16)
        for byte in chunk:
            bits.put(byte, 8)


def literal_block(bits, data):
    if any(
        byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for byte in data
    ):
        raise ValueError("registered span is not unpadded base64")
    frequencies = Counter(data)
    frequencies[256] = 1
    sizes = lengths(frequencies)
    before = bits.position
    bits.put(0, 1)  # More JSON follows this span.
    bits.put(2, 2)
    bits.put(0, 5)  # Exactly 257 literal/length symbols, including EOB.
    bits.put(0, 5)  # One unused distance symbol.
    bits.put(15, 4)  # All 19 code-length alphabet entries.
    order = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)
    cl_sizes = {symbol: 4 for symbol in range(16)}
    for symbol in order:
        bits.put(cl_sizes.get(symbol, 0), 3)
    cl_codes = codes(cl_sizes)
    for symbol in range(257):
        bits.put(*cl_codes[sizes.get(symbol, 0)])
    bits.put(*cl_codes[1])
    header_bits = bits.position - before
    table = codes(sizes)
    payload_start = bits.position
    for byte in data:
        bits.put(*table[byte])
    bits.put(*table[256])
    return {
        "raw_span_bytes": len(data),
        "literal_bits": bits.position - payload_start,
        "literal_charge_bytes": (bits.position - payload_start + 7) // 8,
        "header_bits": header_bits,
        "block_bits": bits.position - before,
        "code_lengths": {str(key): value for key, value in sorted(sizes.items())},
    }


def wrap(raw, deflated):
    return (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
        + deflated
        + struct.pack("<II", binascii.crc32(raw), len(raw) & 0xFFFFFFFF)
    )


def member(spans):
    """Spans are (name, bytes, literal_carrier); report actual additive bit costs."""
    bits = Bits()
    report = {}
    raw = b"".join(data for _, data, _ in spans)
    for i, (name, data, literal) in enumerate(spans):
        start = bits.position
        if literal:
            report[name] = literal_block(bits, data)
        else:
            stored(bits, data, final=i == len(spans) - 1)
            report[name] = {"raw_span_bytes": len(data), "block_bits": bits.position - start}
    payload = bits.finish()
    result = wrap(raw, payload)
    return result, {
        "sections": report,
        "raw_bytes": len(raw),
        "deflate_bytes": len(payload),
        "gzip_framing_bytes": 18,
        "gzip_bytes": len(result),
        "padding_bits": len(payload) * 8 - sum(row["block_bits"] for row in report.values()),
    }


def unpadded(data):
    return base64.b64encode(data).rstrip(b"=")


def compressed_sections(spans):
    """One gzip member, with additive, independently charged section boundaries."""
    compressor = zlib.compressobj(wbits=-15)
    chunks, report = [], {}
    raw = b"".join(data for _, data in spans)
    for i, (name, data) in enumerate(spans):
        chunk = compressor.compress(data) + compressor.flush(
            zlib.Z_FINISH if i == len(spans) - 1 else zlib.Z_SYNC_FLUSH
        )
        chunks.append(chunk)
        report[name] = {"raw_bytes": len(data), "deflate_bytes": len(chunk)}
    payload = b"".join(chunks)
    result = wrap(raw, payload)
    return result, {
        "sections": report,
        "raw_bytes": len(raw),
        "deflate_bytes": len(payload),
        "gzip_framing_bytes": 18,
        "gzip_bytes": len(result),
    }
