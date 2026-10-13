"""Independent DEFLATE structural reader for registered first-member tests.

Rejects length/distance symbols, fixed Huffman blocks and invalid stored lengths.
Does not import the writer or its code-generation helpers.
"""


class Reader:
    def __init__(self, data):
        self.data, self.bit = data, 0

    def read(self, size):
        value = 0
        for i in range(size):
            value |= ((self.data[self.bit // 8] >> (self.bit % 8)) & 1) << i
            self.bit += 1
        return value

    def align(self):
        self.bit = (self.bit + 7) // 8 * 8


def tree(lengths):
    counts = [lengths.count(i) for i in range(16)]
    counts[0] = 0
    code, next_code = 0, {}
    for bits in range(1, 16):
        code = (code + counts[bits - 1]) << 1
        next_code[bits] = code
    result = {}
    for symbol, bits in enumerate(lengths):
        if bits:
            result[(bits, next_code[bits])] = symbol
            next_code[bits] += 1
    return result


def symbol(reader, mapping):
    code = 0
    for bits in range(1, 16):
        code = (code << 1) | reader.read(1)
        if (bits, code) in mapping:
            return mapping[(bits, code)]
    raise AssertionError("invalid Huffman code")


def blocks(gzip_data):
    assert gzip_data[:10] == b"\x1f\x8b\x08\0\0\0\0\0\0\xff"
    reader = Reader(gzip_data[10:])
    result, final, offset = [], False, 0
    while not final:
        start = reader.bit
        final, kind = reader.read(1), reader.read(2)
        output = bytearray()
        if kind == 0:
            reader.align()
            n, complement = reader.read(16), reader.read(16)
            assert n ^ complement == 65535
            output.extend(reader.read(8) for _ in range(n))
        elif kind == 2:
            hlit, hdist, hclen = reader.read(5) + 257, reader.read(5) + 1, reader.read(4) + 4
            cl = [0] * 19
            order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
            for i in range(hclen):
                cl[order[i]] = reader.read(3)
            lengths, mapping = [], tree(cl)
            while len(lengths) < hlit + hdist:
                value = symbol(reader, mapping)
                if value < 16:
                    lengths.append(value)
                elif value == 16:
                    lengths.extend([lengths[-1]] * (reader.read(2) + 3))
                elif value == 17:
                    lengths.extend([0] * (reader.read(3) + 3))
                else:
                    lengths.extend([0] * (reader.read(7) + 11))
            assert len(lengths) == hlit + hdist
            literal_tree = tree(lengths[:hlit])
            while True:
                value = symbol(reader, literal_tree)
                if value == 256:
                    break
                assert value < 256, "length/distance token in registered literal-only block"
                output.append(value)
        else:
            raise AssertionError(f"unexpected block type {kind}")
        result.append(
            {
                "kind": kind,
                "output_start": offset,
                "output_end": offset + len(output),
                "data": bytes(output),
                "bits": reader.bit - start,
            }
        )
        offset += len(output)
    return result
