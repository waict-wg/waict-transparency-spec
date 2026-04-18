#!/usr/bin/env python3
"""Generate test vectors for the Merkle Patricia Tree spec."""

import hashlib
import json
import base64
import random

SEED = b"waict-v1-mpt-kats"
OUT_FILENAME = "merkle_patricia_vectors.jsonl"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def bit_at(b: bytes, i: int) -> int:
    """Get bit i of a 32-byte value, where bit 0 is the leftmost (MSB of byte 0)."""
    return (b[i // 8] >> (7 - i % 8)) & 1


def common_prefix_len(a: bytes, b: bytes, max_len: int) -> int:
    """Count leading matching bits between a and b, up to max_len bits."""
    for i in range(max_len):
        if bit_at(a, i) != bit_at(b, i):
            return i
    return max_len


def prefix_truncate(prefix: bytes, r: int) -> bytes:
    """Return prefix[..r] || 0...0, padded to 32 bytes."""
    result = bytearray(32)
    full_bytes = r // 8
    for i in range(full_bytes):
        result[i] = prefix[i]
    remaining_bits = r % 8
    if remaining_bits > 0 and full_bytes < 32:
        mask = (0xFF << (8 - remaining_bits)) & 0xFF
        result[full_bytes] = prefix[full_bytes] & mask
    return bytes(result)


class InteriorNode:
    def __init__(self, prefix: bytes, prefix_len: int, hash_val: bytes):
        self.prefix = prefix
        self.prefix_len = prefix_len
        self.hash = hash_val


def to_interior(k: bytes, v: bytes) -> InteriorNode:
    return InteriorNode(
        prefix=k,
        prefix_len=256,
        hash_val=sha256(b"\x00" + k + v),
    )


def similarity(n: InteriorNode, m: InteriorNode) -> int:
    l = min(n.prefix_len, m.prefix_len)
    assert not (l == 256 and n.prefix == m.prefix), "identical length-256 prefixes"
    result = common_prefix_len(n.prefix, m.prefix, l)
    assert result <= 255
    return result


def mpt_prime(nodes: list) -> bytes:
    if len(nodes) == 0:
        return sha256(b"")
    if len(nodes) == 1:
        return nodes[0].hash

    # Find pair with maximum similarity
    best_sim = -1
    best_i, best_j = -1, -1
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            s = similarity(nodes[i], nodes[j])
            if s > best_sim:
                best_sim = s
                best_i, best_j = i, j

    ni, nj = nodes[best_i], nodes[best_j]
    r = best_sim

    prefix_new = prefix_truncate(ni.prefix, r)

    if ni.prefix <= nj.prefix:
        children_hashes = ni.hash + nj.hash
    else:
        children_hashes = nj.hash + ni.hash

    hash_new = sha256(b"\x01" + bytes([r]) + prefix_new + children_hashes)
    n_new = InteriorNode(prefix=prefix_new, prefix_len=r, hash_val=hash_new)

    new_nodes = [node for idx, node in enumerate(nodes) if idx not in (best_i, best_j)]
    new_nodes.append(n_new)

    return mpt_prime(new_nodes)


def mpt(pairs: list) -> bytes:
    nodes = [to_interior(k, v) for k, v in pairs]
    return mpt_prime(nodes)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def random_bytestring(rng: random.Random) -> bytes:
    """Generate a random 32-byte bytestring"""
    return rng.getrandbits(256).to_bytes(32, "big")


def set_bit(data: bytes, i: int, val: int) -> bytes:
    """Set bit i of a 32-byte value to val (0 or 1)."""
    ba = bytearray(data)
    byte_idx = i // 8
    bit_idx = 7 - i % 8
    if val:
        ba[byte_idx] |= 1 << bit_idx
    else:
        ba[byte_idx] &= ~(1 << bit_idx)
    return bytes(ba)


def make_test_vector(pairs: list, label: str) -> dict:
    root = mpt(pairs)
    return {
        "label": label,
        "root": b64(root),
        "set": [{"key": b64(k), "value": b64(v)} for k, v in pairs],
    }


def main():
    rng = random.Random(SEED)
    vectors = []

    # --- Random sets of sizes 0..=16 ---
    for size in range(17):
        pairs = [(random_bytestring(rng), random_bytestring(rng)) for _ in range(size)]
        vectors.append(make_test_vector(pairs, f"random_size_{size}"))

    # --- Edge case: two keys differing only at the last bit (bit 255) ---
    k0 = random_bytestring(rng)
    v0 = random_bytestring(rng)
    k1 = set_bit(k0, 255, 1 - bit_at(k0, 255))
    v1 = random_bytestring(rng)
    vectors.append(make_test_vector([(k0, v0), (k1, v1)], "differ_last_bit"))

    # --- Edge case: two keys differing only at the first bit (bit 0) ---
    k0 = random_bytestring(rng)
    v0 = random_bytestring(rng)
    k1 = set_bit(k0, 0, 1 - bit_at(k0, 0))
    v1 = random_bytestring(rng)
    vectors.append(make_test_vector([(k0, v0), (k1, v1)], "differ_first_bit"))

    # --- Edge case: 8 keys sharing 250-bit common prefix ---
    base_key = random_bytestring(rng)
    pairs = []
    for i in range(8):
        k = bytearray(base_key)
        # Write bits 250..257 with the value i (3 bits), rest stays as base
        # We set bits 250, 251, 252 to the 3-bit encoding of i
        k = bytes(k)
        for bit_pos in range(3):
            k = set_bit(k, 250 + bit_pos, (i >> (2 - bit_pos)) & 1)
        v = random_bytestring(rng)
        pairs.append((k, v))
    vectors.append(make_test_vector(pairs, "long_common_prefix_250bits"))

    # --- Edge case: tie scenario ---
    # 4 keys: 00..., 01..., 10..., 11... (differ at bit 1 within each pair)
    # Pairs (k0,k1) and (k2,k3) both have similarity = bit where they first differ
    base = random_bytestring(rng)
    # Zero out the first 2 bits, then construct 4 keys
    base = set_bit(base, 0, 0)
    base = set_bit(base, 1, 0)
    k00 = set_bit(set_bit(base, 0, 0), 1, 0)
    k01 = set_bit(set_bit(base, 0, 0), 1, 1)
    k10 = set_bit(set_bit(base, 0, 1), 1, 0)
    k11 = set_bit(set_bit(base, 0, 1), 1, 1)
    # Make remaining bits unique so keys are distinct beyond bit 1
    # They already differ at bits 0-1, and share all other bits from base.
    # Similarity: (k00,k01)=1, (k10,k11)=1, cross-pairs=0. Tie at max sim=1.
    pairs = [
        (k00, random_bytestring(rng)),
        (k01, random_bytestring(rng)),
        (k10, random_bytestring(rng)),
        (k11, random_bytestring(rng)),
    ]
    vectors.append(make_test_vector(pairs, "tie_max_similarity"))

    # --- Edge case: all-zeros key and value ---
    z = b"\x00" * 32
    vectors.append(make_test_vector([(z, z)], "all_zeros"))

    # --- Edge case: all-ones key and value ---
    ones = b"\xff" * 32
    vectors.append(make_test_vector([(ones, ones)], "all_ones"))

    # --- Edge case: all-zeros vs all-ones (differ at bit 0, max distance) ---
    vectors.append(
        make_test_vector([(z, z), (ones, ones)], "zeros_and_ones")
    )

    with open(OUT_FILENAME, "w") as f:
        for vec in vectors:
            f.write(json.dumps(vec) + "\n")

    print(f"Wrote {len(vectors)} test vectors to {OUT_FILENAME}")


if __name__ == "__main__":
    main()
