#!/usr/bin/env python3
"""Generate test vectors for the Merkle Patricia Tree spec."""

import hashlib
import itertools
import json
import base64
import random
import sys

SEED = b"waict-v1-mpt-kats"
ROOT_KAT_FILENAME = "mpt_root_kats.jsonl"
INCLUSION_KAT_FILENAME = "mpt_inclusion_kats.jsonl"


# ---------------------------------------------------------------------------
# Core MPT primitives
# ---------------------------------------------------------------------------

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


def find_max_similarity_pair(nodes: list) -> tuple:
    """Find indices i < j that maximize Similarity(nodes[i], nodes[j])."""
    best_sim = -1
    best_i, best_j = -1, -1
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            s = similarity(nodes[i], nodes[j])
            if s > best_sim:
                best_sim = s
                best_i, best_j = i, j
    return best_i, best_j, best_sim


def merge_nodes(ni: InteriorNode, nj: InteriorNode, r: int) -> InteriorNode:
    """Merge two interior nodes at similarity r into a parent node."""
    prefix_new = prefix_truncate(ni.prefix, r)
    if ni.prefix <= nj.prefix:
        children_hashes = ni.hash + nj.hash
    else:
        children_hashes = nj.hash + ni.hash
    hash_new = sha256(b"\x01" + bytes([r]) + prefix_new + children_hashes)
    return InteriorNode(prefix=prefix_new, prefix_len=r, hash_val=hash_new)


# ---------------------------------------------------------------------------
# Combined root + inclusion proof (over a list, with a target index)
# ---------------------------------------------------------------------------

def compute_root_and_inclusion(target_idx: int, nodes: list) -> tuple:
    """
    Compute the MPT root hash and inclusion proof for nodes[target_idx].
    target_idx is 0-indexed.
    Returns (proof_bytes, root_hash).
    """
    assert len(nodes) > 0, "cannot prove inclusion in an empty list"
    if len(nodes) == 1:
        return (b"", nodes[0].hash)

    # Same global merge as MPT'
    best_i, best_j, r = find_max_similarity_pair(nodes)
    ni, nj = nodes[best_i], nodes[best_j]
    n_new = merge_nodes(ni, nj, r)

    # Build L': replace best_i with n', remove best_j
    new_nodes = list(nodes)
    new_nodes[best_i] = n_new
    new_nodes.pop(best_j)

    # Emit proof segment if the target is part of this merge
    if target_idx == best_i or target_idx == best_j:
        nk = nodes[target_idx]
        h_idx = best_j if target_idx == best_i else best_i
        nh = nodes[h_idx]
        is_left = nk.prefix <= nh.prefix
        proof_segment = bytes([int(is_left)]) + bytes([r]) + nh.hash
        new_target = best_i
    else:
        proof_segment = b""
        new_target = target_idx if target_idx < best_j else target_idx - 1

    rest_proof, root = compute_root_and_inclusion(new_target, new_nodes)
    return (proof_segment + rest_proof, root)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

def mpt(pairs: list) -> bytes:
    """Compute the MPT root hash for a set of key-value pairs."""
    if len(pairs) == 0:
        return sha256(b"")
    nodes = [to_interior(k, v) for k, v in pairs]
    _, root = compute_root_and_inclusion(0, nodes)
    return root


def test_root_matches(pairs: list):
    """Verify compute_root_and_inclusion produces the same root for every target index."""
    if len(pairs) == 0:
        return
    nodes = [to_interior(k, v) for k, v in pairs]
    _, expected_root = compute_root_and_inclusion(0, list(nodes))
    for idx in range(1, len(pairs)):
        _, root = compute_root_and_inclusion(idx, list(nodes))
        assert root == expected_root, (
            f"root mismatch for target {idx}: "
            f"{root.hex()} != {expected_root.hex()}"
        )


def test_permutation_invariance(pairs: list, rng: random.Random, num_perms: int = 20):
    """
    Verify that compute_root_and_inclusion(k, L) produces identical (proof, root)
    regardless of where nk sits in L and how the rest of L is permuted.
    """
    if len(pairs) <= 1:
        return

    nodes = [to_interior(k, v) for k, v in pairs]

    # For each element, compute reference proof in the canonical order
    refs = {}
    for idx in range(len(pairs)):
        proof, root = compute_root_and_inclusion(idx, list(nodes))
        refs[idx] = (proof, root)

    # Try random permutations
    indices = list(range(len(pairs)))
    for _ in range(num_perms):
        perm = list(indices)
        rng.shuffle(perm)
        perm_nodes = [nodes[p] for p in perm]

        for orig_idx in range(len(pairs)):
            new_idx = perm.index(orig_idx)
            proof, root = compute_root_and_inclusion(new_idx, list(perm_nodes))
            ref_proof, ref_root = refs[orig_idx]
            assert root == ref_root, (
                f"root differs under permutation for element {orig_idx}"
            )
            assert proof == ref_proof, (
                f"proof differs under permutation for element {orig_idx}"
            )

    # For small lists, also try all permutations exhaustively
    if len(pairs) <= 6:
        for perm in itertools.permutations(indices):
            perm = list(perm)
            perm_nodes = [nodes[p] for p in perm]
            for orig_idx in range(len(pairs)):
                new_idx = perm.index(orig_idx)
                proof, root = compute_root_and_inclusion(new_idx, list(perm_nodes))
                ref_proof, ref_root = refs[orig_idx]
                assert root == ref_root, (
                    f"root differs under permutation {perm} for element {orig_idx}"
                )
                assert proof == ref_proof, (
                    f"proof differs under permutation {perm} for element {orig_idx}"
                )


def run_property_tests():
    """Run property tests before generating test vectors."""
    print("Running property tests...")
    rng = random.Random(b"mpt-property-tests")

    # Fixed small cases
    for size in range(1, 7):
        pairs = [(random_bytestring(rng), random_bytestring(rng)) for _ in range(size)]
        test_root_matches(pairs)
        test_permutation_invariance(pairs, rng)
        print(f"  size {size}: root + permutation invariance OK")

    # Larger random cases (random permutations only, not exhaustive)
    for size in [8, 10, 14, 16]:
        pairs = [(random_bytestring(rng), random_bytestring(rng)) for _ in range(size)]
        test_root_matches(pairs)
        test_permutation_invariance(pairs, rng, num_perms=30)
        print(f"  size {size}: root + permutation invariance OK")

    print("All property tests passed.")


# ---------------------------------------------------------------------------
# Test vector construction
# ---------------------------------------------------------------------------

def make_root_vector(pairs: list, label: str) -> dict:
    root = mpt(pairs)
    return {
        "label": label,
        "root": b64(root),
        "set": [{"key": b64(k), "value": b64(v)} for k, v in pairs],
    }


def make_inclusion_vector(pairs: list, target_idx: int, label: str) -> dict:
    nodes = [to_interior(k, v) for k, v in pairs]
    proof, root = compute_root_and_inclusion(target_idx, nodes)
    return {
        "label": label,
        "root": b64(root),
        "list": [{"key": b64(k), "value": b64(v)} for k, v in pairs],
        "target_index": target_idx,
        "proof": b64(proof),
    }


def build_edge_case_pairs(rng: random.Random) -> list:
    """Return a list of (label, pairs) for edge-case sets."""
    cases = []

    # Two keys differing only at the last bit (bit 255)
    k0 = random_bytestring(rng)
    v0 = random_bytestring(rng)
    k1 = set_bit(k0, 255, 1 - bit_at(k0, 255))
    v1 = random_bytestring(rng)
    cases.append(("differ_last_bit", [(k0, v0), (k1, v1)]))

    # Two keys differing only at the first bit (bit 0)
    k0 = random_bytestring(rng)
    v0 = random_bytestring(rng)
    k1 = set_bit(k0, 0, 1 - bit_at(k0, 0))
    v1 = random_bytestring(rng)
    cases.append(("differ_first_bit", [(k0, v0), (k1, v1)]))

    # 8 keys sharing 250-bit common prefix
    base_key = random_bytestring(rng)
    pairs = []
    for i in range(8):
        k = bytes(bytearray(base_key))
        for bit_pos in range(3):
            k = set_bit(k, 250 + bit_pos, (i >> (2 - bit_pos)) & 1)
        v = random_bytestring(rng)
        pairs.append((k, v))
    cases.append(("long_common_prefix_250bits", pairs))

    # Tie scenario: 4 keys where two disjoint pairs tie for max similarity
    base = random_bytestring(rng)
    base = set_bit(base, 0, 0)
    base = set_bit(base, 1, 0)
    k00 = set_bit(set_bit(base, 0, 0), 1, 0)
    k01 = set_bit(set_bit(base, 0, 0), 1, 1)
    k10 = set_bit(set_bit(base, 0, 1), 1, 0)
    k11 = set_bit(set_bit(base, 0, 1), 1, 1)
    pairs = [
        (k00, random_bytestring(rng)),
        (k01, random_bytestring(rng)),
        (k10, random_bytestring(rng)),
        (k11, random_bytestring(rng)),
    ]
    cases.append(("tie_max_similarity", pairs))

    # All-zeros key and value
    z = b"\x00" * 32
    cases.append(("all_zeros", [(z, z)]))

    # All-ones key and value
    ones = b"\xff" * 32
    cases.append(("all_ones", [(ones, ones)]))

    # All-zeros vs all-ones
    cases.append(("zeros_and_ones", [(z, z), (ones, ones)]))

    return cases


def main():
    run_property_tests()

    rng = random.Random(SEED)
    root_vectors = []
    inclusion_vectors = []

    # --- Random sets of sizes 0..=16 ---
    for size in range(17):
        pairs = [(random_bytestring(rng), random_bytestring(rng)) for _ in range(size)]
        root_vectors.append(make_root_vector(pairs, f"random_size_{size}"))
        if size > 0:
            target = rng.randint(0, size - 1)
            inclusion_vectors.append(
                make_inclusion_vector(pairs, target, f"random_size_{size}_idx{target}")
            )

    # --- Edge cases ---
    for label, pairs in build_edge_case_pairs(rng):
        root_vectors.append(make_root_vector(pairs, label))
        # Generate an inclusion proof for every element in edge-case sets
        for idx in range(len(pairs)):
            inclusion_vectors.append(
                make_inclusion_vector(pairs, idx, f"{label}_idx{idx}")
            )

    # --- Write output ---
    with open(ROOT_KAT_FILENAME, "w") as f:
        for vec in root_vectors:
            f.write(json.dumps(vec) + "\n")
    print(f"Wrote {len(root_vectors)} root test vectors to {ROOT_KAT_FILENAME}")

    with open(INCLUSION_KAT_FILENAME, "w") as f:
        for vec in inclusion_vectors:
            f.write(json.dumps(vec) + "\n")
    print(f"Wrote {len(inclusion_vectors)} inclusion test vectors to {INCLUSION_KAT_FILENAME}")


if __name__ == "__main__":
    main()
