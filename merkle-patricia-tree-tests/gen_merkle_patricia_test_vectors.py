#!/usr/bin/env python3
"""Generate test vectors for the Merkle Patricia Tree spec."""

import base64
import hashlib
import itertools
import json
import random

SEED = b"waict-v1-mpt-kats"
ROOT_KAT_FILENAME = "mpt_root_kats.jsonl"
INCLUSION_KAT_FILENAME = "mpt_inclusion_kats.jsonl"
BAD_VERIFIER_KAT_FILENAME = "mpt_bad_verifier_kats.jsonl"


# ---------------------------------------------------------------------------
# Core MPT primitives
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def bit_at(b: bytes, i: int) -> int:
    """Get bit i of a 32-byte value, where bit 0 is the MSB of byte 0."""
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
        mask = (
            0xFF << (8 - remaining_bits)
        ) & 0xFF  # keep the upper remaining_bits bits
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
        hash_val=sha256(k + v),
    )


def similarity(n: InteriorNode, m: InteriorNode) -> int:
    length = min(n.prefix_len, m.prefix_len)
    assert not (length == 256 and n.prefix == m.prefix), "identical length-256 prefixes"
    result = common_prefix_len(n.prefix, m.prefix, length)
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
    if ni.prefix < nj.prefix:
        children_hashes = ni.hash + nj.hash
    else:
        children_hashes = nj.hash + ni.hash
    hash_new = sha256(children_hashes + bytes([r]))
    return InteriorNode(prefix=prefix_new, prefix_len=r, hash_val=hash_new)


# ---------------------------------------------------------------------------
# Combined root + inclusion proof (over a list, with a target index)
# ---------------------------------------------------------------------------


def compute_root_and_inclusion(target_idx: int, pairs: list) -> tuple:
    """
    Compute the MPT root hash and inclusion proof for pairs[target_idx].
    target_idx is 0-indexed.
    Returns (proof_bytes, root_hash).
    """
    assert len(pairs) > 0, "cannot prove inclusion in an empty list"

    proof_prefix = b"mptproof" + bytes([0x01]) + pairs[target_idx][1]

    nodes = [to_interior(k, v) for k, v in pairs]
    proof, root = compute_root_and_inclusion_helper(target_idx, nodes)
    return (proof_prefix + proof, root)


def compute_root_and_inclusion_helper(target_idx: int, nodes: list) -> tuple:
    """
    Compute the MPT root hash and non-intro portion of inclusion proof for
    nodes[target_idx].
    target_idx is 0-indexed.
    Returns (proof_bytes, root_hash).
    """
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
        h_idx = best_j if target_idx == best_i else best_i
        nh = nodes[h_idx]
        proof_segment = bytes([r]) + nh.hash
        new_target = best_i
    else:
        proof_segment = b""
        new_target = target_idx if target_idx < best_j else target_idx - 1

    rest_proof, root = compute_root_and_inclusion_helper(new_target, new_nodes)
    return (proof_segment + rest_proof, root)


# ---------------------------------------------------------------------------
# Correct inclusion verification
# ---------------------------------------------------------------------------


class VerificationError(Exception):
    """Raised when a proof is structurally malformed."""

    pass


def verify_inclusion(root: bytes, k: bytes, v: bytes, proof: bytes) -> bool:
    """
    Correct inclusion verifier matching the spec's VerifyInclusion.
    Returns True if (k, v) is proven to be in the tree with the given root.
    Returns False if the proof is structurally valid but doesn't match.
    Raises VerificationError if the proof is malformed.
    """
    if len(proof) < 41 or proof[:9] != b"mptproof\x01":
        raise VerificationError("invalid proof header")
    if proof[9:41] != v:
        return False
    node = to_interior(k, v)
    return _verify_inclusion_helper(root, node, proof[9 + 32 :], 256)


def _verify_inclusion_helper(
    root: bytes, node: InteriorNode, proof: bytes, last_r: int
) -> bool:
    if len(proof) == 0:
        return root == node.hash
    if len(proof) < 33:
        raise VerificationError("incomplete proof segment")

    r = proof[0]
    sibling = proof[1:33]
    if r >= last_r:
        raise VerificationError(f"non-decreasing r: {r} >= {last_r}")

    prefix_new = prefix_truncate(node.prefix, r)
    if bit_at(node.prefix, r) == 0:
        children_hashes = node.hash + sibling
    else:
        children_hashes = sibling + node.hash
    hash_new = sha256(children_hashes + bytes([r]))
    node_new = InteriorNode(prefix=prefix_new, prefix_len=r, hash_val=hash_new)
    return _verify_inclusion_helper(root, node_new, proof[33:], r)


# ---------------------------------------------------------------------------
# Bad (deliberately weak) inclusion verification
# ---------------------------------------------------------------------------


def bad_verify_inclusion(root: bytes, k: bytes, v: bytes, proof: bytes) -> bool:
    """
    Deliberately weak inclusion verifier with the following flaws:
    1. Does not check the magic header (just skips 9 bytes)
    2. Does not verify the embedded value matches v (just skips 32 bytes)
    3. Treats any remainder < 33 bytes as end-of-proof (instead of
       raising an error for 1-32 trailing bytes)
    4. Does not check that r values are strictly decreasing
    """
    # BAD: skip header without checking its value
    proof = proof[9:]
    # BAD: skip embedded value without verifying it matches v
    proof = proof[32:]
    node = to_interior(k, v)
    return _bad_verify_inclusion_helper(root, node, proof)


def _bad_verify_inclusion_helper(root: bytes, node: InteriorNode, proof: bytes) -> bool:
    # BAD: treats any remainder < 33 as valid end-of-proof
    # (should only accept exactly 0 remaining bytes)
    if len(proof) < 33:
        return root == node.hash
    r = proof[0]
    sibling = proof[1:33]
    # BAD: no check that r < last_r
    prefix_new = prefix_truncate(node.prefix, r)
    if bit_at(node.prefix, r) == 0:
        children_hashes = node.hash + sibling
    else:
        children_hashes = sibling + node.hash
    hash_new = sha256(children_hashes + bytes([r]))
    node_new = InteriorNode(prefix=prefix_new, prefix_len=r, hash_val=hash_new)
    return _bad_verify_inclusion_helper(root, node_new, proof[33:])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def random_bytestring(rng: random.Random) -> bytes:
    """Generate a random 32-byte bytestring"""
    return rng.getrandbits(256).to_bytes(32, "big")


def set_bit(data: bytes, i: int, val: int) -> bytes:
    """Set bit i of a 32-byte value to val (0 or 1). Bit 0 is the MSB of byte 0."""
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
    _, root = compute_root_and_inclusion(0, pairs)
    return root


def test_root_matches(pairs: list):
    """Verify compute_root_and_inclusion produces the same root for every target index."""
    if len(pairs) == 0:
        return
    _, expected_root = compute_root_and_inclusion(0, pairs)
    for idx in range(1, len(pairs)):
        _, root = compute_root_and_inclusion(idx, pairs)
        assert root == expected_root, (
            f"root mismatch for target {idx}: {root.hex()} != {expected_root.hex()}"
        )


def test_permutation_invariance(pairs: list, rng: random.Random, num_perms: int = 20):
    """
    Verify that compute_root_and_inclusion(k, L) produces identical (proof, root)
    regardless of where nk sits in L and how the rest of L is permuted.
    """
    if len(pairs) <= 1:
        return

    # For each element, compute reference proof in the canonical order
    refs = {}
    for idx in range(len(pairs)):
        proof, root = compute_root_and_inclusion(idx, pairs)
        refs[idx] = (proof, root)

    # Try random permutations
    indices = list(range(len(pairs)))
    for _ in range(num_perms):
        perm = list(indices)
        rng.shuffle(perm)
        perm_pairs = [pairs[p] for p in perm]

        for orig_idx in range(len(pairs)):
            new_idx = perm.index(orig_idx)
            proof, root = compute_root_and_inclusion(new_idx, list(perm_pairs))
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
            perm_pairs = [pairs[p] for p in perm]
            for orig_idx in range(len(pairs)):
                new_idx = perm.index(orig_idx)
                proof, root = compute_root_and_inclusion(new_idx, list(perm_pairs))
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

    # Verify that generated proofs pass the correct verifier
    rng2 = random.Random(b"mpt-verification-tests")
    for size in range(1, 8):
        pairs = [
            (random_bytestring(rng2), random_bytestring(rng2)) for _ in range(size)
        ]
        for idx in range(size):
            proof, root = compute_root_and_inclusion(idx, pairs)
            k, v = pairs[idx]
            assert verify_inclusion(root, k, v, proof), (
                f"valid proof failed verify_inclusion for size={size} idx={idx}"
            )
            assert bad_verify_inclusion(root, k, v, proof), (
                f"valid proof failed bad_verify_inclusion for size={size} idx={idx}"
            )
    print("  verify_inclusion on generated proofs: OK")

    print("All property tests passed.")


# ---------------------------------------------------------------------------
# Test vector construction
# ---------------------------------------------------------------------------


def make_root_vector(pairs: list, label: str) -> dict:
    root = mpt(pairs)
    return {
        "label": label,
        "root": b64(root),
        "leaves": [{"key": b64(k), "value": b64(v)} for k, v in pairs],
    }


def make_inclusion_vector(pairs: list, target_idx: int, label: str) -> dict:
    proof, root = compute_root_and_inclusion(target_idx, pairs)
    return {
        "label": label,
        "root": b64(root),
        "leaves": [{"key": b64(k), "value": b64(v)} for k, v in pairs],
        "target_index": target_idx,
        "proof": b64(proof),
    }


def generate_bad_verifier_vectors(rng: random.Random) -> list:
    """
    Generate test vectors that pass bad_verify_inclusion but fail
    verify_inclusion. Each vector exploits a specific missing check.
    """
    vectors = []

    # Build a valid proof to use as a starting point for exploits 1-3
    k1 = random_bytestring(rng)
    v1 = random_bytestring(rng)
    k2 = random_bytestring(rng)
    v2 = random_bytestring(rng)
    pairs = [(k1, v1), (k2, v2)]
    valid_proof, root = compute_root_and_inclusion(0, pairs)

    # Sanity: the valid proof passes both verifiers
    assert verify_inclusion(root, k1, v1, valid_proof)
    assert bad_verify_inclusion(root, k1, v1, valid_proof)

    # --- Exploit 1: Wrong magic header ---
    # Replace the 9-byte header with garbage. The bad verifier blindly skips
    # past it, so the rest of the proof still verifies.
    bad_proof = b"XXXXXXXXX" + valid_proof[9:]
    assert bad_verify_inclusion(root, k1, v1, bad_proof)
    try:
        verify_inclusion(root, k1, v1, bad_proof)
        assert False, "correct verifier should have raised"
    except VerificationError:
        pass
    vectors.append(
        {
            "label": "wrong_magic_header",
            "exploit": "Header bytes replaced with garbage; bad verifier skips without checking",
            "root": b64(root),
            "key": b64(k1),
            "value": b64(v1),
            "proof": b64(bad_proof),
        }
    )

    # --- Exploit 2: Wrong embedded value ---
    # Replace the 32-byte value embedded after the header with a different
    # value. The bad verifier skips it without comparing to v.
    fake_v = random_bytestring(rng)
    assert fake_v != v1
    bad_proof = valid_proof[:9] + fake_v + valid_proof[41:]
    assert bad_verify_inclusion(root, k1, v1, bad_proof)
    assert not verify_inclusion(root, k1, v1, bad_proof)
    vectors.append(
        {
            "label": "wrong_embedded_value",
            "exploit": "Embedded value replaced with random bytes; bad verifier skips value check",
            "root": b64(root),
            "key": b64(k1),
            "value": b64(v1),
            "proof": b64(bad_proof),
        }
    )

    # --- Exploit 3: Trailing junk bytes ---
    # Append 16 bytes of junk after the valid proof. After processing all
    # real segments, 16 bytes remain. The bad verifier treats < 33 remaining
    # as end-of-proof; the correct verifier raises Malformed.
    junk = bytes(rng.getrandbits(8) for _ in range(16))
    bad_proof = valid_proof + junk
    assert bad_verify_inclusion(root, k1, v1, bad_proof)
    try:
        verify_inclusion(root, k1, v1, bad_proof)
        assert False, "correct verifier should have raised"
    except VerificationError:
        pass
    vectors.append(
        {
            "label": "trailing_junk_bytes",
            "exploit": "16 junk bytes appended; bad verifier silently ignores trailing remainder < 33 bytes",
            "root": b64(root),
            "key": b64(k1),
            "value": b64(v1),
            "proof": b64(bad_proof),
        }
    )

    # --- Exploit 4: Non-monotonic r values ---
    # Construct a proof from scratch where r increases (50 → 100).
    # The bad verifier doesn't check monotonicity.
    k = random_bytestring(rng)
    v = random_bytestring(rng)
    node = to_interior(k, v)

    r1 = 50
    sibling1 = random_bytestring(rng)
    if bit_at(node.prefix, r1) == 0:
        ch = node.hash + sibling1
    else:
        ch = sibling1 + node.hash
    hash1 = sha256(ch + bytes([r1]))
    node1 = InteriorNode(
        prefix=prefix_truncate(node.prefix, r1), prefix_len=r1, hash_val=hash1
    )

    r2 = 100  # r2 > r1: non-monotonic!
    sibling2 = random_bytestring(rng)
    if bit_at(node1.prefix, r2) == 0:
        ch = node1.hash + sibling2
    else:
        ch = sibling2 + node1.hash
    crafted_root = sha256(ch + bytes([r2]))

    bad_proof = b"mptproof\x01" + v + bytes([r1]) + sibling1 + bytes([r2]) + sibling2
    assert bad_verify_inclusion(crafted_root, k, v, bad_proof)
    try:
        verify_inclusion(crafted_root, k, v, bad_proof)
        assert False, "correct verifier should have raised"
    except VerificationError:
        pass
    vectors.append(
        {
            "label": "non_monotonic_r",
            "exploit": "r values go 50 then 100 (increasing); bad verifier skips monotonicity check",
            "root": b64(crafted_root),
            "key": b64(k),
            "value": b64(v),
            "proof": b64(bad_proof),
        }
    )

    # --- Exploit 5: Root mismatch ---
    # A structurally valid proof, but the root is all zeros (doesn't match
    # the computed root). Both verifiers reject this.
    k = random_bytestring(rng)
    v = random_bytestring(rng)
    pairs_single = [(k, v)]
    valid_proof, _ = compute_root_and_inclusion(0, pairs_single)
    zero_root = b"\x00" * 32
    assert not bad_verify_inclusion(zero_root, k, v, valid_proof)
    assert not verify_inclusion(zero_root, k, v, valid_proof)
    vectors.append(
        {
            "label": "root_mismatch",
            "exploit": "Valid proof structure but root is all zeros; computed root does not match",
            "root": b64(zero_root),
            "key": b64(k),
            "value": b64(v),
            "proof": b64(valid_proof),
        }
    )

    return vectors


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

    # --- Bad verifier exploit vectors ---
    bad_rng = random.Random(b"waict-v1-bad-verifier-kats")
    bad_vectors = generate_bad_verifier_vectors(bad_rng)

    # --- Write output ---
    with open(ROOT_KAT_FILENAME, "w") as f:
        for vec in root_vectors:
            f.write(json.dumps(vec) + "\n")
    print(f"Wrote {len(root_vectors)} root test vectors to {ROOT_KAT_FILENAME}")

    with open(INCLUSION_KAT_FILENAME, "w") as f:
        for vec in inclusion_vectors:
            f.write(json.dumps(vec) + "\n")
    print(
        f"Wrote {len(inclusion_vectors)} inclusion test vectors to {INCLUSION_KAT_FILENAME}"
    )

    with open(BAD_VERIFIER_KAT_FILENAME, "w") as f:
        for vec in bad_vectors:
            f.write(json.dumps(vec) + "\n")
    print(
        f"Wrote {len(bad_vectors)} bad-verifier exploit vectors to {BAD_VERIFIER_KAT_FILENAME}"
    )


if __name__ == "__main__":
    main()
