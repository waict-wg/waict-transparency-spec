# Merkle Patricia Tree spec

We define the root hash MPT over a set S of key-value pairs (k, v) ∈ 𝔹² where 𝔹 = {0,1}²⁵⁶. We treat an element b ∈ 𝔹 as a bitvector, with b[0] referring to the leftmost bit, and b[..i] referring to the subvector containing all bits from index 0 to and not including i. We use || to mean concatenation. We define H be the SHA256 hash function.

## Creating interior nodes

We define interior nodes as having the structure

    struct Interior {
        prefix: 𝔹,
        prefix_len: u16,
        hash: 𝔹,
    }

For our algorithm, we must map key-value pairs to interior nodes:

    def ToInterior(k, v):
        return Interior {
            prefix: k,
            prefix_len: 256,
            hash: H(0x00 || k || v)
        }

We will also need a utility function that measure the "similarity" of two interior nodes. Similarity is defined as the number of leading binary digits the prefixes have in common:

    // Lexicographic similarity between to prefixes.
    // Precondition: n and m do not have identical prefixes of length-256
    def Similarity(n: Interior, m: Interior) -> u8:
        let l = min(n.prefix_len, m.prefix_len)
        assert l != 256 or n.prefix != m.prefix
        return (n.prefix[..l] ^ m.prefix[..l]).leading_zeros() as u8

Note our precondition permits us to make the final cast to u8. We ensure in later algorithms that this precondition is enforced.

## Defining the root hash

We define our helper function MPT' over a set of interior nodes as follows:

    def MPT'({}): return H("")

    def MPT'({n}): return n.hash

    // Precondition: no two ni, nj have identical prefixes of length-256
    def MPT'(S = {n1, n2, ..., nk}):
        find an i,j that maximizes r = Similarity(ni, nj) (note this is not nec unique)
        let prefix' = ni.prefix[..r] || 0...0  // pad to 256 bits
        let children_hashes = if ni.prefix ≤ nj.prefix: ni.hash || nj.hash, else: nj.hash || ni.hash
        let hash' = H(0x01 || r || prefix' || children_hashes)
        let n' = {prefix: prefix', prefix_len: r, hash: hash'}
        let S' = S \ {ni, nj} U {n'} // Merge ni and nj into n' (we call this the parent)
        return MPT'(S')

Finally, we define our top-level function:

    // Precondition: no two ni, nj have identical keys
    def MPT(S = {n1, n2, ..., nk}):
        MPT'(S.map(ToInterior)).

## Proof format

TODO

# Non-normative notes

Note that you can efficiently insert a new entry (k, v) into a tree if you have all the interior nodes that were created in the process of computing MPT':

    let S be the set of all nodes that were ever computed in MPT'
    let m = ToInterior(k, v)
    let n be the element of S that maximizes r = Similarity(n, m)
    // if n was a node with a parent (true whenever S is not a singleton), then we kick out the sibling
    let S' be the subset of S whose prefixes TODO