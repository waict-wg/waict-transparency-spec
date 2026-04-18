# Merkle Patricia Tree spec

We define the root hash MPT over a set `S` of key-value pairs `(k, v) ∈ 𝔹²` where `𝔹 = {0,1}²⁵⁶`.  We say `b[..i]` is the subarray containing all bits from index 0 up to and not including index `i`. We use `||` to mean concatenation. We define `H` be the SHA256 hash function. We represent elements of 𝔹 as byte arrays where we say the 0-th bit of `a: [u8; 32]` is the least significant bit of `a[0]`, and so on.

## Creating interior nodes

We define interior nodes as having the structure

    struct InteriorNode {
        prefix: 𝔹,
        prefix_len: u16,
        hash: 𝔹,
    }

For our algorithm, we must map key-value pairs to interior nodes:

    def ToInterior(k, v):
        return InteriorNode {
            prefix: k,
            prefix_len: 256,
            hash: H(0x00 || k || v)
        }

We will also need a utility function that measure the "similarity" of two interior nodes. Similarity is defined as the number of leading binary digits the prefixes have in common:

    // Lexicographic similarity between two prefixes.
    // Precondition: n and m do not have identical prefixes of length-256
    def Similarity(n: InteriorNode, m: InteriorNode) -> u8:
        let l = min(n.prefix_len, m.prefix_len)
        assert l != 256 or n.prefix != m.prefix
        return (n.prefix[..l] ^ m.prefix[..l]).leading_zeros() as u8

Note our precondition permits us to make the final cast to `u8`. We ensure in later algorithms that this precondition is enforced.

## Defining the root hash

We define our helper function `MPT'` over a set of interior nodes as follows:

    def MPT'({}): return H("")

    def MPT'({n}): return n.hash

    // Precondition: no two ni, nj have identical prefixes of length-256
    def MPT'(S = {n1, n2, ..., nk}):
        find indices i ≠ j that maximizes r = Similarity(ni, nj) (note this is not nec unique)
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

## Inclusion proof

We define the inclusion proof of the `k`-th element in a list `L` of interior nodes as follows:

    def Inclusion'(k, []):
        raise Error("Cannot prove inclusion in an empty list")

    def Inclusion'(1, [n1]):
        return ""

    // Precondition: 1 ≤ k ≤ N
    // Precondition: no two ni, nj have identical prefixes of length-256
    def Inclusion'(k, L = [n1, n2, ..., nN]):
        find indices i < j that maximizes r = Similarity(ni, nj) (note this is not nec unique)

        // Merge ni and nj into n', just like in MPT'
        let prefix' = ni.prefix[..r] || 0...0  // pad to 256 bits
        let children_hashes = if ni.prefix ≤ nj.prefix: ni.hash || nj.hash, else: nj.hash || ni.hash
        let hash' = H(0x01 || r || prefix' || children_hashes)
        let n' = {prefix: prefix', prefix_len: r, hash: hash'}
        let L' equal L with the i-th element set to n' and the j-th element removed

        // If our target index is being merged, its new sibling is now part of the proof
        let proof_segment = if i == k || j == k:
                let h = if i == k: j, else: i // h is the sibling index
                let is_left = nk.prefix ≤ nh.prefix
                (is_left as u8) || r || nh.hash
            else: ""

        // Similarly, compute the new target index
        let k' = if i == k || j == k:
                i // We merged ni and nj into n' at index i
            else if k < j:
                k
            else:
                k - 1

        // Recurse
        return proof_segment || Inclusion'(k', L')

Finally we define the top-level function that is given an index and a list of key-value pairs:

    // Precondition: 1 ≤ i ≤ len(L)
    def Inclusion(k, L):
        return Inclusion'(i, L.map(ToInterior))

# Non-normative notes

Note that you can efficiently insert a new entry `(k, v)` into a tree if you have all the interior nodes that were created in the process of computing `MPT'`:

    let S be the set of all nodes that were ever computed in MPT'
    let m = ToInterior(k, v)
    let n be the element of S that maximizes r = Similarity(n, m)
    // if n was a node with a parent (true whenever S is not a singleton), then we kick out the sibling
    let S' be the subset of S whose prefixes ... TODO