# Merkle Patricia Tree spec

We define the root hash MPT over a set `S` of key-value pairs `(k, v) ∈ 𝔹²` where `𝔹 = {0,1}²⁵⁶`.  We say `b[..i]` is the subarray containing all bits from index 0 up to and not including index `i`. We use `||` to mean concatenation. We define `H` be the SHA256 hash function. We represent elements of 𝔹 as byte arrays where we say the 0-th bit of `a: [u8; 32]` is the most significant bit of `a[0]`, and so on. When `a` and `b` are bit strings, we say `a < b` using the lexicographic ordering. Note this corresponds to the ordering on byte strings, where each byte starting at the 0-th is compared as an integer until an inequality is found, with the shorter input being declared less if no inequality is found.

In this spec, we will specify how to compute the root of a Merkle-Patricia Tree, as well as inclusion proofs of elements. The proofs and hashes are intentionally made compatible with Russ Cox's [MPT] design.

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
            hash: H(k || v)
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

    // Precondition: no two ni, nj have identical prefixes
    def MPT'(S = {n1, n2, ..., nk}):
        find indices i ≠ j that maximizes r = Similarity(ni, nj) (note this is not nec unique)
        let prefix' = ni.prefix[..r] || 0...0  // pad to 256 bits
        let children_hashes = if ni.prefix < nj.prefix: ni.hash || nj.hash, else: nj.hash || ni.hash
        let hash' = H(children_hashes || r)
        let n' = {prefix: prefix', prefix_len: r, hash: hash'}
        let S' = S \ {ni, nj} U {n'} // Merge ni and nj into n'
        return MPT'(S')

Finally, we define our top-level function:

    // Precondition: no two ni, nj have identical keys
    def MPT(S = {n1, n2, ..., nk}):
        MPT'(S.map(ToInterior)).

## Inclusion proof

We define the inclusion proof of the `k`-th element in a list `L` of interior nodes as follows:

    def ProveInclusion'(k, []):
        raise Error("Cannot prove inclusion in an empty list")

    def ProveInclusion'(1, [n1]):
        return ""

    // Precondition: 1 ≤ k ≤ N
    // Precondition: no two ni, nj have identical prefixes
    def ProveInclusion'(k, L = [n1, n2, ..., nN]):
        find indices i < j that maximizes r = Similarity(ni, nj) (note this is not nec unique)

        // Merge ni and nj into n', just like in MPT'
        let prefix' = ni.prefix[..r] || 0...0  // pad to 256 bits
        let children_hashes = if ni.prefix < nj.prefix: ni.hash || nj.hash, else: nj.hash || ni.hash
        let hash' = H(children_hashes || r)
        let n' = {prefix: prefix', prefix_len: r, hash: hash'}
        let L' equal L with the i-th element set to n' and the j-th element removed

        // If our target index is being merged, its new sibling is now part of the proof
        let proof_segment = if i == k || j == k:
                let h = if i == k: j, else: i // h is the sibling index
                r || nh.hash
            else: ""

        // Similarly, compute the new target index
        let k' = if i == k || j == k:
                i // We merged ni and nj into n' at index i
            else if k < j:
                k
            else:
                k - 1

        // Recurse
        return proof_segment || ProveInclusion'(k', L')

Finally we define the top-level function that is given an index and a list of key-value pairs:

    // Precondition: 1 ≤ k ≤ len(L)
    def ProveInclusion(k, L):
        let (_, val) = L[k]
        return "mptproof" || 0x01 || val || ProveInclusion'(k, L.map(ToInterior))

We define the verification algorithm for the proof `proof` that the key-value pair `k,v` appear in the tree with root hash `root`. This function returns true when the proof is valid, returns false when invalid, and raises a `Malformed` error when the proof is malformed.

```
def VerifyInclusion'(root, node, proof, lastR):
    if proof.len() == 0: # End of proof
        return root == node.hash
    if proof.len() < 33:
        raise Malformed
        
    let r = proof[0]
    let sibling = proof[1..33]
    if r >= lastR: # Prefix len must be strictly decreasing
        raise Malformed

    let prefix' = node.prefix[..r] || 0...0  // pad to 256 bits
    let children_hashes = if node.prefix[r] == 0:
        node.hash || sibling
      else:
        sibling || node.hash
    let hash' = H(children_hashes || r)
    let node' = {prefix: prefix', prefix_len: r, hash: hash'}

    return VerifyInclusion'(root, node', proof[33..], r)

def VerifyInclusion(root, k, v, proof):
    if proof[..9] != ("mptproof" || 0x01):
        raise Malformed;
    if proof[9..9+32] != v:
        return false
        
    let proof' = proof[9+32..]
    let node = ToInterior(k, v)
    return VerifyInclusion'(root, node, proof', 256)
```

TODO: Specify non-inclusion proofs. Make sure to handle the empty tree case.  

# Known-answer tests

Known-answer tests can be found in `merkle-patricia-tree-tests/`. There are two test files in there.

## Root computation tests

The file `mpt_root_kats.jsonl` has a JSON object on each line. Each object has the following keys:
* `label` — Represents the name of this test vector
* `root` — A base64-encoded length-32 bytestring
* `leaves` — A list containing any number of objects containing `key` and `value`, both base64-encoded length-32 bytestrings

Each test vector has the property that `MPT(leaves) = root`

## Inclusion tests

The file `mpt_inclusion_kats.jsonl` has a JSON object on each line. Each object has the following keys:
* `label` — Represents the name of this test vector
* `root` — A base64-encoded length-32 bytestring
* `proof` — A base64-encoded length-32 bytestring
* `target_index` — An integer in the range `[0, len(leaves))`
* `leaves` — A list containing any number of objects containing `key` and `value`, both base64-encoded length-32 bytestrings

Each test vector has the property that `Inclusion(leaves) = proof` and `MPT(leaves) = root`.

# Non-normative notes

## Memory-Efficient Root Computation

Russ Cox's [MPT] construction defines the `MPT` function using an imperative algorithm. This algorithm has far better asymptotics than the `MPT` algorithm defined above—O(KN³) versus O(KN), where K is a hash comparison:
```
func mpt(list) -> (hash)
	s = {}
	for each k, v in list
		s = reduce(push(s, leaf(k, v)))
	return stackhash(s)

func leaf(k, v) -> (node)
	return {key: k, bits: 256, hash: SHA256(k || v)}

func reduce(s) -> (stack)
	while len(s) >= 3 and overlap(s[-3], s[-2]) > overlap(s[-2], s[-1])
		s = push(s[:-3], merge(s[-3], s[-2]), s[-1])
	return s

func stackhash(s) -> (hash)
	if len(s) == 0
		return SHA256()
	while len(s) >= 2
		s = push(s[:-2], merge(s[-2], s[-1]))
	return s[-1].hash

func overlap(x, y) -> (bool)
	return number of bits in shared prefix of x and y (at most min(x.bits, y.bits))

func merge(x, y) -> (node)
	b = overlap(x, y)
	return {key: x.key, bits: b, hash: SHA256(x.hash || y.hash || b)}
```

[MPT]: https://github.com/rsc/tmp/blob/b6bdb3d0c98a466099207da2af224c10f20544bf/mpt/DESIGN.md
