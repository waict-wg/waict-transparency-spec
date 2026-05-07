# WAICT Proofs and Algorithms

# Introduction

This document defines the data structures and algorithms for the proofs used in the WAICT transparency specification.

# Notation and Dependencies

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use the TLS presentation syntax from [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) to represent data structures and their canonical serialized format.

We use the Prefix Tree data structure from the [key transparency draft specification](https://www.ietf.org/archive/id/draft-keytrans-mcmillion-protocol-02.html#name-prefix-tree). We also use the `PrefixProof` structure for proofs of inclusion and non-inclusion, as well as the structure's associated verification algorithm.

We use the Signed Note data structure from the [C2SP signed note standard](https://github.com/C2SP/C2SP/blob/main/signed-note.md). We use the term "cosignature" as in the standard, to refer to a signature on a signed note.

# Inclusion Proofs

A full inclusion proof in a transparency service's tree is of the form:
```
struct {
  ChainNode head;
  uint8 inc_proof<1..2^14-1>;
  uint8 signed_prefix_root<1..2^24-1>;
} ChainHeadWithProof;
```
where `signed_prefix_root` is a Signed Note as described in `/upload-cosignature` endpoint in [`waict-apis.md`].

To verify a `ChainHeadWithProof` with respect to a leaf key, the verifier:

1. Parses `signed_prefix_root` and extracts the root hash.
1. Verifies `entry.entry.resource_hash` equals the expected resource hash.
1. Verifies `inc_proof` with respect to `entry` (serialized), the given leaf key, and the parsed prefix root.
1. Checks that the domain in the first line in `signed_prefix_root` (everything before the first `/`) matches the domain of a transparency service. The client MAY choose the set of transparency services that it trusts for this verification step.
1. Verifies the cosignatures on `signed_prefix_root`. The client MAY choose the set of public keys that it trusts for this verification step.

# Presenting inclusion proofs

We must define a way for the client to get the proof that that a manifest appears in the transparency log.

Suppose a server is enrolled in transparency and serves a manifest with identifier `X` as a source in `Integrity-Policy` or `Integrity-Policy-Report-Only`. The server MUST expose an HTTP GET endpoint `/.well-known/waict/v1/inclusion/<X>`  (recall, identifiers are a nonempty sequence of URL-unreserved characters) that returns an `application/octet-stream` containing a `ChainHeadWithProof` for the manifest.
