# WAICT APIs

# Introduction

This document describes a set of APIs for a transparency system for web resources. It enables clients fetching web resources, identified by a URL, to be assured that the received web resource has been publicly logged. It also enables website operators (and others) to enumerate the history of a web resource and observe when it changes.

The primary use case is [WAICT](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k), Web Application Integrity, Consistency and Transparency, which aims to bring stronger transparency and integrity properties to applications delivered over the web in order to support properties like end-to-end encrypted messaging.

# Glossary

* A **Site** is a web-based service that exposes some functionality that people want to use. Examples include Facebook or Proton Mail. **A Site is identified by its origin**, i.e., the triple of scheme, domain, and port. An origin is precisely specified in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html).
* A **Web Resource** is a file identified by a URL whose contents are committed to by a cryptographic hash.
* A **User** is someone that wants to use a Site. We treat a User and their browser as one in the same in this document.
* A **Transparency Service** is a service that a Site registers with to announce that they have enabled transparency and will log web resources to. It maintains a mapping of site to transparency information.
* An **Asset Host** is a content-addressable storage service. One or more are chosen by a site to be responsible for storing the assets logged in the transparency service.
* A **Witness** ensures that a Transparency Service is well-behaved, i.e., only makes updates that are allowed by the specification. It receives a proof of that the transparency service has correctly transitioned the values in its map. On success, the witness signs a representation of the map.

## Notation and Dependencies

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use the TLS presentation syntax from [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) to represent data structures and their canonical serialized format.

We use the base64 encoding algorithms described in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html). Specifically we use the standard "base64" encoding and the URL-safe "base64url" encoding.

We use `||` to denote concatenation of bytestrings. Unless otherwise specified, we use the placeholder text `<digest>` to refer to a base64-encoded SHA-256 digest, prefixed by `sha256-`. This makes the digest a valid SRI [`hash-expression`](https://www.w3.org/TR/sri-2/#grammardef-hash-expression).

We use the Prefix Tree data structure from the [key transparency draft specification](https://www.ietf.org/archive/id/draft-keytrans-mcmillion-protocol-02.html#name-prefix-tree). We also use the `PrefixProof` structure for proofs of inclusion and non-inclusion, as well as the structure's associated verification algorithm.

We use the Signed Note data structure from the [C2SP signed note standard](https://github.com/C2SP/C2SP/blob/main/signed-note.md). We use the term "cosignature" as in the standard, to refer to a signature on a signed note.

We use the JSON Schema langauge from the [JSON Schema standard](https://json-schema.org/draft/2020-12/json-schema-core) to specify the structure of JSON objects. We also use the associated [validation standard](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3) for additional keywords such as `maxLength` or `pattern`.

# Construction Overview

(TODO: fill in)

(TODO: Include rough estimates for Log storage requirements (and witness if required))

# The Transparency Service

The Transparency Service maintains a mapping of domains to resource hashes and asset hosts (and further, the histories of those values). This is encoded as a prefix tree whose keys are domains and whose entries contain:

1. The prefix root that preceded the creation of the entry
1. The hash of the resource
1. The size of the resource history for the domain
1. A commitment to the asset hosts associated with the domain

Concretely, the Transparency Service operator maintains a prefix tree where the keys are domains and values are `ChainNode`, defined as follows:
```
struct {
    uint64 position_in_chain;
    uint64 time_created;
    uint8 resource_hash[32];
    uint8 asset_hosts_hash[32];
} Entry;

struct {
    Entry entry;
    uint8 chain_hash[32];
} ChainNode;
```
An entry whose resource hash is all zeros is called a _tombstone entry_, signifying that the site has unenrolled from transparency. A client receiving a sufficiently recent tombstone entry will not perform any transparency verification.

As sites interact with the transparency service, the prefix tree changes. All adds, updates, and removals are encoded in a growing sequence of `TreeEvent` structs, defined below.
```
struct {
  opaque url<1..511>;
} AssetHost;

/* In an add/update event, the asset hosts can either be changed or unchanged */
enum { changed(0), unchanged(1) } NewAssetHostsTag;
struct {
  NewAssetHostsTag type;
  select (NewAssetHosts.type) {
      case changed: AssetHost<1..2^13-1>;
      case unchanged: opaque[0]; /* empty */
  };
} NewAssetHosts;

struct {
  opaque domain<1..255>;
  NewAssetHosts asset_hosts;
  opaque new_resource_hash[32];
  uint64 timestamp;
} TreeEvent;
```

(TODO: write an algorithm for how to process a list of events. Eg you MUST reject an event for a previously undefined domain that uses `NewAssetHostTag::unchanged`)

Tree events are exposed to witnesses in _batches_. Every time a witness processes a new batch of events, it signs the resulting tree root and sends it to the transparency service.

## Hash Computations

Entries contain hashes of arbitrary _resources_. The transparency never stores resources directly, only their hashes. The _resource hash_ of the resource `r` is defined to be `SHA-256("waict-rh" || r)`.

The `chain_hash` field of an `ChainNode` encodes the history of the entries associated with a given domain excluding the `entry` field that it lies next to. Specifically, let `ec` be the domain's previous `ChainNode`. Then the `chain_hash` field of a new `ChainNode` is computed as `SHA-256("waict-ch" || cn)` (where `cn` is serialized in its TLS representation).

The initial chain hash is 32 bytes of 0x00. So, for example, if `e` is the first entry for a domain, then the first `ChainNode` will have the form `ChainNode{entry: e, chain_hash: [0x00; 32]}`.

The `asset_hosts_hash` encodes the asset hosts where resources can be fetched from. It's computed over the comma-separated list of base64-encoded URLs, with no trailing comma. `asset_hosts_hash = SHA-256("waict-ah" || entry1_b64 || "," || entry2_b64 || "," || ...)`.

## Transparency Service API

We describe the HTTP API that the transparency service MUST expose.

### Append to resource chain

* Endpoint: `/append/<domain>`
* Method: POST
* Body: `application/json` containing a "New Entry Data" object, defined below
* Return value: A `WaictInclusionProof` for the new entry in the new prefix tree
* Authentication: Defined by the transparency service, e.g. a JWT. The transparency service MAY apply further policies or rate limits, e.g. requiring payment per resource logged.

The "New Entry Data" object provides the transparency service with the information it needs to create a new entry in the prefix tree. It has the following schema:
```json
{
  "title": "New Entry Data",
  "type": "object",
  "properties": {
    "resource_hash": {
      "type": "string",
      "maxLength": 45,
      "$comment": "Current resource hash, encoded in base64"
    },
    "asset_hosts": {
      "type": "array",
      "items": {
        "minLength": 1,
        "maxLength": 512,
        "type": "string"
      },
      "maxItems": 16,
      "$comment": "URLs of this site's asset hosts"
    }
  },
  "required": [ "resource_hash" ]
}
```
The return value is an `application/octet-stream` containing an `ChainHeadWithProof`, defined in the [WAICT proofs spec](./waict-proofs.md).

The transparency service creates an entry and appends it to the prefix tree. It requires that an entry for the given domain exists. If not, it returns an 400 error. The steps for appending are as follows. The transparency service:
1. Computes the hash `ah` of the given asset hosts
1. Checks that `resource_hash` is valid base64, and is 32 bytes once decoded and checks that all the elements of `asset_hosts` are valid URLs.
1. Computes the chain hash `ch` of the current `ChainNode`
1. Creates a new `Entry`, `e`, with `time_created` set to the current Unix time in seconds `t`, `resource_hash` set to the decoded given resource hash, `position_in_chain` set to one plus the previous entry's position in the chain, and `asset_hosts_hash` set to `ah`
1. Sets the value of the leaf equal to an `ChainNode`, with `entry` set to `e`, and `chain_hash` set to `ch`.
1. Computes a new prefix root given the new leaf
1. Appends a `TreeEvent` struct to the the sequence of tree events, with `domain` set to the given domain, `new_resource_hash` set to the decoded given resource hash, and `timestamp` set to `t`. If asset hosts are present in the query, then `asset_hosts` is set to have enum type `changed` and containing the given asset hosts. Otherwise, `asset_hosts` is set to have enum type `unchanged`.
1. Waits for cosignatures on the new prefix root or a root that came after it
1. Returns a `ChainHeadWithProof` with `head` set to the latest `ChainNode` associated with `domain` in the newly cosigned prefix tree, `inc_proof` set to the inclusion proof in that tree, and `signed_prefix_root` set to the signed note for the prefix tree root.

Note well: the `ChainNode` that is returned in the inclusion proof MAY be different from the one that was appended to the prefix tree. This happens if the transparency service received multiple `/append` requests for the same domain within the time it takes to receive new cosignatures. In these cases, the returned `ChainNode` is the one that was appended last.

If the given `resource_hash` is the base64 encoding of `[0x00; 32]`, this is interpreted by the transparency service as unenrolling the site.

So as to not trigger spurious connection failures due to timeout, this endpoint SHOULD respond within one minute of receiving a request.

(TODO: this should maybe support arbitrary fast-forward, not just single item appends; note this has to be within reason bc of the linear proof size)

(TODO: should this endpoint accept hashes instead of preimages? Hashes are more efficient, but storing arbitrary user-input data is not great)

### Enrollment via HTTPS

* Endpoint `/enroll/<domain>`
* Method: POST

`domain` is the domain being enrolled. The server MUST reject a domain with characters outside `[a-zA-Z0-9.\-]`.

Calling this endpoint causes the transparency service to make an HTTPS GET query to `https://<domain>/.well-known/waict-enroll` (TODO: register with IANA).

The enrolling site will return a response containing all the information the transparency service needs to create a new `ChainNode`. Concretely, the site responds with a "New Entry Data" object, as defined above, with MIME type `application/json`.

After the transparency service makes the GET request, it updates the entry if it exists, or creates a new one. Specifically:
1. If an entry for the given domain does not exist, it:
    1. Computes the hash `ah` of the given asset hosts
    1. Creates a new `Entry`, `e`, with `time_created` set to the current Unix time in seconds `t`, `resource_hash` set to the decoded given resource hash, `position_in_chain` set to 0, and `asset_hosts_hash` set to `ah`
    1. Creates a new `ChainNode`, with `entry` set to `e`, and `chain_hash` set to the initial chain hash of `[0x00; 32]`.
    1. Appends a `TreeEvent` struct to the the sequence of tree events, with `domain` set to the given domain, `asset_hosts` set to have enum type `changed` and containing the given asset hosts, `new_resource_hash` set to the decoded given resource hash, and `timestamp` set to `t`.
1. Else, if an entry for the given domain does exist, it follows the steps of `/append/<domain>`.

If the given `resource_hash` is the base64 encoding of `[0x00; 32]`, this is interpreted by the transparency service as unenrolling the site.

So as to not trigger spurious connection failures due to timeout, this endpoint SHOULD respond within one minute of receiving a request.

(TODO: if a user enrolls for the firs time using an all-zeros resource hash, should this be interpreted as unenrolling? Kinda odd)

### Get Leaf

* Endpoint: `/leaf/<domain>`
* Method: GET
* Return: An `application/octet-stream` containing an `ChainHeadWithProof` for the given domain in the prefix tree

### Get Entries Tile

* Endpoint: `/entries-tile/<domain>/<N>[.p/<W>]`
* Method: GET
* Response: An `application/octet-stream` containing up to 256 concatenated `Entry`s belonging to the given domain, consecutive by `position_in_chain`, starting at `position_in_chain == N * 256`

`<N>` is the index of the _tile_ where each tile is 256 consecutive entries in the history of the site. `N` MUST be an integer in the range [0, 2²⁴), encoded into 3-digit path elements. All but the last path element MUST begin with an x. For example, index 1234067 will be encoded as `x001/x234/067`. The `.p/<W>` suffix is only present for partial tiles, defined below. `<W>` is the width of the tile, a decimal ASCII integer in the range [1, 256), with no leading zeroes.

The transparency service MUST store a tile of an enrolled site for at least one year beyond the youngest entry in the tile, by `time_created`. If the tile is partial, then the transparency service MUST NOT delete it until the site unenrolled.

A transparency service MAY unenroll a site after a year of no successful `/append` calls.

### Get Chain Hash

* Endpoint: `/chain-hash/<domain>/<N>`
* Method: GET
* Returns: An `application/octet-stream` containing the chain hash that occurs after the `N`-th entry in the chain.

`<N>` is formatted as above. `<N>` MUST be in the range [0, 2³²).

The transparency service MUST store a chain hash of an enrolled domain for at least one year.

### Get Asset Hosts

* Endpoint: `/asset-hosts/<digest>`
* Method: GET
* Returns: An `application/octet-stream` containing the comma-separated list of base64-encoded URLs corresponding to the `hash`.

`<digest>` is a `asset_hosts_hash` (string-formatted same as all digests) inside some `Entry` hosted by the transparency service. Every such value MUST be served at this endpoint.

This endpoint is similar in function to the [issuers](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#issuers) endpoint used in Static CT. Sites are not expected to change their asset hosts frequently, but must be free to do so as-needed.

### Get Batched Tree Events

* Endpoint: `/tree-event-batch/<N>`
* Method: GET
* Returns: An `application/octet-stream` containing the `N`-th (0-indexed) chronological `TreeEventBatch`.

`<N>` is formatted as above. `<N>` MUST be in the range [0, 2⁶⁴).

As the transparency service's event sequence grows, the service will periodically select a tail (starting at the first unpublished event), and package it into a batch. Before publishing the batch, the transparency service MAY arbitrarily transform it, so long as it does not affect the resulting tree. More precisely, for a given sequence of batches `batch_0, ..., batch_k`, and a new batch `b`, the transparency service MAY publish any batch `b'` so long as the following trees are equal:
1. The tree resulting from processing `batch_0, ..., batch_k, b`, in order
1. The tree resulting from processing `batch_0, ..., batch_k, b'`, in order

Endpoints under `/tree-event-batch` are immutable. That is, once a 2xx response code has been returned for a particular `N`, all future response bodies at that endpoint MUST be the same as the first's.

Since this endpoint can produce large responses, a transparency service MAY require additional GET parameters or headers for authorization purposes.

The definition of `TreeEventBatch` is below:
```
struct {
  uint16 num_events;
  TreeEvent events<1..2^24-1>;
} TreeEventBatch;
```
In any returned `TreeEventBatch`, the `num_events` field MUST be set to the number of events included in the batch.

### Upload cosignature

* Endpoint: `/upload-cosignature/<N>`
* Method: POST
* Body: An `application/octet-stream` containing signature(s) on the tree resulting from processing all batches in the range `[0, N)`, in order.

(TODO: make sure there's a notion of the root of the empty tree, so witnesses can sign that)

The body MUST be a sequence of one or more Signed Note signature lines, each starting with the `—` character (U+2014) and ending with a newline character (U+000A). The signature type MUST be `0x06` (TODO: request this codepoint from C2SP). This signature type is identical to the [cosignature-v1 signature type](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md) except for the signature text and signature type identifier.

The key ID is computed as
```
SHA-256(<name> || "\n" || 0x06 || 32-byte Ed25519 cosigner public key)[:4]
```
where `<name>` is the key name from the signature line.

The signed note text is
```
waict-cosignature/v1
time <time>
<tdomain>/prefix-tree
<N>
<root>
```
where

* `<time>` is the timestamp of the signature, in seconds since the epoch, encoded in ASCII decimal with no leading zeroes
* `<tdomain>` is the domain of the transparency service
* `<N>` is encoded in ASCII decimal with no leading zeroes
* `<root>` is the base64-encoded root of the transparency service's prefix tree after processing batches `[0, N)` in order, and the last line ends with a newline (U+000A).

Note `<time>` MUST match the timestamp encoded in the signature line.

The signature MUST be of the form
```
struct {
    u64 timestamp;
    u8 signature[64];
} TimestampedSignature;
```
where `timestamp` is the same as the timestamp in the signed note text.

# Asset Host API

The asset host only need to be able to return a file given its hash.

## Get Asset

* Endpoint `/fetch/<digest>`
* Method: GET
* Response: An `octet-stream` containing the resource whose string-formatted SHA-256 hash is `<digest>`

These endpoints are immutable, so asset hosts SHOULD have long caching times.

# Client Behavior

A client's only job is to verify inclusion proofs. This is covered in the [WAICT proofs spec](waict-proofs.md). Of course, strong security guarantees only come when the client enforces the validity of these inclusion proofs, which means the client must know when the proofs are necessary and unnecessary (i.e., when transparency is enabled). This question of _signalling_ is covered in the [WAICT signalling spec](waict-signalling.md).

# Appendix

We describe possible uses of this transparency protocol which are not considered part of the standard.

## Extensions

Sites may wish to have associated metadata that is subject to certain update rules. We call these **extensions**.

As an example, a site may wish to support Sigstore-based code signing, and have developer OpenID identifiers as extensions. A cooldown period on this extension would guarantee that, if a site changes developer IDs, it must wait, e.g., 24 hours for the change to go into effect. Further, since the manifest extensions are themselves transparent, a site can use a simple script to monitor for extension changes and notify the maintainer if an unexpected change happens.

To define a cooldown mechanism for a site extension, the site maintainer needs to make two updates every time it updates an extension called, say, `foobar`:

1. It updates the extension `foobar` with the value that it desires (to delete, the value should be set to the empty string, essentially as a tombstone). It receives the inclusion proof of the manifest in the new prefix tree.
1. It updates the extension `foobar-inclusion` with the inclusion proof above.

Now any client can enforce the cooldown property by simply verifying `foobar-inclusion` and checking how old its timestamp is. If it verifies and the timestamp is sufficiently old, then it uses the value in `foobar`. Otherwise, it errors and uses whatever valid stored value it has.

(TODO: the details above aren't worked out. Where are these extensions stored? How do you check an old inclusion proof without providing the entire old manifest + extensions?)

### Preload Lists for Extensions

Clients still have to know to expect the extension, otherwise a site can just delete the extension without cooldown. So any extension ecosystem will have to maintain its own preload list. If a site wants to disable the extension, they request removal from the preload list. Until then, they serve tombstone values.

Another option is to have extensions piggyback on the transparency preload list. This requires one modification: rather than being a list, we say browser vendors maintain a **transparency preload dictionary**, mapping domains to hashes.

In this setup, the browser vendor maintains the signup form as before, but also exposes an input form, where site owners can write the extensions they wish to commit to to all users. The
vendor hashes this list and sets this to the site's value in the transparency preload dictionary. When a user navigates to a site in the preload dictionary, the user retrieves the hash, and expects the site to reveal the extension list it committed to.
