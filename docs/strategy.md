# Strategy

The completeness matrix is [../ROADMAP.md](../ROADMAP.md). This document is *why* the rows
are ordered the way they are, and the rules that order has to respect.

## The constitution

1. **The core is the specification implementation.** `pkix/` holds codecs, state machines
   and the vocabulary of pkix. New core code appears when a document defines the
   behaviour, or when an ordering rule with no document earns an explicit convention label.
2. **Sans-IO before sockets.** Anything decidable from data plus a clock is implemented
   without touching a socket, so every timeout, retry and rollover is testable without
   sleeping or networking.
3. **Dependency-free by default.** An exception needs a sentence in README.md explaining why
   the rule was broken, and a floor with no ceiling.
4. **Positioning is correctness and legibility, not throughput.** The incumbents in this
   corner are usually stale, untyped, or welded to a product. This is the implementation that
   says how it knows what it claims.
5. **Every answer carries its provenance.** Verified or cached, which document, refused or
   believed. An answer without provenance is a guess with a confident type.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `pkix/` | codecs, state machines, policy objects | RFC-cited or convention-labelled |
| Apps | `pkix/apps/` | reusable assemblies that compose core | no new protocol surface |
| Examples | `examples/` | one runnable script per use case | configures; never restates logic |

## Dependencies, and who owns the bytes

Two documents govern this and they were in conflict until 2026-11-07. `docs/plan.md` gives the
reason asn1core is a dependency at all — the signature is checked over the DER encoding of the
TBSCertificate, "so validation cannot be written above a codec that re-encodes what it parsed" —
while the code reached for `cryptography.x509` instead. `cryptography` parses certificates and then
emits its own re-encoding of them, so a validator built on it cannot name the bytes §4.1.1.3 says
were signed. The position now:

| Concern | Owner | Why there |
|---|---|---|
| DER, the certificate/extension structures, distinguished names and §7.1 comparison | `asn1core` | it keeps every field as a slice of the document that arrived |
| what a name match, a constraint or a policy means | `pkix` | this project's whole reason to exist |
| big-integer arithmetic and digests | the standard library | `pow(m, e, n)` and `hashlib`, neither of which is ours to rewrite |
| the verification equations and paddings | `pkix`, as of the M2 row | see "verify-only" below |
| a second opinion on all of it | `cryptography`, dev-only | differential testing against a different implementation |

**The section number was wrong in the plan.** `docs/plan.md` cited RFC 5280 §4.1.3.2, and §4.1 ends
at §4.1.2.9; no §4.1.3.2 exists. The clause is §4.1.1.3: "The signatureValue field contains a
digital signature computed upon the ASN.1 DER encoded tbsCertificate. The ASN.1 DER encoded
tbsCertificate is used as the input to the signature function." The number lived in the generator
(`sdk-forge/forge_data/position.py`), so it is fixed there and regenerated rather than patched here;
pkix was the only project rendering that sentence, and a scan of every `docs/plan.md` in the
workspace found no other copy.

### Verify-only, which is why the earlier objection does not apply

This file and `README.md` previously held that writing RSA or ECDSA would turn pkix into "a timing
side channel project". That objection is sound about *private-key* operations — RSA-CSP with
blinding, or a DSA/ECDSA nonce that leaks a key when it repeats — and it does not carry over to
verification, which is what pkix does and the only thing it will ever do here. Every input to a
verification is public: RSA uses the public exponent, ECDSA's `u1`/`u2` are derived from the
signature and the digest, and Ed25519 checks `sB = R + uA` with all four values in the clear. There
is no secret scalar in the code path to leak, and a test enforces that no private-key operation
exists to begin with. Signing stays a non-goal.

What remains is the risk that actually breaks path validators: **accepting something that should be
rejected** — a signature malleated to `n - s`, `r` or `s` of zero, a point not on the curve, an
`AlgorithmIdentifier` whose parameters are NULL in one place and absent in the other, a PKCS#1 v1.5
`DigestInfo` matched by prefix rather than byte-for-byte so a truncated hash slips through, a PSS
salt length or trailer field nobody checked. Verification-only gets an oracle for that for free:
every certificate in the recorded corpus was signed by some *other* implementation, so the corpus is
known-answer data for "accept", and vectors built by mutating those signatures are known-answer data
for "reject". A verifier that agrees with itself proves nothing; a verifier that agrees with what
the world issued proves a great deal. Worth remembering that the reference text is not immune
either — RFC 8032 §6's illustrative `verify()` carried a verified technical erratum (eid 5930,
reported by Daniel Bleichenbacher) because its signature-length check was missing a `raise` and so
tested nothing.

### The commit-ordering rule

`pyproject.toml` keeps `cryptography` as a runtime dependency until the last import of it is gone
from `pkix/`, and `dependencies` becomes empty in that same commit. Declaring the destination
before the code arrives would make the metadata describe a project that does not exist, which is
the failure this file exists to prevent. Until then `README.md` says so plainly rather than
describing the plan as the state.

### What could not be cited, and is therefore a decision rather than a requirement

No reachable source in this environment carries SEC1 (SECG v2.0) §2.3.3, X9.62, or FIPS 186-3 /
SP 800-56A, so the point-validation and small-subgroup procedures that RFC 5480 §4 gestures at in
lower case cannot be quoted as MUSTs; RFC 9560 turned out to be RDAP-over-OIDC, not a post-quantum
certificate profile (ML-DSA is RFC 9881, SLH-DSA is RFC 9909). Where the record is silent, pkix
decides and says so in the row — the default is refusal, consistent with the no-silent-stubs
invariant. See "Open questions" in `ROADMAP.md`.

One engine, three drives, never parallel implementations:

- **await** -- the native asyncio surface.
- **blocking** -- a facade owning a private loop, so a call from inside a caller's running
  loop works instead of deadlocking.
- **callback** -- plain callables, no third-party promise type.

## Naming

One string everywhere: the distribution, the import and the console script. A name that
means one thing in the installer, in `import` and on `PATH` is the only arrangement that
cannot surprise anyone, and it is also why this project does not sit one edit away from a
project that already exists.
