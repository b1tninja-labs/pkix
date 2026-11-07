# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation pkix could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `anchors.load_anchor()` | RFC 5280 sec. 6.1 | `[ok]` | `tests/test_obligations.py::test_a_trust_anchor_carries_the_name_and_key_that_sec_611_requires` | M1 |
| `chain.candidates()` | RFC 5280 sec. 6.1 | `[ ]` | `tests/test_obligations.py::candidates` | M1 |
| `validity.check_signature()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::check_signature` | M2 |
| `validity.check_validity()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::check_validity` | M2 |
| `names.constraint_holds()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::constraint_holds` | M3 |
| `policy.resolve()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::resolve` | M4 |
| `revocation.status_of()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::status_of` | M5 |
| `result.validate()` | RFC 5280 sec. 6 | `[ ]` | `tests/test_obligations.py::validate` | M6 |
| `store.remember()` | design | `[ ]` | `tests/test_obligations.py::remember` | - |
| `cab.member()` | MS-CAB (vendor format, not an RFC) | `[ ]` | `tests/test_obligations.py::cab_member` | M7 |
| `ctl.root_program()` | MS-CTL (vendor format, not an RFC) | `[ ]` | `tests/test_obligations.py::ctl_root_program` | M7 |
| `ctl.signed_by_microsoft()` | MS-CTL Authenticode | `[ ]` | `tests/test_obligations.py::ctl_signed_by_microsoft` | M7 |

The Milestone column places each row on the ladder in section 2, using that ladder's own wording. Two placements are a reading and not a quotation: `result.validate()` sits at M6 because the conformance trace exercises the whole-path entry point, and `store.remember()` is a design row the ladder does not place, so it carries `-`.

### Why the CTL rows belong here and not in `trustatlas`

`trustatlas` collects the published trust programs of several vendors and joins them by hash. For
Mozilla and curl that needs no parsing at all — `certdata.txt` is text, `cacert.pem` is PEM — and its
rule is that it interprets nothing. Microsoft publishes its program as a CAB containing one member,
`authroot.stl`, whose records are trust blobs in a vendor binary format; the only published form
reachable from a Linux container is served over **plain HTTP**, so the signature inside the CTL is the
sole integrity protection it has. Decoding it is protocol logic with a silent failure mode — a wrong
record boundary yields a plausible list of thumbprints, which is the exact shape of error that makes a
trust map wrong rather than merely incomplete. A second, laxer parser in the collector directory is
the failure this file's honesty rule exists to prevent, so the obligation lives here.

Pinned bytes the implementation will be tested against, from `trustatlas`'s sweep of 2026-11-07
(`tools/collect_ctl.py`; the container re-fetched and reproduced both hashes):

- `authrootstl.cab` — 80,353 octets, `sha256 c0aa761fb7d8d1e4449a8990…`, `application/vnd.ms-cab-compressed`
- `disallowedcertstl.cab` — 5,652 octets, `sha256 1f2719b100fcc59601f0dbb2…`, the blocklist

`cab.member()` is the first slice and is independently testable: a CAB's CFHEADER, CFFOLDER and CFFILE
records name its member and its uncompressed size, and the folder's compression field says whether the
member must be inflated before anything downstream can read it. `ctl.root_program()` depends on that
answer, and `ctl.signed_by_microsoft()` is what turns "bytes as delivered over HTTP" into a claim about
the program rather than about the network path.

### M7 is blocked on a document, and the block is recorded so it is not guessed around

Milestone M7 was not implemented on 2026-11-07 because the normative text could not be reached, and
every field of a CAB or a CTL would otherwise have come from a model's recollection. That is the exact
failure this project's rules exist to prevent, and it has form in this repository's neighbour: a tile
parser written against an assumed TranscriptItem prefix returned `0x00` where `0x06` was expected, and
a trust count compared against `CKT_NSS_TRUSTED_CONNECT_PEER`, a constant that does not exist. Both
looked like clean results.

What was tried, all on 2026-11-07, so the next attempt starts here rather than re-running the dead ends:

| Source attempted | Result |
|---|---|
| `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cab/` | **HTTP 404** |
| `https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CAB.pdf` | **HTTP 409** |
| the same blob for `MS-CTL.pdf`, `MS-WINCAB.pdf` | **HTTP 409** |
| web search for the CFHEADER/CFFOLDER pages | CAPTCHA, no results |
| Wikipedia's cabinet article | **no byte-level field tables at all**, and flagged as containing original research |

Two negative observations from poking the pinned CABs directly, recorded as *where it hurt*, not as
format knowledge: the CFHEADER and CFFOLDER records at the offsets tried parsed consistently with the
member name and sizes visible in the raw bytes, and **iteration of CFFILE records failed twice** on the
variable-length name field. That is the field whose exact terminator and padding rule must come from the
document, because a one-byte error there produces a file list that looks entirely plausible. No field
layout, offset, or padding rule is asserted anywhere in this file.

**Exit rule for M7, therefore:** it is implemented against a retrieved copy of the specification, with
the document's title and revision recorded in the commit that lands the code. A row may not move from
`[ ]` on the strength of a parser that agrees with itself; it moves when the pinned
`authrootstl.cab` and `disallowedcertstl.cab` fixtures parse into entries a named test asserts on, and
when `signed_by_microsoft()` has checked the signature — without which the whole exercise describes an
HTTP response rather than the Windows program.



## 2. Milestones

- M1 anchors and chain discovery with a fixture set of real chains
- M2 section 6.2 validity: signature, dates, issuer matching, critical extensions
- M3 name constraints including excluded subtrees and the issuance-time exception
- M4 policy mapping, constraints and anyPolicy
- M5 revocation interface plus CRL and OCSP backed implementations and cross-checks against openssl verify
- M6 publication: 0.1.0 with the conformance trace against NIST and vendor path test suites
- M7 vendor program containers: CAB member extraction, then the CTL record and Authenticode rows above,
  accepted by the pinned `authrootstl.cab` and `disallowedcertstl.cab` fixtures. `trustatlas` cannot say
  what the Windows program trusts until this lands; today it can only pin the bytes it was given.

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 5280 carries 6 verified errata and is updated by RFC 6818, RFC 8398, RFC 8399, RFC 9549, RFC 9598, RFC 9608, RFC 9618, RFC 9925 and RFC 10007. The updates are not editorial: internationalised names and notBefore bounds changed the answer.
- RFC 5912 carries 8 verified errata.
- RFC 6960 carries 6 verified errata.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a certificate parser: accept DER or a cryptography object and refuse anything else | `[no]` | a named document requires it |
| crypto primitives of any kind | `[no]` | a named document requires it |
| ACME, CMP or any issuance protocol: enrollkit asks pkix whether the result is acceptable | `[no]` | a named document requires it |
| the CA/Browser Forum baseline requirements, which are a policy profile built on top, not this algorithm | `[no]` | a named document requires it |

## 5. Open questions

- none recorded yet

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

## Board projection

`py sdk-forge/sync_roadmap.py --project pkix --check` projects §1 onto GitHub issues, collected on Project
V2 **#2 "Protocol SDK portfolio"**. Read through the hosted GitHub MCP server on 2026-11-07: **12 items**, all
open, all `status:unimplemented`. The matrix holds 16 rows: 12 `[ ]` filed, 4 `[no]` in §4 deliberately not
filed, because a non-goal is a decision and not a piece of work.

A dated snapshot, not a live count. The board is the live view and this file is the source of truth: a board
cannot refuse a row that claims `[ok]` without a test, and `tests/test_roadmap_rows.py` can.
