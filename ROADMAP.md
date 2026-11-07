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
| `chain.candidates()` | RFC 5280 sec. 6.1.1(a), 6.1.3(a)(4), 7.1, 4.2.1.9 | `[ok]` | `tests/test_chain_candidates.py::test_the_served_chain_is_one_candidate_path` | M1 |
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

Re-attempted 2026-11-11, four sources the table above did not try. Still unreachable, and the
shape of the failure is now clearer than it was:

| Source attempted | Result |
|---|---|
| `https://interoperability.blob.core.windows.net/files/MS-CAB/[MS-CAB].pdf` (and MS-CTL) | **DNS does not resolve** from this environment; the host is outside the egress allow-list |
| `https://web.archive.org/cdx/search/cdx?url=learn.microsoft.com/...ms-cab*` | **HTTP 503**, so no archived copy could even be located, let alone fetched |
| `https://learn.microsoft.com/en-us/openspecs/file_formats/ms-cab/` and `.../windows_protocols/ms-ctl/` | **HTTP 404** — and this is the correction to the 2026-11-07 entry: `learn.microsoft.com` itself resolves and answers (a legacy `msdn.microsoft.com` URL returned 200 by redirecting), so the host was never the obstacle. The document is. |
| `https://learn.microsoft.com/api/search?search=CFHEADER cabinet file format` | 30 results, **none of them the specification** — no CFHEADER/CFFOLDER page exists on the site any more |

So the block is not a network policy that a different route would satisfy: Microsoft appears to
have withdrawn the MS-CAB pages from the site that carried them, the PDF archive host is
unreachable from here, and the one place that could hold a superseded copy — the Wayback
Machine — would not answer. **M7 remains blocked, and `cab.member()` stays `[ ]`.**

Two things this section should record about the loop rather than about the network. First,
`sdk-forge/loop.py next` recommended `cab.member()` on 2026-11-11 as the portfolio's next
obligation. Its arithmetic is eligibility over board fields — Active projects, row status,
milestone, dependencies — and it does not read this prose, so a block that exists only as a
paragraph and a native link is invisible to it. Second, that is precisely why the exit rule below
is written as a rule about evidence rather than about effort: the recommendation was followed far
enough to look for the document, and the document is what refused.

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
| a certificate parser of its own: pkix takes DER and refuses anything else, while the codec and the certificate structures belong to `asn1core` | `[no]` | a named document requires pkix to own a codec |
| any private-key operation inside `pkix/`, signing included: where a test needs a certificate signed, the signature comes from `cryptography`, which stays a dev dependency | `[no]` | a named document requires pkix to issue a certificate |
| ACME, CMP or any issuance protocol: enrollkit asks pkix whether the result is acceptable | `[no]` | a named document requires it |
| the CA/Browser Forum baseline requirements, which are a policy profile built on top, not this algorithm | `[no]` | a named document requires it |

**One row left this table on 2026-11-07 and it is recorded here rather than deleted.** "crypto
primitives of any kind" was listed above, with "a named document requires it" as the condition to
revisit. That condition is not met and no one is pretending it is: no document requires pkix to
write its own arithmetic, because RFC 5280 is indifferent to how a signature is checked. The work
became the M2 obligation `validity.check_signature()` by a maintainer decision to carry no runtime
dependency, on the reasoning in [docs/strategy.md](docs/strategy.md) — verification has no secret
input, digests and modular exponentiation are standard library, and a verifier's honest test corpus
is signatures that other implementations produced. The sentence that previously justified the
non-goal ("the one thing this project must not write itself") is corrected in `README.md` in the
same commit, because leaving it standing would make the two documents disagree about the project.

## 5. Open questions

- **`anchors` is the last module importing `cryptography`, and the order of the remaining two
  changes is undecided.** M1 closed on 2026-11-07 (`anchors.load_anchor()` and
  `chain.candidates()`, both pinned, the latter discovering a real four-deep served chain), and
  `chain.py` already works entirely on `asn1core` types. Re-basing `anchors` onto the same model
  removes the parsing role in one move, but `TrustAnchor.verify()` needs *something* to check a
  signature with: either a thin bridge that hands `subject_public_key_info` and `tbs_certificate` to
  `cryptography`'s primitives until M2 lands, or M2 first with no bridge at all. The bridge is
  roughly one function and would be deleted by M2; writing it means testing something twice. Not
  chosen yet, and the choice is recorded here rather than made silently in whichever commit comes
  first.
- **A version 1 certificate carries no basic constraints extension at all**, and RFC 5280 §4.2.1.9
  phrases its prohibition for the case where the extension "is not present in a *version 3*
  certificate". Read closely, that sentence does not reach a v1 issuer, so the text does not say
  whether a v1 CA certificate may serve as a path member. pkix's answer is refusal (fail closed)
  until a reachable source says otherwise; the alternative — treating silence as permission — lets a
  v1 document into a path on a reading nobody verified.
- **Whether a verifier must reject a public key that is not on the curve, or not in the prime-order
  subgroup, is not a quoted MUST here.** RFC 5480 §4 raises it in lower case and attributes the
  choices to SP 800-56A, and SEC1 §2.3.3, X9.62 and FIPS 186-3 are not reachable from this
  environment. The implementation will validate the point and say in the row that the decision is
  pkix's, not the specification's.
- **RSA-PSS salt length when the parameters do not pin it.** RFC 8017 §9.1.2 treats `sLen` as a
  supplied option and RFC 4055 §3.3 only orders the signature and key salt lengths, so accepting
  `emLen - hLen - 2` is undetermined by anything reachable. It will be an explicit option or a
  refusal, not a silent acceptance.
- **MS-CAB and MS-CTL remain unreachable** (M7). The dead ends are tabulated above so the next
  attempt starts past them.

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
