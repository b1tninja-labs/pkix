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
| `anchors.load_anchor()` | RFC 5280 sec. 6.1.1(d); RFC 6818 | `[ok]` | `tests/test_obligations.py::test_a_trust_anchor_carries_the_name_and_key_that_sec_611_requires` | M1 |
| `chain.candidates()` | RFC 5280 sec. 6.1.1(a), 6.1.3(a)(4), 7.1, 4.2.1.9 | `[ok]` | `tests/test_chain_candidates.py::test_the_served_chain_is_one_candidate_path` | M1 |
| `anchors.rebase` | RFC 5280 sec. 6.1.1(d), 4.1.1.3 | `[ok]` | `tests/test_anchors_asn1core.py::test_anchor_carries_stored_spki_and_tbs_slices` | M1 |
| `anchors.no_cryptography` | the owner's dependency rule of 2026-11-12 | `[ok]` | `tests/test_anchors_asn1core.py::test_package_source_never_imports_cryptography` | M2 |
| `anchors.verify` | RFC 5280 sec. 6.1.3(a)(1) | `[ok]` | `tests/test_anchors_asn1core.py::test_anchor_verify_checks_signatures_under_the_anchor_key` | M2 |
| `validity.check_validity()` | RFC 5280 sec. 6.1.3(a)(2), 4.1.2.5 | `[ok]` | `tests/test_validity.py::test_validity_period_boundaries_are_inclusive` | M2 |
| `validity.unsigned_certificate` | RFC 9925 sec. 3.1, 4 | `[ok]` | `tests/test_signatures.py::test_an_unsigned_certificate_is_refused_as_a_path_signature` | M2 |
| `algorithms.oid_table` | RFC 3279 sec. 2.2; RFC 4055 sec. 5; RFC 5758 sec. 3.2; RFC 8017 erratum 5154 | `[ok]` | `tests/test_signatures.py::test_every_signature_oid_maps_to_the_hash_its_document_names` | M2 |
| `validity.check_signature()` | RFC 5280 sec. 6.1.3(a)(1), 4.1.1.2, 4.1.1.3; RFC 3279; RFC 4055 sec. 3.1, 5; RFC 5480 sec. 2; RFC 5758 sec. 3.2; RFC 8410 sec. 3, 6; arithmetic by `sigwire[verify]` | `[part]` | `tests/test_signatures.py::test_differential_against_cryptography` | M2 |
| `algorithms.rehome` | design: `asn1core` owns structure (its `dk.spki-key` row) | `[ ]` | (to be written) | M2 |
| `algorithms.ec_compressed` | RFC 5480 sec. 2.2 (compressed points MAY be supported) | `[ ]` | (to be written) | M2 |
| `algorithms.rsassa_pss_key` | RFC 4055 sec. 3.1, 3.3; RFC 5756; RFC 8017 sec. A.2.3 and erratum 5111 | `[ ]` | (to be written) | M2 |
| `algorithms.ed448` | RFC 8410 sec. 3; RFC 8032 sec. 5.2 | `[ ]` | (to be written) | M2 |
| `algorithms.ml_dsa` | RFC 9881 | `[ ]` | (to be written) | M2 |
| `chain.ca_constraints` | RFC 5280 sec. 6.1.4(k)-(n), 4.2.1.9, 4.2.1.3; RFC 5480 sec. 3 with RFC 8813; RFC 9295 | `[ ]` | (to be written) | M2 |
| `chain.critical_extensions` | RFC 5280 sec. 4.2, 6.1.4 | `[ ]` | (to be written) | M2 |
| `chain.issuer_binding` | RFC 5280 sec. 6.1.3(a)(1), (a)(4), 4.2.1.1, 4.2.1.2 | `[ ]` | (to be written) | M2 |
| `validity.version1_ca` | RFC 5280 sec. 4.2.1.9 (silent on v1); fail closed, see section 5 | `[ ]` | (to be written) | M2 |
| `names.constraint_holds()` | RFC 5280 sec. 6.1.3(b), (c), 4.2.1.10, 7; RFC 9549 sec. 2.2-2.5 | `[ ]` | `tests/test_obligations.py::constraint_holds` | M3 |
| `names.idn_email` | RFC 9549 sec. 2.3-2.5 (RFC 8399 is obsolete); RFC 9598 (RFC 8398 is obsolete) | `[ ]` | (to be written) | M3 |
| `policy.resolve()` | RFC 5280 sec. 6.1.2-6.1.5 as replaced by RFC 9618 sec. 5.1-5.6 | `[ ]` | `tests/test_obligations.py::resolve` | M4 |
| `policy.graph` | RFC 9618 sec. 4.1, 4.2 and 5.2-5.5: the policy graph, linear in the certificates | `[ ]` | (to be written) | M4 |
| `policy.limits` | RFC 9618 sec. 6.2, 6.3 (fallback bounds on depth and size; defence in depth once the graph exists) | `[ ]` | (to be written) | M4 |
| `revocation.status_of()` | RFC 5280 sec. 6.1.3(a)(3), 6.3; RFC 6960 | `[ ]` | `tests/test_obligations.py::status_of` | M5 |
| `revocation.no_rev_avail` | RFC 9608 sec. 4: step (a)(3) is skipped for noRevAvail or ocsp-nocheck | `[ ]` | (to be written) | M5 |
| `revocation.crl_issuer_key_usage` | RFC 10007 sec. 4: amended step (f) of RFC 5280 sec. 6.3.3 | `[ ]` | (to be written) | M5 |
| `revocation.crl_signature` | RFC 5280 sec. 5.1.1, 6.3.3; verify through `validity.check_signature_with_spki` | `[ ]` | (to be written) | M5 |
| `result.validate()` | RFC 5280 sec. 6 | `[ ]` | `tests/test_obligations.py::validate` | M6 |
| `result.provenance` | design: strategy constitution item 5 | `[ ]` | (to be written) | M6 |
| `corpus.path_validation` | a pinned public path-validation suite (source, digest and licence not yet chosen) | `[ ]` | (to be written) | M6 |
| `deps.sigprim_pin` | design: `sigwire[verify]` (merged from the retired `sigprim`, 2026-11-13) is unpublished, so CI and the wheel cannot resolve it yet | `[ ]` | (to be written) | M6 |
| `store.remember()` | design | `[ ]` | `tests/test_obligations.py::remember` | - |
| `m7.document` | MS-CAB and MS-CTL: no retrievable copy, see below | `[ ]` | (to be written) | M7 |
| `cab.member()` | MS-CAB (vendor format, not an RFC). **Blocked by `m7.document`.** | `[ ]` | `tests/test_obligations.py::cab_member` | M7 |
| `ctl.root_program()` | MS-CTL (vendor format, not an RFC). **Blocked by `m7.document`.** | `[ ]` | `tests/test_obligations.py::ctl_root_program` | M7 |
| `ctl.signed_by_microsoft()` | MS-CTL Authenticode. **Blocked by `m7.document` and by `signeddata` (CMS/PKCS #7 verification).** | `[ ]` | `tests/test_obligations.py::ctl_signed_by_microsoft` | M7 |

### What the new rows record

Added 2026-11-13 from the group A roadmap review, each claim re-read through `rfclib` first.

- `validity.check_signature()` is `[part]`: RSASSA-PKCS1-v1_5 (the SHA-2 identifiers and SHA-1), RSASSA-PSS
  with an `rsaEncryption` key, ECDSA over P-256, P-384 and P-521, and Ed25519 verify, through `sigwire[verify]`,
  and the real Let's Encrypt chain plus synthetic certificates from `cryptography` are the corpus. Not yet
  covered, each its own row above: compressed EC points, `id-RSASSA-PSS` public keys, Ed448, ML-DSA, DSA,
  and the signature on a CRL. SHA-1 and RSA under 2048 bits are refused by the default `sigwire[verify]` policy, as
  a `SignaturePolicyRefused` that is never reported as a bad signature.
- `anchors.rebase`, `anchors.no_cryptography` and `anchors.verify` close the open question of section 5:
  `anchors` reads through `asn1core`, verifies through `validity`, and `cryptography` left the runtime
  dependencies (it stays a dev dependency, as the oracle and as the thing that mints test certificates).
  The review proposed a `verify()` that "raises until M2" and no such method existed; M2's signature check
  landed in the same change, so `TrustAnchor.verify()` works, and it raises `SignatureUnsupported` for any
  key it cannot check.
- `policy.graph`: the section 6.1.2 and 6.1.3 text of RFC 5280 describes a policy **tree** that RFC 9618
  replaces with a policy **graph**; implementing the 5280 text reintroduces the exponential growth. RFC 9618
  section 6.3 ("limit policy tree size") is an alternative mitigation for implementations that keep the
  tree, so `policy.limits` is defence in depth and not a substitute. The review cited sections 5.2 and 5.3;
  the update runs from 5.1 to 5.6.
- `revocation.crl_issuer_key_usage`: RFC 10007 section 4 requires, for a **v3** CRL issuer certificate, that
  keyUsage be present and carry cRLSign. A v1 or v2 issuer is exempt because those versions have no
  extensions. The review said "a keyUsage/cRLSign check"; the presence requirement is the new part.
- `names.idn_email`: RFC 8398 and RFC 8399 are obsolete (by RFC 9598 and RFC 9549) and are no longer listed
  as sources.
- `chain.ca_constraints`, `chain.critical_extensions`, `chain.issuer_binding`: the checks of section 6.1.4
  steps (k) to (n) and section 4.2, which the candidate search deliberately does not make. `asn1core`
  already lists `unrecognised_critical`; deciding what to do with it is this project's.
- `algorithms.rehome`: `pkix/_algorithms.py` reads AlgorithmIdentifier and SubjectPublicKeyInfo with
  `asn1core`'s codec because `asn1core` has no key decoder yet. It moves there when its `dk.spki-key` row
  lands, and the private TLV helpers that `chain.py` still carries go with it.
- `deps.sigprim_pin`: (id kept from before the merge into `sigwire[verify]` on 2026-11-13) `sigwire` is an unpublished sibling checkout, so the
  CI workflows (which check out only `asn1core`) and a built wheel cannot resolve it. Until it is
  published, `ci.yml` and `security.yml` need a second checkout step, and the call surface used here
  (`rsa.verify_pkcs1v15`, `rsa.verify_pss`, `ecdsa.verify`, `eddsa.verify_ed25519`, `hashes.lookup`,
  `policy.DEFAULT`, `policy.LEGACY`) must be pinned. `sigwire[verify]` itself reaches `cryptography` for the group
  arithmetic, which is the owner's rule for primitives; pkix does not.
- `corpus.path_validation`: the validator's honest corpus is an independent one. No suite (NIST PKITS,
  Wycheproof, BetterTLS or similar) has been fetched or verified here; choosing one, with its source,
  digest and licence, comes before M6.
- `m7.document` is the row the three M7 rows are blocked by: a copy of MS-CAB and MS-CTL, with title and
  revision, retrieved by a person who can reach one. It encodes in the matrix what the prose below says,
  because `projecthub`'s loop reads rows and not paragraphs. `ctl.signed_by_microsoft()` is also blocked by
  `signeddata`, because an Authenticode signature is CMS and none of RFC 5280 covers it.

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
- M2 section 6.1.3 step (a), basic certificate processing: signature, dates, issuer matching, critical
  extensions (this line cited section 6.2 until 2026-11-13; section 6.2 is "Using the Path Validation
  Algorithm", and `validity.py` was corrected to 6.1.3 on 2026-11-07)
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

Read through `rfclib` on 2026-11-13; [docs/rfc-map.md](docs/rfc-map.md) carries the full table, with each
document's status, its errata and what it changes here.

- RFC 5280 carries 6 verified errata and is updated by RFC 6818, RFC 9549, RFC 9598, RFC 9608, RFC 9618,
  RFC 9925 and RFC 10007. **RFC 8398 and RFC 8399, which this line listed until 2026-11-13, are obsolete**
  (by RFC 9598 and RFC 9549 respectively); implement the successors. The updates are not editorial:
  RFC 9618 replaces the policy tree with a graph (`policy.graph`), RFC 10007 amends the CRL issuer check
  of section 6.3.3 (`revocation.crl_issuer_key_usage`), RFC 9608 amends step (a)(3) of section 6.1.3
  (`revocation.no_rev_avail`), RFC 9549 and RFC 9598 change name constraints and email names
  (`names.idn_email`), and RFC 9925 adds a placeholder signature algorithm that must never verify
  (`validity.unsigned_certificate`, done).
- RFC 5912 carries 8 verified errata.
- RFC 6960 carries 6 verified errata.
- The signature documents, each with errata: RFC 3279 (5), RFC 4055 (2, updated by RFC 5756), RFC 5480 (2,
  updated by RFC 8813), RFC 5758 (none verified), RFC 8017 (5, of which **erratum 5154** misprints the
  `sha224WithRSAEncryption` row as SHA-256; pinned by `algorithms.oid_table`), RFC 8032 (6, of which 5519
  and 5968 fix the range of S and 5930 is a missing `raise` in the reference `verify()`; enforced in
  `sigwire[verify]`) and RFC 8410 (4, updated by RFC 9295).

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

- **Resolved 2026-11-13: `anchors` against M2.** The question was whether to write a throwaway
  `cryptography` bridge so `TrustAnchor.verify()` could check a signature before M2. Neither happened: M2's
  signature check was written instead (`validity.check_signature`, through `sigwire[verify]`), `anchors` was
  re-based onto `asn1core` in the same change, and `cryptography` is no longer imported by anything in
  `pkix/`. RFC 5280 section 6.1.1(d) does not require an anchor's own signature to verify, so `load_anchor`
  still loads a certificate whose self-signature does not check and records `self_signed` instead.
- **A version 1 certificate carries no basic constraints extension at all**, and RFC 5280 §4.2.1.9
  phrases its prohibition for the case where the extension "is not present in a *version 3*
  certificate". Read closely, that sentence does not reach a v1 issuer, so the text does not say
  whether a v1 CA certificate may serve as a path member. pkix's answer is refusal (fail closed)
  until a reachable source says otherwise; the alternative — treating silence as permission — lets a
  v1 document into a path on a reading nobody verified.
- **Whether a verifier must reject a public key that is not on the curve, or not in the prime-order
  subgroup, is not a quoted MUST here.** RFC 5480 §4 raises it in lower case and attributes the
  choices to SP 800-56A, and SEC1 §2.3.3, X9.62 and FIPS 186-3 are not reachable from this
  environment. The point is validated, by `sigwire[verify]`, which raises for one that is off the curve;
  pkix reports that as `MalformedAlgorithm` (`test_an_ec_key_off_the_curve_is_malformed_not_a_verdict`).
  The decision is pkix's and sigwire[verify]'s, not the specification's, and a subgroup check beyond that is
  not made.
- **RSA-PSS salt length when the parameters do not pin it.** For a *signature*, RFC 4055 §3.1 makes
  the parameters mandatory in the signatureAlgorithm and gives `saltLength` a default of 20, so the
  salt length is always known and `check_signature` passes exactly that number to `sigwire[verify]`, never its
  "auto" mode (`test_pss_parameters_are_read_with_their_defaults`). What stays open is the
  restriction an `id-RSASSA-PSS` *key* carries (RFC 4055 §3.3), which is row `algorithms.rsassa_pss_key`.
- **MS-CAB and MS-CTL remain unreachable** (M7). The dead ends are tabulated above so the next
  attempt starts past them.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

## Board projection

`python -m projecthub sync --check` (the retired `sdk-forge/sync_roadmap.py` was its predecessor)
projects section 1 onto GitHub issues, collected on Project V2 **#2 "Protocol SDK portfolio"**. Counts as the
matrix stands on 2026-11-13: **36 rows** in section 1, of which 8 `[ok]`, 1 `[part]` and 27 `[ ]`, plus the 4
`[no]` non-goals of section 4, which are decisions and not work and are not filed.

A live read, `python -m projecthub sync --check --project pkix` on 2026-11-13, reports **36 rows, 10 rows with
issues, 20 drift items**: 19 are open rows with no issue (the rows added today) and 1 is
`validity.check_validity()`, which is now `[ok]` while issue #297 is still open. The five new `[ok]` rows
have no issue and are not drift. The previous count in this paragraph, **12 items** read through the hosted
GitHub MCP server on 2026-11-07, was stale because M1's rows closed afterwards. Rows with no issue are filed
by `projecthub sync --apply`, and closing #297 is the same run's job.
Neither write was made from here. The numbers here are a dated snapshot and not a live
count: the board is the live view and this file is the source of truth, because a board cannot refuse a row
that claims `[ok]` without a test, and `tests/test_roadmap_rows.py` can (it now checks that the named test
exists, which it did not before 2026-11-13).
