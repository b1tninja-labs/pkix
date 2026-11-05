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

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `anchors.load_anchor()` | RFC 5280 sec. 6.1 | `[ ]` | `tests/test_obligations.py::load_anchor` |
| `chain.candidates()` | RFC 5280 sec. 6.1 | `[ ]` | `tests/test_obligations.py::candidates` |
| `validity.check_signature()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::check_signature` |
| `validity.check_validity()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::check_validity` |
| `names.constraint_holds()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::constraint_holds` |
| `policy.resolve()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::resolve` |
| `revocation.status_of()` | RFC 5280 | `[ ]` | `tests/test_obligations.py::status_of` |
| `result.validate()` | RFC 5280 sec. 6 | `[ ]` | `tests/test_obligations.py::validate` |
| `store.remember()` | design | `[ ]` | `tests/test_obligations.py::remember` |

## 2. Milestones

- M1 anchors and chain discovery with a fixture set of real chains
- M2 section 6.2 validity: signature, dates, issuer matching, critical extensions
- M3 name constraints including excluded subtrees and the issuance-time exception
- M4 policy mapping, constraints and anyPolicy
- M5 revocation interface plus CRL and OCSP backed implementations and cross-checks against openssl verify
- M6 publication: 0.1.0 with the conformance trace against NIST and vendor path test suites

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
