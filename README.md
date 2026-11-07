# pkix

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

pkix -- RFC 5280 path validation, the part Python never had

Python can build a certificate and parse a certificate, and it cannot tell you whether a certificate is valid. cryptography has no path validator; the one serious implementation, certvalidator 0.11.1, has not been released since 2016-07-29 and sits on oscrypto, itself dead since 2022-03-18. Everything else shells out to openssl verify and parses text. That is the odd gap in PKI: the specification is a single algorithm, RFC 5280 section 6, and it is the one nobody maintains in Python. Parsing is a solved problem and x509kit proved it again in 2026-10-11 by writing a whole toolkit including its own RSA, ECDSA and AES; pkix deliberately owns the opposite half: decisions, not bytes, and primitives borrowed from cryptography rather than re-invented.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| certvalidator | 0.11.1 | 2016-07-29 | the only Python path validator, dead for a decade on a dead crypto backend |
| cryptography | 50.0.2 | 2026-09-30 | builds and parses certificates, and verifies signatures, but builds no path and applies no policy |
| x509kit | 0.10.0 | 2026-10-11 | structures and its own crypto; validation policy is not the product |

What this project intends to add:

- section 6.1 user data and 6.2 certification path validity checks, implemented as written
- name constraints including the subtle excluded-subtrees rule and the check-only-at-issuance exception
- policy mapping, policy constraints and explicit policy with anyPolicy handled correctly
- revocation as an injected interface, so CRL, OCSP, stapled and cached answers are all opinions you can test
- a result object that states which trust anchor, which chain, which policy and which revocation source decided it

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 5280 | Proposed Standard | 2008-05 | the profile and the section 6 path validation algorithm |
| RFC 5912 | Informational | 2010-06 | the ASN.1 modules every PKIX structure is written in |
| RFC 6960 | Proposed Standard | 2013-06 | OCSP status, one of the two revocation inputs the algorithm consults |

### Errata watch

- RFC 5280 carries 6 verified errata and is updated by RFC 6818, RFC 8398, RFC 8399, RFC 9549, RFC 9598, RFC 9608, RFC 9618, RFC 9925 and RFC 10007. The updates are not editorial: internationalised names and notBefore bounds changed the answer.
- RFC 5912 carries 8 verified errata.
- RFC 6960 carries 6 verified errata.

## Module layout

| Module | Responsibility |
|---|---|
| `anchors` | trust anchor selection, including name restrictions and certificates only sets (RFC 5280 sec. 6.1) |
| `chain` | candidate path discovery against a store or a directory of intermediates |
| `validity` | the section 6.2 processing: signature, validity, issuer, name constraints (RFC 5280) |
| `names` | name forms, general names and constraint comparison, including internationalised forms |
| `policy` | policy mappings, constraints and anyPolicy resolution (RFC 5280) |
| `revocation` | the status interface plus an allow list of trusted decisions |
| `result` | the outcome object with provenance for every decision |
| `store` | certificate, CRL and OCSP caches behind one interface |

## What it does not do

- a certificate parser of its own: parsing belongs to `asn1core`, which keeps the bytes it parsed; pkix accepts DER and refuses anything else
- signing anything: pkix verifies certificates and CRLs, holds no private key, and has no operation that produces a signature
- ACME, CMP or any issuance protocol: enrollkit asks pkix whether the result is acceptable
- the CA/Browser Forum baseline requirements, which are a policy profile built on top, not this algorithm



## Why this project has a runtime dependency

Right now, and only for as long as the table below says so: one module imports `cryptography` — `pkix/anchors.py`, which uses it to parse a certificate and to check a signature. Neither role is permanent, and neither is where this project's value is.

| Role `cryptography` plays today | Where | Leaves when | Why it leaves |
|---|---|---|---|
| parses certificates into objects | `pkix/anchors.py` | the M1 model row | RFC 5280 §4.1.1.3 binds the signature to the DER encoding of the tbsCertificate as it arrived; a parser that hands back its own re-encoding cannot show those bytes. `asn1core` keeps every field as a slice of the document it read |
| compares two distinguished names | `pkix/anchors.py`, and `pkix/chain.py` as soon as discovery lands | the M1 model row | §6.1.3(a)(4) links a path by name equality, and §7.1 defines that equality through the RFC 4518 preparation and `caseIgnoreMatch`. Delegating it to a borrowed `__eq__` outsources the most security-relevant comparison in path validation |
| the verification equations and paddings | not yet written | the M2 row `validity.check_signature()` | pkix verifies and never signs, so every input is public: there is no secret exponent or nonce in the code path to leak. Digests come from `hashlib` and modular exponentiation from `pow()`, both standard library |

The earlier version of this section argued that re-implementing RSA or ECDSA would turn the project into "a timing side channel project". That argument is about private-key work — blinding, and nonces that leak a key when they repeat — and it does not reach verification, which is all pkix does. What verification genuinely risks is accepting a signature that should be rejected, and being verification-only buys the test data for that cheaply: every certificate in the recorded corpus was signed by a different implementation, so the corpus is known-answer data for acceptance and mutated copies of it are known-answer data for refusal. `docs/strategy.md` carries the full reasoning, including the parts of the record (SEC1, X9.62, FIPS 186-3) that this environment cannot reach and that therefore become stated project decisions rather than quoted MUSTs.

The end state is no runtime dependency at all, with `cryptography` staying in the dev group as a differential oracle — a second implementation to disagree with, not a data model to conform to. `pyproject.toml` declares it as a runtime dependency until the commit that removes the last import, because metadata that describes a project which does not exist yet is the same lie in a different file.

Declared as a floor with no ceiling: the application that installs this library resolves the final set, and a ceiling inside a library guarantees a conflict the first time something else needs a newer line.
## Install

```bash
git clone https://github.com/b1tninja/pkix.cd pkix
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy pkix tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
