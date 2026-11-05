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

- a certificate parser: accept DER or a cryptography object and refuse anything else
- crypto primitives of any kind
- ACME, CMP or any issuance protocol: enrollkit asks pkix whether the result is acceptable
- the CA/Browser Forum baseline requirements, which are a policy profile built on top, not this algorithm



## Why this project has a runtime dependency

Signature verification is the one thing this project must not write itself. A path validator that re-implements RSA or ECDSA in Python turns a well studied algorithm problem into a timing side channel project, so primitives come from cryptography, which vendors audited OpenSSL.

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
mypy pkix
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
