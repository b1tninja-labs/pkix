# Instructions for coding agents

Certification path discovery and validation per RFC 5280: trust anchors, name constraints, policy mapping and constraints, CRL and OCSP status hooks, explicit result provenance.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` is the work queue, and `README.md` explains
what the library is for. Read those three before changing anything.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python -m projecthub pickup --who <your name> --project pkix

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.projecthub/packet.md` if it exists. If it does not, ask what
to work on.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy pkix tests

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[x]` unless
   the test named in its `Evidence` cell exists and passes. `tests/test_roadmap_rows.py`
   fails on any row that claims done without a named test, and that check is the
   reason the roadmap can be trusted. Do not weaken it, skip it, or delete it to
   get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with `rfclib` and
   cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies.** The runtime dependencies are `asn1core` and `sigwire[verify]`, both resolved from sibling
   checkouts. `cryptography` is **not** one: nothing in `pkix/` may import it, a test enforces that, and it is
   a dev dependency for minting test certificates and as a differential oracle. Certificate parsing is
   `asn1core`'s and signature arithmetic is `sigwire[verify]`'s (which reaches `cryptography` for the primitives, as
   the owner's rule of 2026-11-12 allows). Adding a runtime dependency needs a paragraph of justification in
   `docs/strategy.md` explaining why the standard library, `asn1core` and `sigwire[verify]` are not enough.
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.

## Read before implementing

- RFC 5280 carries 6 verified errata and is updated by RFC 6818, RFC 9549, RFC 9598, RFC 9608, RFC 9618, RFC 9925 and RFC 10007. RFC 8398 and RFC 8399 are obsolete (by RFC 9598 and RFC 9549): do not cite them. The updates are not editorial. RFC 9618 replaces the policy tree with a graph, so `policy.resolve()` implements 9618 and not the 5280 text; RFC 10007 amends the CRL issuer check; RFC 9608 skips revocation for noRevAvail; RFC 9925 makes id-alg-unsigned never verify.
- The signature documents (RFC 3279, 4055, 5480, 5758, 8017, 8032, 8410) are in `docs/rfc-map.md` with their errata. RFC 8017 erratum 5154 (sha224WithRSAEncryption is SHA-224) and RFC 8032 errata 5519, 5930, 5968 are pinned in tests.
- RFC 5912 carries 8 verified errata.
- RFC 6960 carries 6 verified errata.

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfclib` calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.
