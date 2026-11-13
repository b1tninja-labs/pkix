"""NIST PKITS 1.0.1 as the conformance corpus of `result.path_walk` (ROADMAP row `corpus.path_validation`).

The corpus is not in this tree: `python tools/fetch_pkits.py` puts the pinned zip in a cache outside
it, and this module skips, loudly, when the zip is absent or is not the pinned bytes. Each case of
`pkits_cases.CASES` (section 4 of the PKITS document) is validated with the trust anchor Trust
Anchor Root Certificate, the CRLs the document lists, and the case's initial inputs, at a fixed
instant inside every certificate's validity window, because PKITS says "the current time" and a
suite that reads the clock changes its answers in 2030.

Every case ends in one of three ways:

* pass: the answer matches the document's expected result;
* not applicable (skipped): pkix answered "unsupported", so it did not decide, and the reason names
  the missing piece (none today; DSA, issuing distribution points, indirect and delta CRLs and
  separate CRL keys were the 69 of the first run);
* fail: pkix decided and decided wrongly. Those known today are listed in `KNOWN_FAILURES` and run
  as strict xfails, so fixing one turns the suite red until the list is updated, and a new one is a
  plain failure.

`test_pkits_counts` pins the three totals, which are also recorded in ROADMAP.md.
"""

from __future__ import annotations

import collections
import datetime
import functools
import zipfile

import asn1core
import pytest
import sigwire.verify
from pkits_cases import CASES, Case

from pkix.anchors import load_anchor
from pkix.errors import PkixError
from pkix.result import PathInputs, PathResult, path_walk
from pkix.revocation import CrlChecker
from pkix.validity import check_signature
from tools import fetch_pkits

AT = datetime.datetime(2020, 6, 1, tzinfo=datetime.UTC)
ANCHOR = "TrustAnchorRootCertificate"
DSA_CASES = frozenset({"4.1.4", "4.1.5", "4.1.6"})

# Cases pkix decides wrongly today, each with the reason found. Empty is the goal.
KNOWN_FAILURES: dict[str, str] = {}

# The totals at the time of writing: pass, not applicable, fail. 178/69/0 until 2026-11-13, when
# issuing distribution points, indirect CRLs, separate CRL signing keys, delta CRLs and DSA (under
# LEGACY) closed the 69.
EXPECTED_COUNTS = {"pass": 247, "n/a": 0, "fail": 0}

_problem = fetch_pkits.verify(fetch_pkits.corpus_path())
if _problem is not None:
    pytest.skip(
        f"PKITS corpus absent ({_problem}): run `python tools/fetch_pkits.py` to fetch the pinned "
        "zip into the cache; nothing about RFC 5280 conformance was checked",
        allow_module_level=True,
    )


@functools.cache
def _archive() -> zipfile.ZipFile:
    return zipfile.ZipFile(fetch_pkits.corpus_path())


def _read(member: str) -> bytes:
    return _archive().read(member)


def _links(child: asn1core.Certificate, parent: asn1core.Certificate) -> bool:
    try:
        check_signature(child, parent, policy=sigwire.verify.LEGACY)
    except PkixError:
        return False
    return True


def order(case: Case, anchor_name: asn1core.Name) -> list[bytes | asn1core.Certificate]:
    """The path, target first, from the certificates the document lists for the case.

    The list is not always a path: some cases also list a CRL signing certificate that shares its
    subject with the CA. So the path is chained back from the target by name, preferring the
    candidate whose key verifies the certificate below it; when none does (an invalid signature is
    the point of the case), the first one by name stays in, so the walk can reject it.
    """
    raw = [_read(f"certs/{s}.crt") for s in case.certificates]
    try:
        pool = [asn1core.parse_certificate(der) for der in raw]
    except asn1core.Asn1Error:
        return list(reversed(raw))  # the walk reports which one is unreadable
    path = [pool.pop()]
    while not asn1core.names_equal(path[-1].issuer, anchor_name):
        named = [c for c in pool if asn1core.names_equal(c.subject, path[-1].issuer)]
        if not named:
            break
        chosen = next((c for c in named if _links(path[-1], c)), named[0])
        pool.remove(chosen)
        path.append(chosen)
    return list(path)


def signature_policy(case: Case) -> sigwire.verify.Policy:
    """The DSA cases (PKITS 4.1.4 to 4.1.6) run under `sigwire.verify.LEGACY`, which admits DSA;
    the strict default refuses it (PORTFOLIO.md section 9 item 15), and
    `test_dsa_cases_are_refused_under_the_strict_policy` pins that. Every other case is SHA-256
    with RSA-2048 and runs under the default."""
    return sigwire.verify.LEGACY if case.section in DSA_CASES else sigwire.verify.DEFAULT


def run(case: Case, policy: sigwire.verify.Policy | None = None) -> PathResult:
    anchor = load_anchor(_read(f"certs/{ANCHOR}.crt"))
    path = order(case, anchor.issuer)
    chosen = signature_policy(case) if policy is None else policy
    # Every certificate the case lists is offered as a possible CRL signer or as an intermediate on
    # a CRL signer's path (RFC 5280 sec. 6.3.3(f)); the path itself is chained by `order`.
    crls = CrlChecker(
        (_read(f"crls/{stem}.crl") for stem in case.crls),
        certificates=[_read(f"certs/{s}.crt") for s in case.certificates],
        policy=chosen,
    )
    inputs = PathInputs(
        user_initial_policy_set=None if case.policies is None else frozenset(case.policies),
        initial_explicit_policy=case.explicit,
        initial_policy_mapping_inhibit=case.mapping_inhibit,
        initial_any_policy_inhibit=case.inhibit_any,
        signature_policy=chosen,
        revocation=crls,
    )
    return path_walk(path, anchor, AT, inputs)


def classify(case: Case, result: PathResult) -> str:
    if result.status == "unsupported":
        return "n/a"
    return "pass" if result.valid == case.valid else "fail"


def _describe(result: PathResult) -> str:
    step = result.failure
    if step is None:
        return result.status
    return f"{result.status} at certificate {step.index}, {step.step}: {step.detail}"


@pytest.mark.parametrize("case", CASES, ids=[c.section for c in CASES])
def test_pkits_case(case: Case) -> None:
    result = run(case)
    verdict = classify(case, result)
    if verdict == "n/a":
        pytest.skip(f"PKITS {case.section} {case.title} not applicable: {_describe(result)}")
    if case.section in KNOWN_FAILURES:
        if verdict == "fail":
            pytest.xfail(f"{KNOWN_FAILURES[case.section]}: {_describe(result)}")
        pytest.fail(f"{case.section} now passes: remove it from KNOWN_FAILURES")
    expected = "valid" if case.valid else "invalid"
    assert verdict == "pass", (
        f"PKITS {case.section} {case.title}: expected {expected}, got {_describe(result)}"
    )


def test_pkits_counts() -> None:
    counts = collections.Counter(classify(case, run(case)) for case in CASES)
    found = {key: counts.get(key, 0) for key in EXPECTED_COUNTS}
    print(f"PKITS 1.0.1: {found['pass']} pass, {found['n/a']} not applicable, {found['fail']} fail")
    assert found == EXPECTED_COUNTS


def test_dsa_cases_are_refused_under_the_strict_policy() -> None:
    """The valid DSA cases validate under LEGACY and are refused, as a policy decision and not as a
    bad signature, under the strict default."""
    for case in CASES:
        if case.section not in DSA_CASES or not case.valid:
            continue
        assert run(case, sigwire.verify.LEGACY).valid, case.section
        strict = run(case, sigwire.verify.DEFAULT)
        assert strict.status == "invalid"
        assert strict.failure is not None
        assert "signature policy" in strict.failure.detail, case.section
