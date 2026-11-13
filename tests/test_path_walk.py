"""`result.path_walk`: RFC 5280 sec. 6.1.3 to 6.1.5 joined into one pass (ROADMAP row `result.path_walk`).

Every certificate here is minted by `builders` and signed with its one key, which is also every
certificate's subject key, so each signature in a path verifies and a test can change exactly one
other property. NIST PKITS (`test_pkits.py`) is the independent corpus; these tests pin each step
without it, so they run where the corpus is absent.
"""

from __future__ import annotations

import datetime

import asn1core
import pytest
from builders import KEY, NOT_BEFORE, certificate, dn, oid
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from pkix.anchors import load_anchor
from pkix.errors import MalformedExtension
from pkix.extensions import parse_key_usage
from pkix.result import PathInputs, path_walk, validate
from pkix.revocation import CrlChecker

AT = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
CA_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)
POLICY = "1.3.6.1.4.1.99999.7"


def ca(path_length: int | None = None) -> tuple[x509.ExtensionType, bool]:
    return x509.BasicConstraints(ca=True, path_length=path_length), True


def usage(**bits: bool) -> tuple[x509.ExtensionType, bool]:
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    )
    return x509.KeyUsage(**{name: bits.get(name, False) for name in names}), True


def policies(*oids: str) -> tuple[x509.ExtensionType, bool]:
    return x509.CertificatePolicies([x509.PolicyInformation(oid(p), None) for p in oids]), False


ROOT = certificate(dn("Root"), dn("Root"), [ca(), (CA_USAGE, True)])
ANCHOR = load_anchor(ROOT.raw)


def chain(*, ca_ext=None, leaf_ext=(), leaf_issuer="CA", leaf_subject="Leaf"):
    """Leaf, then one intermediate "CA" issued by "Root": target first, as path_walk takes it."""
    intermediate = certificate(
        dn("CA"), dn("Root"), [ca(), (CA_USAGE, True)] if ca_ext is None else ca_ext
    )
    leaf = certificate(dn(leaf_subject), dn(leaf_issuer), list(leaf_ext))
    return [leaf, intermediate]


def failed_step(result) -> str:
    assert result.failure is not None
    return result.failure.step


def test_a_well_formed_path_validates_and_records_every_step():
    result = path_walk(chain(), ANCHOR, AT)
    assert result.valid
    assert result.working_public_key == chain()[0].subject_public_key_info
    steps = [(s.index, s.step) for s in result.steps]
    assert (1, "6.1.3(a)(1) signature") in steps
    assert (1, "6.1.4(k) CA certificate") in steps
    assert (2, "6.1.5(f) critical extensions") in steps
    assert steps[-1] == (0, "6.1.3(d)-6.1.5(g) policy (RFC 9618)")
    # No revocation checker was given, and the result says so rather than implying "not revoked".
    assert result.revocation_checked is False


def test_the_policy_limits_of_rfc_9618_sec_6_are_inputs_of_the_walk():
    """Row `policy.limits`: `PathInputs.policy_max_depth` and `policy_max_nodes` fail the policy step."""
    assert path_walk(chain(), ANCHOR, AT, PathInputs(policy_max_depth=2)).valid
    shallow = path_walk(chain(), ANCHOR, AT, PathInputs(policy_max_depth=1))
    assert shallow.status == "invalid"
    assert failed_step(shallow) == "6.1.3(d)-6.1.5(g) policy (RFC 9618)"
    assert shallow.failure is not None
    assert "6.2" in shallow.failure.detail
    # Both certificates assert a policy, so the graph has nodes: 2 below the anyPolicy root.
    asserting = chain(
        ca_ext=[ca(), (CA_USAGE, True), policies(POLICY)], leaf_ext=[policies(POLICY)]
    )
    assert path_walk(asserting, ANCHOR, AT, PathInputs(policy_max_nodes=50)).valid
    tight = path_walk(asserting, ANCHOR, AT, PathInputs(policy_max_nodes=1))
    assert tight.status == "invalid"
    assert tight.failure is not None
    assert "6.3" in tight.failure.detail


def test_an_intermediate_without_basic_constraints_ca_is_rejected():
    result = path_walk(chain(ca_ext=[(CA_USAGE, True)]), ANCHOR, AT)
    assert result.status == "invalid"
    assert failed_step(result) == "6.1.4(k) CA certificate"


def test_path_length_constraint_zero_stops_a_further_ca():
    sub = certificate(dn("Sub"), dn("CA"), [ca(), (CA_USAGE, True)])
    intermediate = certificate(dn("CA"), dn("Root"), [ca(0), (CA_USAGE, True)])
    leaf = certificate(dn("Leaf"), dn("Sub"))
    result = path_walk([leaf, sub, intermediate], ANCHOR, AT)
    assert failed_step(result) == "6.1.4(l) path length"
    assert result.failure is not None
    assert result.failure.index == 2


def test_a_key_usage_without_key_cert_sign_is_rejected():
    result = path_walk(chain(ca_ext=[ca(), usage(crl_sign=True)]), ANCHOR, AT)
    assert failed_step(result) == "6.1.4(n) key usage"


def test_an_unknown_critical_extension_fails_and_a_non_critical_one_does_not():
    unknown = x509.UnrecognizedExtension(oid("1.3.6.1.4.1.99999.99"), b"\x05\x00")
    assert failed_step(path_walk(chain(leaf_ext=[(unknown, True)]), ANCHOR, AT)) == (
        "6.1.5(f) critical extensions"
    )
    assert path_walk(chain(leaf_ext=[(unknown, False)]), ANCHOR, AT).valid


def test_an_issuer_that_is_not_the_working_issuer_name_breaks_the_path():
    result = path_walk(chain(leaf_issuer="Someone Else"), ANCHOR, AT)
    assert failed_step(result) == "6.1.3(a)(4) issuer name"


def test_a_certificate_outside_its_validity_period_is_rejected():
    late = NOT_BEFORE.replace(tzinfo=datetime.UTC) + datetime.timedelta(days=4000)
    assert failed_step(path_walk(chain(), ANCHOR, late)) == "6.1.3(a)(2) validity"


def test_excluded_subtree_rejects_the_leaf():
    constraints = x509.NameConstraints(
        permitted_subtrees=None, excluded_subtrees=[x509.DNSName("bad.example")]
    )
    san = x509.SubjectAlternativeName([x509.DNSName("www.bad.example")])
    path = chain(ca_ext=[ca(), (CA_USAGE, True), (constraints, True)], leaf_ext=[(san, False)])
    result = path_walk(path, ANCHOR, AT)
    assert failed_step(result) == "6.1.3(b)-(c) name constraints"
    assert result.failure is not None
    assert "excluded" in result.failure.detail


def test_initial_explicit_policy_needs_a_policy_on_every_certificate():
    inputs = PathInputs(initial_explicit_policy=True)
    assert failed_step(path_walk(chain(), ANCHOR, AT, inputs)).startswith("6.1.3(d)")
    with_policy = chain(
        ca_ext=[ca(), (CA_USAGE, True), policies(POLICY)], leaf_ext=[policies(POLICY)]
    )
    root = certificate(dn("Root"), dn("Root"), [ca(), (CA_USAGE, True)])
    result = path_walk(with_policy, load_anchor(root.raw), AT, inputs)
    assert result.valid
    assert result.policy is not None
    assert set(result.policy.user_constrained) == {POLICY}


def _crl(issuer: str, revoked_serials=(), extensions=()) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(dn(issuer))
        .last_update(datetime.datetime(2025, 1, 1))
        .next_update(datetime.datetime(2026, 1, 1))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(datetime.datetime(2025, 2, 1))
            .build()
        )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    return builder.sign(KEY, hashes.SHA256()).public_bytes(Encoding.DER)


def test_a_revoked_leaf_fails_and_an_absent_crl_fails_closed():
    path = chain()
    good = PathInputs(revocation=CrlChecker([_crl("Root"), _crl("CA")]))
    result = path_walk(path, ANCHOR, AT, good)
    assert result.valid
    assert result.revocation_checked
    revoked = PathInputs(revocation=CrlChecker([_crl("Root"), _crl("CA", [path[0].serial])]))
    result = path_walk(path, ANCHOR, AT, revoked)
    assert failed_step(result) == "6.1.3(a)(3) revocation"
    assert result.failure is not None
    assert result.failure.detail.startswith("revoked")
    # RFC 5280 sec. 6.3.3: no CRL from the leaf's issuer is UNDETERMINED, and that is not "good".
    missing = PathInputs(revocation=CrlChecker([_crl("Root")]))
    result = path_walk(path, ANCHOR, AT, missing)
    assert result.status == "invalid"
    assert result.failure is not None
    assert result.failure.detail.startswith("undetermined")


def test_a_crl_pkix_cannot_verify_is_unsupported_not_good():
    """An issuing distribution point used to be the example here; it is processed now (row
    `revocation.idp`). What stays unsupported is evidence pkix cannot check: a CRL signed with an
    algorithm it does not verify (Ed448, row `algorithms.ed448`)."""
    from cryptography.hazmat.primitives.asymmetric import ed448

    unverifiable = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(dn("CA"))
        .last_update(datetime.datetime(2025, 1, 1))
        .next_update(datetime.datetime(2026, 1, 1))
        .sign(ed448.Ed448PrivateKey.generate(), None)
        .public_bytes(Encoding.DER)
    )
    inputs = PathInputs(revocation=CrlChecker([_crl("Root"), unverifiable]))
    result = path_walk(chain(), ANCHOR, AT, inputs)
    assert result.status == "unsupported"
    assert failed_step(result) == "6.1.3(a)(3) revocation"


def test_validate_discovers_the_path_through_the_pool():
    leaf, intermediate = chain()
    result = validate(leaf, [ANCHOR], AT, intermediates=[intermediate])
    assert result.valid
    nowhere = validate(leaf, [ANCHOR], AT)
    assert nowhere.status == "invalid"
    assert failed_step(nowhere) == "6.1.1(a) path discovery"


def test_key_usage_is_read_by_asn1core_and_a_trailing_zero_bit_is_refused():
    """keyUsage moved onto `asn1core.extensions.parse_key_usage`, which enforces X.690 11.2.2."""
    good = asn1core.Extension((2, 5, 29, 15), True, bytes.fromhex("03020106"), b"")
    assert parse_key_usage(good) == frozenset({"keyCertSign", "cRLSign"})
    # 03 02 00 06: the same two bits with the trailing zero bit kept, which DER forbids.
    trailing = asn1core.Extension((2, 5, 29, 15), True, bytes.fromhex("03020006"), b"")
    with pytest.raises(MalformedExtension, match=r"11\.2\.2"):
        parse_key_usage(trailing)
