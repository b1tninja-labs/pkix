"""Discovery of prospective certification paths (RFC 5280 sec. 6.1.1(a), 6.1.3(a)(4), 4.2.1.9).

The real fixtures carry more than a picture of production: the served chain is four deep, its leaf
is a genuine `cA`-absent certificate, and its last member is a cross-certificate, so the cross-sign
shape that makes discovery interesting arrives without inventing anything. Synthetic certificates
supply the shapes a real deployment does not hand out -- a cycle, two issuers sharing a name, and a
name spelled differently -- and where a test needs a signature, it comes from `cryptography`, because
`pkix` verifies and never signs (README, "any private-key operation inside `pkix/`").
"""

from __future__ import annotations

import datetime
import pathlib

import asn1core
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pkix.chain import candidates, may_issue

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"


def load(*parts: str) -> asn1core.Certificate:
    return asn1core.parse_certificate((FIX.joinpath(*parts)).read_bytes())


@pytest.fixture(scope="module")
def served() -> list[asn1core.Certificate]:
    return [load("chains", f"letsencrypt.org-{index}.der") for index in range(4)]


@pytest.fixture(scope="module")
def x1() -> asn1core.Certificate:
    return load("anchors", "isrg-root-x1.der")


_NOT_BEFORE = datetime.datetime(2024, 1, 1)


def name(text: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def mint(
    subject: str,
    issuer: str,
    *,
    ca: bool,
    serial: int,
    key: ec.EllipticCurvePrivateKey,
    issuer_key: ec.EllipticCurvePrivateKey,
    path_length: int | None = None,
) -> asn1core.Certificate:
    """A v3 certificate with basicConstraints, signed here because pkix never signs."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_BEFORE + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    )
    signing_key = issuer_key
    issued = builder.sign(signing_key, hashes.SHA256())
    # cryptography 50.x hands back an x509.Certificate, not the bytes: it has to be serialised
    # before asn1core can read it, which is a fair reminder of why a borrowed type is a poor model.
    return asn1core.parse_certificate(issued.public_bytes(serialization.Encoding.DER))


@pytest.fixture(scope="module")
def keys() -> list[ec.EllipticCurvePrivateKey]:
    return [ec.generate_private_key(ec.SECP256R1()) for _ in range(6)]


def test_the_served_chain_is_one_candidate_path(served: list, x1: asn1core.Certificate) -> None:
    paths = candidates(served[0], served[1:], [x1])
    assert [len(path) for path in paths] == [4]
    assert path_id(paths[0]) == path_id(served)


def test_a_path_ends_where_the_anchor_is_reached(served: list, x1: asn1core.Certificate) -> None:
    # The fourth certificate is a cross-certificate whose subject is ISRG Root X2: trusted as an
    # anchor, it ends the path there rather than at a self-signed root. sec. 6.1.1(d) permits
    # exactly that, and sec. 6.1.2 spells out what to do when the anchor is not self-signed.
    paths = candidates(served[0], served[1:], [served[3]])
    assert [len(path) for path in paths] == [3]
    assert paths[0][-1] is served[2]
    # Both anchors available: reaching one does not stop the search, because the longer path
    # through the same name may be the one that survives validation.
    both = candidates(served[0], served[1:], [served[3], x1])
    assert [len(path) for path in both] == [3, 4]


def test_an_unreachable_anchor_yields_no_candidate(served: list, x1: asn1core.Certificate) -> None:
    unrelated = load("anchors", "isrg-root-x2-cross-signed.der")
    assert candidates(served[0], [unrelated], [x1]) == []


def test_the_anchor_is_not_part_of_the_returned_path(
    served: list, x1: asn1core.Certificate
) -> None:
    path = candidates(served[0], served[1:], [x1])[0]
    assert path[0] is served[0]
    assert all(certificate.raw != x1.raw for certificate in path)


def path_id(path: list[asn1core.Certificate]) -> tuple[int, ...]:
    return tuple(certificate.serial for certificate in path)


def _respell(node: asn1core.Node, source: int, target: int) -> bytes:
    """Rebuild a TLV with every attribute value of one string type spelled as another.

    Tag 19 (PrintableString) and 12 (UTF8String) are both single octets and the content octets are
    untouched, so this changes only the spelling of the name. That is the whole point: a comparison
    of bytes reports two identical names as different, which is what sec. 7.1 forbids.
    """
    if not node.constructed:
        tag = node.tag
        if tag.number == source:
            tag = asn1core.Tag(target, False, asn1core.TagClass.universal)
        content = node.content()
        return asn1core.encode_tag(tag) + asn1core.encode_length(len(content)) + content
    body = b"".join(_respell(child, source, target) for child in node.children)
    return asn1core.encode_tag(node.tag) + asn1core.encode_length(len(body)) + body


def test_a_certificate_that_may_not_issue_is_never_a_path_member(
    served: list, keys: list, x1: asn1core.Certificate
) -> None:
    # The served leaf really is a non-CA certificate, so pointing a synthetic child at its subject
    # tests the rule against production bytes: sec. 4.2.1.9 says its key cannot certify anything.
    child = mint(
        "www.example.test", "letsencrypt.org", ca=False, serial=99, key=keys[4], issuer_key=keys[5]
    )
    assert may_issue(served[0]) is False
    assert candidates(child, [served[0], served[1]], [x1]) == []


def test_may_issue_reads_an_absent_ca_boolean_as_false(served: list) -> None:
    assert may_issue(served[0]) is False  # BasicConstraints SEQUENCE {}, cA DEFAULT FALSE
    assert may_issue(served[1]) is True  # cA TRUE with pathLenConstraint 0
    assert may_issue(served[2]) is True


def test_two_certificates_sharing_a_name_yield_two_candidates(keys: list) -> None:
    root = mint("Test Root", "Test Root", ca=True, serial=1, key=keys[0], issuer_key=keys[0])
    first = mint("Cross CA", "Test Root", ca=True, serial=2, key=keys[1], issuer_key=keys[0])
    second = mint("Cross CA", "Test Root", ca=True, serial=3, key=keys[1], issuer_key=keys[0])
    leaf = mint("leaf.test", "Cross CA", ca=False, serial=4, key=keys[2], issuer_key=keys[1])
    paths = candidates(leaf, [first, second], [root])
    assert [len(path) for path in paths] == [2, 2]
    assert {path[-1].serial for path in paths} == {2, 3}


def test_a_cross_signing_cycle_terminates(keys: list) -> None:
    root = mint("Test Root", "Test Root", ca=True, serial=1, key=keys[0], issuer_key=keys[0])
    forward = mint("Cycle A", "Cycle B", ca=True, serial=11, key=keys[1], issuer_key=keys[2])
    back = mint("Cycle B", "Cycle A", ca=True, serial=12, key=keys[2], issuer_key=keys[1])
    leaf = mint("leaf.test", "Cycle A", ca=False, serial=13, key=keys[3], issuer_key=keys[1])
    assert candidates(leaf, [forward, back], [root]) == []


def test_a_certificate_appears_only_once_per_path(served: list, x1: asn1core.Certificate) -> None:
    # sec. 6.1: "A certificate MUST NOT appear more than once in a prospective certification path."
    # Listing the same certificate twice in the pool must not double the search.
    paths = candidates(served[0], [*served[1:], served[1]], [x1])
    assert [len(path) for path in paths] == [4]


def test_max_depth_bounds_the_search(served: list, x1: asn1core.Certificate) -> None:
    assert candidates(served[0], served[1:], [x1], max_depth=2) == []
    assert candidates(served[0], served[1:], [x1], max_depth=4) != []
    with pytest.raises(ValueError, match="max_depth"):
        candidates(served[0], served[1:], [x1], max_depth=0)


def test_a_name_spelled_differently_still_links_the_path(
    served: list, x1: asn1core.Certificate
) -> None:
    # RFC 5280 sec. 7.1 makes name equality a prepared comparison, not a byte comparison, and
    # sec. 6.1.3(a)(4) links a path through that equality. Re-spelling one issuer's
    # PrintableStrings as UTF8Strings changes the bytes and must change nothing else: a validator
    # that compared bytes would lose the path here.
    issuer_tlv = asn1core.certificate_parts(served[2].raw).issuer
    node, _ = asn1core.decode(served[2].raw)

    def rebuild(current: asn1core.Node) -> bytes:
        if current.raw == issuer_tlv:
            return _respell(current, 19, 12)
        if current.constructed:
            body = b"".join(rebuild(child) for child in current.children)
            return asn1core.encode_tag(current.tag) + asn1core.encode_length(len(body)) + body
        return current.raw

    respelled = asn1core.parse_certificate(rebuild(node))
    assert asn1core.certificate_parts(respelled.raw).issuer != issuer_tlv
    assert asn1core.names_equal(respelled.issuer, served[3].subject)
    paths = candidates(served[0], [served[1], respelled, served[3]], [x1])
    assert [path_id(path) for path in paths] == [
        path_id([served[0], served[1], respelled, served[3]])
    ]


def test_der_bytes_are_accepted_directly(served: list, x1: asn1core.Certificate) -> None:
    paths = candidates(served[0].raw, [certificate.raw for certificate in served[1:]], [x1])
    assert [len(path) for path in paths] == [4]


def test_a_foreign_certificate_type_is_refused(served: list, x1: asn1core.Certificate) -> None:
    borrowed = x509.load_der_x509_certificate(served[0].raw)
    with pytest.raises(TypeError, match="asn1core"):
        candidates(borrowed, served[1:], [x1])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="anchor"):
        candidates(served[0], served[1:], ["CN=Some CA"])  # type: ignore[list-item]
