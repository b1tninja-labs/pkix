"""Obligation tests: one named behaviour, one fixture, one assertion set.

The fixtures are recorded real certificates, not synthetic ones, because the behaviour under
test is about what real trust anchors look like. `isrg-root-x1.der` is a self-signed RSA root;
`isrg-root-x2-cross-signed.der` is ISRG Root X2's key issued by ISRG Root X1, which is the
interesting case for RFC 5280 sec. 6.1.1: it is a legal trust anchor that is **not**
self-signed, its subject differs from its issuer, and its signature algorithm (rsaEncryption,
from the signing CA) differs from the algorithm in its own subjectPublicKeyInfo
(id-ecPublicKey). Anything that reads the wrong field of the certificate fails here.
"""

from __future__ import annotations

import pathlib

import pytest

from pkix.anchors import Subtree, load_anchor

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "anchors"

# From RFC 5912's ALGORITHM module, read rather than recalled:
#   rsaEncryption  ::= iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 1
#   id-ecPublicKey ::= iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"

ROOT_X1 = "CN=ISRG Root X1,O=Internet Security Research Group,C=US"
ROOT_X2 = "CN=ISRG Root X2,O=Internet Security Research Group,C=US"


def der(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_a_trust_anchor_carries_the_name_and_key_that_sec_611_requires():
    """Sec. 6.1.1(d): trusted issuer name, public key algorithm, public key, and the
    certificate it came from so a caller can re-derive anything else it needs."""
    anchor = load_anchor(der("isrg-root-x1.der"), None)
    assert anchor.issuer.rfc4514() == ROOT_X1
    assert anchor.algorithm == RSA_ENCRYPTION
    # The key is the RSAPublicKey SEQUENCE the SPKI's BIT STRING carries, as stored bytes.
    assert anchor.public_key[:1] == b"0"
    assert anchor.public_key in anchor.spki
    assert anchor.certificate == der("isrg-root-x1.der")


def test_the_trusted_issuer_name_is_the_subject_and_not_the_issuer_field():
    """Sec. 6.1.1: "the name in the subject field is used as the trusted issuer name"."""
    anchor = load_anchor(der("isrg-root-x2-cross-signed.der"), None)
    assert anchor.issuer.rfc4514() == ROOT_X2
    # ...and the key algorithm is the one in the SPKI, not the one that signed the
    # certificate -- this cross-certificate was signed with RSA by X1 but carries an EC key.
    assert anchor.algorithm == ID_EC_PUBLIC_KEY
    # An EC key needs its curve; the algorithm parameters are input (4).
    assert anchor.parameters


def test_an_anchor_that_is_not_self_signed_is_still_an_anchor_and_says_which_it_is():
    """Sec. 6.1.1 offers a self-signed certificate as one way to supply the information; it
    is not a requirement, so a cross-certificate loads and the flag records the difference
    rather than the loader refusing a legal input."""
    root = load_anchor(der("isrg-root-x1.der"), None)
    cross = load_anchor(der("isrg-root-x2-cross-signed.der"), None)
    assert root.self_signed is True
    assert cross.self_signed is False


def test_a_name_restriction_becomes_a_permitted_subtree_of_its_own_name_type():
    """Sec. 6.1.1(h) gives initial-permitted-subtrees "for each name type (e.g., X.500
    distinguished names, email addresses, or IP addresses)", so a single string argument has
    to be resolved to one of them rather than treated as a string to compare."""
    dn = load_anchor(der("isrg-root-x1.der"), "O=Example, C=US")
    assert dn.permitted_subtrees == (Subtree("directoryName", "O=Example, C=US"),)

    email = load_anchor(der("isrg-root-x1.der"), "corp@example.com")
    assert email.permitted_subtrees == (Subtree("rfc822Name", "corp@example.com"),)

    ip = load_anchor(der("isrg-root-x1.der"), "198.51.100.0/24")
    assert ip.permitted_subtrees == (Subtree("IPAddress", "198.51.100.0/24"),)

    # An explicit name type wins over the guess.
    explicit = load_anchor(der("isrg-root-x1.der"), "email:corp@example.com")
    assert explicit.permitted_subtrees == (Subtree("rfc822Name", "corp@example.com"),)


def test_an_ambiguous_restriction_is_refused_rather_than_guessed_at():
    """A bare DNS name is not one of the name types sec. 6.1.1(h) enumerates, and silently
    reading it as a domain or as an RFC 822 mailbox both produce an anchor that validates the
    wrong thing."""
    with pytest.raises(ValueError, match="cannot tell which name type"):
        load_anchor(der("isrg-root-x1.der"), "example.com")
    with pytest.raises(ValueError, match="restricts nothing"):
        load_anchor(der("isrg-root-x1.der"), "")


def test_bytes_that_are_not_a_certificate_are_refused():
    with pytest.raises(ValueError, match="not a DER certificate"):
        load_anchor(b"not a certificate", None)
