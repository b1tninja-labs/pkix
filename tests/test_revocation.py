"""RFC 9608 noRevAvail, RFC 10007 cRLSign, and the CRL signature (RFC 5280 sections 5.1.1 and 6.3.3)."""

from __future__ import annotations

import dataclasses
import datetime

import asn1core
import pytest
from builders import KEY, NOT_BEFORE, certificate, dn, oid
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from pkix import errors, revocation

NO_REV_AVAIL = oid("2.5.29.56")
NULL = b"\x05\x00"


def no_rev_avail(value: bytes = NULL, critical: bool = False):
    return x509.UnrecognizedExtension(NO_REV_AVAIL, value), critical


def test_no_rev_avail_skips_revocation_checking():
    """RFC 9608 sec. 4: with noRevAvail present, "Step (a)(3) is skipped"."""
    leaf = certificate(dn("leaf"), dn("ca"), [no_rev_avail()])
    assert revocation.skips_revocation(leaf) == "noRevAvail"


def test_ocsp_nocheck_skips_revocation_checking_too():
    """RFC 9608 sec. 4: "or the ocsp-nocheck certificate extension [RFC6960] is present"."""
    leaf = certificate(dn("responder"), dn("ca"), [(x509.OCSPNoCheck(), False)])
    assert revocation.skips_revocation(leaf) == "ocsp-nocheck"


def test_an_ordinary_certificate_is_not_skipped():
    assert revocation.skips_revocation(certificate(dn("leaf"), dn("ca"))) is None


def test_no_rev_avail_must_be_the_der_null():
    """RFC 9608 sec. 2: syntax NULL, "'0500'H is the DER encoding"."""
    leaf = certificate(dn("leaf"), dn("ca"), [no_rev_avail(b"\x05\x01\x00")])
    with pytest.raises(errors.MalformedExtension, match="NULL"):
        revocation.skips_revocation(leaf)


def test_no_rev_avail_on_a_ca_is_invalid():
    """RFC 9608 sec. 3: such a certificate "MUST NOT also include the basic constraints ... cA TRUE"."""
    ca = certificate(
        dn("ca"),
        dn("root"),
        [(x509.BasicConstraints(ca=True, path_length=None), True), no_rev_avail()],
    )
    with pytest.raises(revocation.ProfileViolationError, match="CA certificate"):
        revocation.skips_revocation(ca)


def test_no_rev_avail_with_crl_distribution_points_is_invalid():
    """RFC 9608 sec. 3: and "MUST NOT also include the CRL Distribution Points" extension."""
    dp = x509.DistributionPoint(
        [x509.UniformResourceIdentifier("http://example.com/crl")], None, None, None
    )
    leaf = certificate(
        dn("leaf"), dn("ca"), [(x509.CRLDistributionPoints([dp]), False), no_rev_avail()]
    )
    with pytest.raises(revocation.ProfileViolationError, match="distribution points"):
        revocation.skips_revocation(leaf)


def test_no_rev_avail_with_freshest_crl_is_invalid():
    dp = x509.DistributionPoint(
        [x509.UniformResourceIdentifier("http://example.com/delta")], None, None, None
    )
    leaf = certificate(dn("leaf"), dn("ca"), [(x509.FreshestCRL([dp]), False), no_rev_avail()])
    with pytest.raises(revocation.ProfileViolationError, match="freshest"):
        revocation.skips_revocation(leaf)


def test_no_rev_avail_with_an_ocsp_access_method_is_invalid_but_ca_issuers_is_fine():
    """RFC 9608 sec. 3: the AIA extension "MUST NOT include an id-ad-ocsp accessMethod"."""
    from cryptography.x509.oid import AuthorityInformationAccessOID as AccessOid

    ocsp = x509.AccessDescription(
        AccessOid.OCSP, x509.UniformResourceIdentifier("http://ocsp.example.com")
    )
    issuers = x509.AccessDescription(
        AccessOid.CA_ISSUERS, x509.UniformResourceIdentifier("http://example.com/ca.der")
    )
    bad = certificate(
        dn("leaf"),
        dn("ca"),
        [(x509.AuthorityInformationAccess([issuers, ocsp]), False), no_rev_avail()],
    )
    with pytest.raises(revocation.ProfileViolationError, match="id-ad-ocsp"):
        revocation.skips_revocation(bad)
    good = certificate(
        dn("leaf"), dn("ca"), [(x509.AuthorityInformationAccess([issuers]), False), no_rev_avail()]
    )
    assert revocation.skips_revocation(good) == "noRevAvail"


# --- RFC 10007 ------------------------------------------------------------------------------


def _usage(**bits: bool) -> tuple[x509.ExtensionType, bool]:
    base = {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
    base.update(bits)
    return x509.KeyUsage(**base), True


def test_a_v3_crl_issuer_with_crl_sign_passes():
    issuer = certificate(dn("ca"), dn("root"), [_usage(crl_sign=True, key_cert_sign=True)])
    result = revocation.check_crl_issuer_key_usage(issuer)
    assert (result.ok, result.reason) == (True, "ok")


def test_a_v3_crl_issuer_without_key_usage_now_fails():
    """RFC 10007 sec. 4: for a v3 issuer, "verify that the key usage extension is present"; the old
    step (f) of RFC 5280 sec. 6.3.3 accepted its absence."""
    issuer = certificate(dn("ca"), dn("root"))
    assert issuer.version == 2
    result = revocation.check_crl_issuer_key_usage(issuer)
    assert (result.ok, result.reason) == (False, "no_key_usage")


def test_a_v3_crl_issuer_whose_key_usage_lacks_crl_sign_fails():
    issuer = certificate(dn("ca"), dn("root"), [_usage(key_cert_sign=True)])
    result = revocation.check_crl_issuer_key_usage(issuer)
    assert (result.ok, result.reason) == (False, "no_crl_sign")


def test_a_v1_or_v2_crl_issuer_is_exempt():
    """RFC 10007 sec. 4: "this check is not performed if the CRL issuer's key is certified using a
    version 1 (v1) or version 2 (v2) X.509 certificate"."""
    base = certificate(dn("ca"), dn("root"))
    for version in (0, 1):
        legacy = dataclasses.replace(base, version=version)
        result = revocation.check_crl_issuer_key_usage(legacy)
        assert (result.ok, result.reason) == (True, "exempt_v1_v2")


def test_the_key_usage_bits_are_read_by_name():
    from pkix.extensions import key_usage

    cert = certificate(
        dn("ca"), dn("root"), [_usage(digital_signature=True, crl_sign=True, decipher_only=False)]
    )
    assert key_usage(cert) == {"digitalSignature", "cRLSign"}
    assert key_usage(certificate(dn("x"), dn("y"))) is None


# --- CRL signature ----------------------------------------------------------------------------


def _crl(key=KEY, revoked: int | None = 7) -> bytes:
    now = NOT_BEFORE
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(dn("ca"))
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )
    if revoked is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(revoked).revocation_date(now).build()
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


def test_a_crl_signature_verifies_under_the_issuer_key():
    crl = asn1core.parse_crl(_crl())
    issuer = certificate(dn("ca"), dn("root"))
    result = revocation.check_crl_signature(crl, issuer.subject_public_key_info)
    assert result.scheme == "ecdsa"
    assert crl.revoked_serials == (7,)


def test_a_crl_signature_does_not_verify_under_another_key():
    other = ec.generate_private_key(ec.SECP256R1())
    crl = asn1core.parse_crl(_crl(key=other))
    issuer = certificate(dn("ca"), dn("root"))
    with pytest.raises(errors.SignatureInvalid):
        revocation.check_crl_signature(crl, issuer.subject_public_key_info)


def test_a_tampered_crl_fails_its_signature():
    """The signed bytes are the stored tbsCertList slice: one flipped serial octet must be caught."""
    raw = bytearray(_crl())
    index = raw.rindex(b"\x02\x01\x07")  # the revoked serial INTEGER 7
    raw[index + 2] = 0x08
    crl = asn1core.parse_crl(bytes(raw))
    assert crl.revoked_serials == (8,)
    issuer = certificate(dn("ca"), dn("root"))
    with pytest.raises(errors.SignatureInvalid):
        revocation.check_crl_signature(crl, issuer.subject_public_key_info)


def test_a_crl_whose_two_algorithm_fields_differ_is_refused():
    """RFC 5280 sec. 5.1.1.2: signatureAlgorithm "MUST contain the same algorithm identifier as the
    signature field in the sequence tbsCertList"."""
    crl = asn1core.parse_crl(_crl())
    forged = dataclasses.replace(
        crl,
        signature_algorithm_raw=crl.signature_algorithm_raw.replace(b"\x03", b"\x04", 1),
    )
    issuer = certificate(dn("ca"), dn("root"))
    with pytest.raises(errors.SignatureInvalid, match="CRL"):
        revocation.check_crl_signature(forged, issuer.subject_public_key_info)
