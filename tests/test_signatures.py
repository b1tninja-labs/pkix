"""RFC 5280 section 6.1.3 step (a)(1): the signature on the certificate verifies under the issuer key.

Two corpora. The real one is the Let's Encrypt chain and the ISRG cross-certificate in
`tests/fixtures`, signed years ago by other people's software: ECDSA P-384 with SHA-384 and RSA
PKCS #1 v1.5 with SHA-256. The synthetic one is minted here with `cryptography` for the families
the real corpus lacks (RSA-PSS, Ed25519, P-256 and P-521). pkix never signs, so a pass in either
means a different implementation's signature was accepted, and the mutations mean a different
implementation's verdict was matched.

The differential test is the one that would fail on a regression in the arithmetic path: it flips
bits in genuine certificates and requires pkix to agree with `cryptography` about every one.
"""

from __future__ import annotations

import datetime
import pathlib
import random
from collections.abc import Callable
from dataclasses import dataclass

import asn1core
import pytest
import sigwire.verify
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa, utils
from support import Minted, join, mint, parts, replace_everywhere, tlv

from pkix import _algorithms as alg
from pkix import errors
from pkix.validity import check_signature, check_signature_with_spki

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"


def real(*parts_: str) -> bytes:
    return FIX.joinpath(*parts_).read_bytes()


# ---------------------------------------------------------------- the real corpus


def test_the_served_chain_verifies_link_by_link() -> None:
    chain = [real("chains", f"letsencrypt.org-{i}.der") for i in range(4)]
    x1 = real("anchors", "isrg-root-x1.der")
    for child, parent in zip(chain, [*chain[1:], x1], strict=True):
        result = check_signature(child, parent)
        assert result.scheme in ("ecdsa", "rsa-pkcs1v15")
    leaf = check_signature(chain[0], chain[1])
    assert (leaf.scheme, leaf.hash_name, leaf.key) == ("ecdsa", "sha384", "P-384")
    cross = check_signature(chain[3], x1)
    assert (cross.scheme, cross.hash_name, cross.key) == ("rsa-pkcs1v15", "sha256", "RSA-4096")


def test_a_self_signed_root_verifies_under_its_own_key() -> None:
    x1 = real("anchors", "isrg-root-x1.der")
    assert check_signature(x1, x1).key == "RSA-4096"


def test_the_wrong_issuer_does_not_verify() -> None:
    chain = [real("chains", f"letsencrypt.org-{i}.der") for i in range(4)]
    with pytest.raises(errors.SignatureInvalid):
        check_signature(chain[0], chain[2])  # the leaf is signed by [1], not by [2]
    with pytest.raises(errors.SignatureInvalid):
        check_signature(chain[3], chain[3])  # a cross-certificate is not signed by itself


def test_the_signature_is_checked_over_the_stored_tbs_bytes() -> None:
    """RFC 5280 section 4.1.1.3: the signature covers the DER tbsCertificate that arrived."""
    chain = [
        asn1core.parse_certificate(real("chains", f"letsencrypt.org-{i}.der")) for i in range(2)
    ]
    top, _ = asn1core.decode(chain[0].raw, der=True)
    assert top.children[0].raw == chain[0].tbs_certificate
    assert check_signature(chain[0], chain[1])


# ---------------------------------------------------------------- the synthetic corpus


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048)


@dataclass(frozen=True)
class Case:
    name: str
    certificate: Minted
    verify_oracle: Callable[[bytes, bytes], None]


def _ec_oracle(key: ec.EllipticCurvePrivateKey, digest: hashes.HashAlgorithm):
    def oracle(signature: bytes, data: bytes) -> None:
        key.public_key().verify(signature, data, ec.ECDSA(digest))

    return oracle


def _rsa_oracle(
    key: rsa.RSAPrivateKey, digest: hashes.HashAlgorithm
) -> Callable[[bytes, bytes], None]:
    def oracle(signature: bytes, data: bytes) -> None:
        key.public_key().verify(signature, data, padding.PKCS1v15(), digest)

    return oracle


def _pss_oracle(
    key: rsa.RSAPrivateKey, digest: hashes.HashAlgorithm, salt: int
) -> Callable[[bytes, bytes], None]:
    def oracle(signature: bytes, data: bytes) -> None:
        key.public_key().verify(signature, data, _pss(digest, salt), digest)

    return oracle


def _pss(digest: hashes.HashAlgorithm, salt: int) -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(digest), salt_length=salt)


@pytest.fixture(scope="module")
def cases(rsa_key: rsa.RSAPrivateKey) -> list[Case]:
    out: list[Case] = []
    for digest in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
        out.append(
            Case(
                f"rsa-pkcs1-{digest.name}",
                mint(rsa_key, rsa_key, hash_algorithm=digest),
                _rsa_oracle(rsa_key, digest),
            )
        )
    for digest, salt in ((hashes.SHA256(), 32), (hashes.SHA384(), 48), (hashes.SHA256(), 0)):
        out.append(
            Case(
                f"rsa-pss-{digest.name}-salt{salt}",
                mint(rsa_key, rsa_key, hash_algorithm=digest, rsa_padding=_pss(digest, salt)),
                _pss_oracle(rsa_key, digest, salt),
            )
        )
    for curve, digest in (
        (ec.SECP256R1(), hashes.SHA256()),
        (ec.SECP256R1(), hashes.SHA384()),
        (ec.SECP384R1(), hashes.SHA384()),
        (ec.SECP521R1(), hashes.SHA512()),
    ):
        key = ec.generate_private_key(curve)
        out.append(
            Case(
                f"ecdsa-{curve.name}-{digest.name}",
                mint(key, key, hash_algorithm=digest),
                _ec_oracle(key, digest),
            )
        )
    ed = ed25519.Ed25519PrivateKey.generate()
    out.append(
        Case(
            "ed25519",
            mint(ed, ed),
            lambda sig, data: ed.public_key().verify(sig, data),
        )
    )
    return out


def test_every_synthetic_family_verifies(cases: list[Case]) -> None:
    for case in cases:
        result = check_signature(case.certificate.der, case.certificate.der)
        assert result.scheme in ("rsa-pkcs1v15", "rsa-pss", "ecdsa", "ed25519"), case.name
        # Whatever pkix accepted, the other implementation accepts over the same bytes.
        certificate = case.certificate.certificate
        case.verify_oracle(certificate.signature_value, certificate.tbs_certificate)


def test_the_result_names_what_verified(cases: list[Case]) -> None:
    by_name = {case.name: case.certificate.der for case in cases}
    pss = check_signature(by_name["rsa-pss-sha384-salt48"], by_name["rsa-pss-sha384-salt48"])
    assert (pss.scheme, pss.hash_name, pss.key, pss.algorithm) == (
        "rsa-pss",
        "sha384",
        "RSA-2048",
        "1.2.840.113549.1.1.10",
    )
    ed = check_signature(by_name["ed25519"], by_name["ed25519"])
    assert (ed.scheme, ed.hash_name, ed.key) == ("ed25519", None, "Ed25519")
    p521 = check_signature(by_name["ecdsa-secp521r1-sha512"], by_name["ecdsa-secp521r1-sha512"])
    assert p521.key == "P-521"


def test_differential_against_cryptography(cases: list[Case]) -> None:
    """Flip single bits in genuine certificates; pkix and `cryptography` must agree on each one.

    A flip may land in a length or a tag and stop the certificate parsing at all, which is not a
    verdict and is skipped. Everywhere else both implementations see the same tbs and signature
    bytes and must give the same answer, which for a flipped bit is always "invalid".
    """
    rng = random.Random(5280)
    compared = 0
    for case in cases:
        der = case.certificate.der
        top, _ = asn1core.decode(der, der=True)
        signature_start = len(der) - len(top.children[2].raw)
        positions = [rng.randrange(0, len(der)) for _ in range(12)]
        positions += [rng.randrange(signature_start + 4, len(der)) for _ in range(12)]
        for position in positions:
            mutated = bytearray(der)
            mutated[position] ^= 1 << rng.randrange(8)
            try:
                parsed = asn1core.parse_certificate(bytes(mutated))
            except asn1core.Asn1Error:
                continue
            if (
                parsed.signature_algorithm_raw
                != case.certificate.certificate.signature_algorithm_raw
            ):
                continue  # the oracle has its algorithm fixed; a changed one is not a comparison
            try:
                check_signature(parsed, case.certificate.certificate)
            except errors.SignatureInvalid:
                pkix_accepts = False
            except errors.PkixError:
                continue  # the flip hit the algorithm or key, which is a refusal and not a verdict
            else:
                pkix_accepts = True
            try:
                case.verify_oracle(parsed.signature_value, parsed.tbs_certificate)
            except (InvalidSignature, ValueError):
                oracle_accepts = False
            else:
                oracle_accepts = True
            assert pkix_accepts == oracle_accepts, f"{case.name}: byte {position}"
            assert not pkix_accepts, f"{case.name}: a flipped bit still verified at {position}"
            compared += 1
    assert compared >= 60, f"only {compared} mutations reached verification"


def test_a_truncated_or_padded_signature_is_invalid_not_an_error(cases: list[Case]) -> None:
    rsa_case = next(c for c in cases if c.name == "rsa-pkcs1-sha256").certificate
    tbs_content = parts(rsa_case.der)[0]
    algorithm, signature = (
        rsa_case.certificate.signature_algorithm_raw,
        rsa_case.certificate.signature_value,
    )
    for broken in (
        signature[:-1],
        b"\x00" + signature,
        signature + b"\x00",
        b"\x00" * len(signature),
    ):
        # The unused-bits octet of the BIT STRING is part of the TLV, so rebuild it.
        forged = join(tbs_content, algorithm + tlv(0x03, b"\x00" + broken))
        with pytest.raises(errors.SignatureInvalid):
            check_signature(forged, rsa_case.der)


# ---------------------------------------------------------------- RFC 5280 section 4.1.1.2


def test_outer_and_inner_signature_algorithms_must_match(cases: list[Case]) -> None:
    ecdsa = next(c for c in cases if c.name == "ecdsa-secp256r1-sha256").certificate
    sha256 = bytes.fromhex("300a06082a8648ce3d040302")
    sha384 = bytes.fromhex("300a06082a8648ce3d040303")
    tbs_content, rest = parts(ecdsa.der)
    assert sha256 in rest
    swapped = join(tbs_content, rest.replace(sha256, sha384))
    with pytest.raises(errors.SignatureInvalid, match=r"4\.1\.1\.2"):
        check_signature(swapped, ecdsa.der)


# ---------------------------------------------------------------- RFC 9925


UNSIGNED = bytes.fromhex("300a06082b06010505070624")


def test_an_unsigned_certificate_is_refused_as_a_path_signature(cases: list[Case]) -> None:
    """RFC 9925 section 4: id-alg-unsigned is always invalid and a validator MUST reject it."""
    ecdsa = next(c for c in cases if c.name == "ecdsa-secp256r1-sha256").certificate
    sha256 = bytes.fromhex("300a06082a8648ce3d040302")
    tbs_content, _ = parts(ecdsa.der)
    # Section 3.1: both algorithm fields carry id-alg-unsigned, parameters omitted, and the
    # signatureValue is a zero-length BIT STRING.
    unsigned = join(tbs_content.replace(sha256, UNSIGNED), UNSIGNED + bytes.fromhex("030100"))
    parsed = asn1core.parse_certificate(unsigned)
    assert parsed.signature_algorithm == (1, 3, 6, 1, 5, 5, 7, 6, 36)
    with pytest.raises(errors.UnsignedCertificate, match="9925"):
        check_signature(unsigned, ecdsa.der)
    # It is also a SignatureUnsupported, as section 4 recommends treating it as an unknown algorithm.
    with pytest.raises(errors.SignatureUnsupported):
        check_signature(unsigned, unsigned)


def test_an_unknown_signature_algorithm_is_unsupported_not_invalid(cases: list[Case]) -> None:
    ecdsa = next(c for c in cases if c.name == "ecdsa-secp256r1-sha256").certificate
    sha256 = bytes.fromhex("300a06082a8648ce3d040302")
    unknown = bytes.fromhex("300a06082a0304050607080a")  # 1.2.3.4.5.6.7.8.10
    forged = replace_everywhere(ecdsa.der, sha256, unknown)
    with pytest.raises(errors.SignatureUnsupported) as excinfo:
        check_signature(forged, ecdsa.der)
    assert not isinstance(excinfo.value, errors.UnsignedCertificate)


# ---------------------------------------------------------------- parameters, per document


def test_ecdsa_parameters_must_be_absent() -> None:
    """RFC 5758 section 3.2: the encoding MUST omit the parameters field."""
    with pytest.raises(errors.MalformedAlgorithm, match="5758"):
        alg.decode_signature_algorithm(
            bytes.fromhex("300c06082a8648ce3d04030205 00".replace(" ", ""))
        )


def test_rsa_pkcs1_parameters_may_be_null_or_absent() -> None:
    """RFC 4055 section 5: parameters MUST be NULL and implementations MUST accept them absent."""
    for encoded in ("300d06092a864886f70d01010b0500", "300b06092a864886f70d01010b"):
        scheme = alg.decode_signature_algorithm(bytes.fromhex(encoded))
        assert (scheme.scheme, scheme.hash_name) == (alg.RSA_PKCS1V15, "sha256")
    with pytest.raises(errors.MalformedAlgorithm):
        alg.decode_signature_algorithm(bytes.fromhex("300e06092a864886f70d01010b0401aa"))


def test_ed25519_parameters_must_be_absent() -> None:
    """RFC 8410 section 6."""
    assert alg.decode_signature_algorithm(bytes.fromhex("300506032b6570")).scheme == alg.ED25519
    with pytest.raises(errors.MalformedAlgorithm, match="8410"):
        alg.decode_signature_algorithm(bytes.fromhex("300706032b65700500"))


_PSS_OID = bytes.fromhex("06092a864886f70d01010a")


def _pss_algorithm(*fields: bytes) -> bytes:
    return tlv(0x30, _PSS_OID + tlv(0x30, b"".join(fields)))


def _explicit(number: int, inner: bytes) -> bytes:
    return tlv(0xA0 | number, inner)


_SHA256_ID = tlv(0x30, bytes.fromhex("0609608648016503040201") + bytes.fromhex("0500"))
_MGF1_SHA256 = tlv(0x30, bytes.fromhex("06092a864886f70d010108") + _SHA256_ID)


def test_pss_parameters_are_read_with_their_defaults() -> None:
    """RFC 4055 section 3.1: absent fields stand for SHA-1, MGF1 with SHA-1, 20 and trailer 1."""
    defaults = alg.decode_signature_algorithm(_pss_algorithm())
    assert (defaults.hash_name, defaults.mgf_hash, defaults.salt_length) == ("sha1", "sha1", 20)
    full = alg.decode_signature_algorithm(
        _pss_algorithm(
            _explicit(0, _SHA256_ID),
            _explicit(1, _MGF1_SHA256),
            _explicit(2, tlv(0x02, b"\x20")),
            _explicit(3, tlv(0x02, b"\x01")),
        )
    )
    assert (full.hash_name, full.mgf_hash, full.salt_length) == ("sha256", "sha256", 32)


def test_pss_parameters_that_break_the_document_are_refused() -> None:
    with pytest.raises(errors.MalformedAlgorithm, match="required"):
        alg.decode_signature_algorithm(tlv(0x30, _PSS_OID))
    with pytest.raises(errors.MalformedAlgorithm, match="trailerField"):
        alg.decode_signature_algorithm(_pss_algorithm(_explicit(3, tlv(0x02, b"\x02"))))
    with pytest.raises(errors.MalformedAlgorithm, match="out of order"):
        alg.decode_signature_algorithm(
            _pss_algorithm(_explicit(2, tlv(0x02, b"\x20")), _explicit(0, _SHA256_ID))
        )
    with pytest.raises(errors.MalformedAlgorithm, match="maskGenAlgorithm"):
        alg.decode_signature_algorithm(_pss_algorithm(_explicit(1, _SHA256_ID)))
    md5 = tlv(0x30, bytes.fromhex("06082a864886f70d0205") + bytes.fromhex("0500"))
    with pytest.raises(errors.SignatureUnsupported, match="hash"):
        alg.decode_signature_algorithm(_pss_algorithm(_explicit(0, md5)))


# ---------------------------------------------------------------- keys


def test_a_signature_cannot_verify_under_a_key_of_another_family(cases: list[Case]) -> None:
    rsa_cert = next(c for c in cases if c.name == "rsa-pkcs1-sha256").certificate
    ec_cert = next(c for c in cases if c.name == "ecdsa-secp256r1-sha256").certificate
    with pytest.raises(errors.SignatureInvalid, match="not RSA"):
        check_signature(rsa_cert.der, ec_cert.der)
    with pytest.raises(errors.SignatureInvalid, match="not an EC key"):
        check_signature(ec_cert.der, rsa_cert.der)


def test_an_ec_key_off_the_curve_is_malformed_not_a_verdict(cases: list[Case]) -> None:
    ec_cert = next(c for c in cases if c.name == "ecdsa-secp256r1-sha256").certificate
    spki = ec_cert.certificate.subject_public_key_info
    broken = spki[:-1] + bytes([spki[-1] ^ 0x01])
    with pytest.raises(errors.MalformedAlgorithm, match="not a point"):
        check_signature_with_spki(ec_cert.der, broken)


def _ec_spki(point: bytes, curve_oid: str = "06082a8648ce3d030107") -> bytes:
    algorithm = tlv(0x30, bytes.fromhex("06072a8648ce3d0201" + curve_oid))
    return tlv(0x30, algorithm + tlv(0x03, b"\x00" + point))


def test_ec_point_forms_follow_rfc_5480_section_2_2() -> None:
    x = bytes(range(1, 33))
    assert isinstance(alg.decode_public_key(_ec_spki(b"\x04" + x + x)), alg.EcKey)
    with pytest.raises(errors.SignatureUnsupported, match="compressed"):
        alg.decode_public_key(_ec_spki(b"\x02" + x))
    with pytest.raises(errors.MalformedAlgorithm, match="first octet"):
        alg.decode_public_key(_ec_spki(b"\x06" + x + x))  # hybrid form MUST NOT be used
    with pytest.raises(errors.MalformedAlgorithm, match="octets"):
        alg.decode_public_key(_ec_spki(b"\x04" + x))
    with pytest.raises(errors.SignatureUnsupported, match="curve"):
        alg.decode_public_key(_ec_spki(b"\x04" + x + x, "06052b81040021"))  # secp224r1


def test_rsa_key_parameters_must_be_null() -> None:
    """RFC 3279 section 2.3.1 and RFC 4055 section 6."""
    rsa_public = tlv(0x30, tlv(0x02, b"\x00\xc5" + b"\x01" * 255) + tlv(0x02, b"\x01\x00\x01"))
    good = tlv(
        0x30,
        tlv(0x30, bytes.fromhex("06092a864886f70d0101010500")) + tlv(0x03, b"\x00" + rsa_public),
    )
    assert isinstance(alg.decode_public_key(good), alg.RsaKey)
    absent = tlv(
        0x30, tlv(0x30, bytes.fromhex("06092a864886f70d010101")) + tlv(0x03, b"\x00" + rsa_public)
    )
    with pytest.raises(errors.MalformedAlgorithm, match="NULL"):
        alg.decode_public_key(absent)


# ---------------------------------------------------------------- policy


def test_policy_refusals_are_not_verdicts(rsa_key: rsa.RSAPrivateKey) -> None:
    small = rsa.generate_private_key(65537, 1024)  # noqa: S505 - the point of the test
    weak = mint(small, small)
    with pytest.raises(errors.SignaturePolicyRefused, match="2048"):
        check_signature(weak.der, weak.der)
    # The legacy policy opens it, and the answer is then the signature's own.
    assert check_signature(weak.der, weak.der, policy=sigwire.verify.LEGACY).key == "RSA-1024"

    # cryptography will not build a SHA-1 certificate, so swap the algorithm of a minted one and
    # sign its tbs with the low-level RSA call, which does still take SHA-1.
    sha256_rsa = bytes.fromhex("300d06092a864886f70d01010b0500")
    sha1_rsa = bytes.fromhex("300d06092a864886f70d0101050500")
    base = mint(rsa_key, rsa_key)
    tbs_content, _ = parts(base.der)
    tbs_content = tbs_content.replace(sha256_rsa, sha1_rsa)
    signature = rsa_key.sign(tlv(0x30, tbs_content), padding.PKCS1v15(), hashes.SHA1())  # noqa: S303
    sha1_cert = join(tbs_content, sha1_rsa + tlv(0x03, b"\x00" + signature))
    with pytest.raises(errors.SignaturePolicyRefused, match="sha1"):
        check_signature(sha1_cert, base.der)
    legacy = check_signature(sha1_cert, base.der, policy=sigwire.verify.LEGACY)
    assert (legacy.hash_name, legacy.deprecated) == ("sha1", True)


def test_a_policy_refusal_is_a_pkix_error_and_not_an_invalid_signature(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    assert not issubclass(errors.SignaturePolicyRefused, errors.SignatureInvalid)
    assert not issubclass(errors.SignatureUnsupported, errors.SignatureInvalid)
    assert issubclass(errors.SignaturePolicyRefused, errors.PkixError)


# ---------------------------------------------------------------- ECDSA encoding


def test_ecdsa_signature_encoding_is_strict_der() -> None:
    good = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x02, b"\x02"))
    assert alg.decode_ecdsa_signature(good) == (1, 2)
    for bad in (
        good + b"\x00",  # trailing octet
        tlv(0x30, tlv(0x02, b"\x00\x01") + tlv(0x02, b"\x02")),  # non-minimal integer
        tlv(0x30, tlv(0x02, b"\x00") + tlv(0x02, b"\x02")),  # r = 0
        tlv(0x30, tlv(0x02, b"\x81") + tlv(0x02, b"\x02")),  # negative r
        tlv(0x30, tlv(0x02, b"\x01")),  # one integer
        b"\x30\x80\x02\x01\x01\x02\x01\x02\x00\x00",  # BER indefinite length
        b"",
    ):
        assert alg.decode_ecdsa_signature(bad) is None


def test_ecdsa_signature_with_s_replaced_by_n_minus_s_is_a_different_signature(
    cases: list[Case],
) -> None:
    """The malleated twin (r, n - s) verifies under bare ECDSA; pkix reports what the arithmetic
    says and does not pretend to reject it, so a caller that needs non-malleability must say so
    elsewhere. The test pins that this is the behaviour and that both forms are strictly DER."""
    case = next(c for c in cases if c.name == "ecdsa-secp256r1-sha256").certificate
    r, s = utils.decode_dss_signature(case.certificate.signature_value)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    twin = utils.encode_dss_signature(r, order - s)
    top, _ = asn1core.decode(case.der, der=True)
    twin_cert = join(
        top.children[0].content(),
        case.certificate.signature_algorithm_raw + tlv(0x03, b"\x00" + twin),
    )
    assert check_signature(twin_cert, case.der).scheme == "ecdsa"


# ---------------------------------------------------------------- the OID table, read from the documents


def test_every_signature_oid_maps_to_the_hash_its_document_names() -> None:
    """OIDs from RFC 3279 section 2.2.1 and 2.2.3, RFC 4055 section 5 and RFC 5758 section 3.2.

    The sha224 row is the one RFC 8017 appendix A.2.4 misprints: the RFC text labels
    `sha224WithRSAEncryption` "SHA-256" (verified erratum 5154, corrected to SHA-224). RFC 4055
    section 5 gives it as { pkcs-1 14 }, which is what the table must say, so a table copied from the
    appendix instead of the erratum fails here.
    """
    rsa = {
        "2a864886f70d010105": "sha1",
        "2a864886f70d01010e": "sha224",
        "2a864886f70d01010b": "sha256",
        "2a864886f70d01010c": "sha384",
        "2a864886f70d01010d": "sha512",
    }
    for oid_hex, hash_name in rsa.items():
        scheme = alg.decode_signature_algorithm(
            tlv(0x30, tlv(0x06, bytes.fromhex(oid_hex)) + b"\x05\x00")
        )
        assert (scheme.scheme, scheme.hash_name) == (alg.RSA_PKCS1V15, hash_name), oid_hex
    ecdsa = {
        "2a8648ce3d0401": "sha1",
        "2a8648ce3d040301": "sha224",
        "2a8648ce3d040302": "sha256",
        "2a8648ce3d040303": "sha384",
        "2a8648ce3d040304": "sha512",
    }
    for oid_hex, hash_name in ecdsa.items():
        scheme = alg.decode_signature_algorithm(tlv(0x30, tlv(0x06, bytes.fromhex(oid_hex))))
        assert (scheme.scheme, scheme.hash_name) == (alg.ECDSA, hash_name), oid_hex
    # RFC 3279 section 2.2.2 and RFC 5758 section 3.1: parameters SHALL be omitted.
    dsa_ids = {
        "2a8648ce380403": "sha1",
        "608648016503040301": "sha224",
        "608648016503040302": "sha256",
    }
    for oid_hex, hash_name in dsa_ids.items():
        scheme = alg.decode_signature_algorithm(tlv(0x30, tlv(0x06, bytes.fromhex(oid_hex))))
        assert (scheme.scheme, scheme.hash_name) == (alg.DSA, hash_name), oid_hex
        with pytest.raises(errors.MalformedAlgorithm, match="SHALL be omitted"):
            alg.decode_signature_algorithm(
                tlv(0x30, tlv(0x06, bytes.fromhex(oid_hex)) + b"\x05\x00")
            )


# ---------------------------------------------------------------- algorithms.rehome


def test_public_keys_are_read_by_asn1core_parse_spki(monkeypatch: pytest.MonkeyPatch) -> None:
    """Row `algorithms.rehome`: `decode_public_key` reads the SPKI through `asn1core.keys`, so a
    rule asn1core enforces (here RFC 3279 section 2.3.2's NULL refusal for DSA) is pkix's too."""
    import asn1core.keys

    seen: list[bytes] = []
    real_parse = asn1core.keys.parse_spki

    def spy(buffer: bytes, *, der: bool = True) -> asn1core.keys.SubjectPublicKeyInfo:
        seen.append(buffer)
        return real_parse(buffer, der=der)

    monkeypatch.setattr(asn1core.keys, "parse_spki", spy)
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    spki = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert isinstance(alg.decode_public_key(spki), alg.EcKey)
    assert seen == [spki]
    dsa_null = tlv(
        0x30,
        tlv(0x30, bytes.fromhex("06072a8648ce380401") + b"\x05\x00")
        + tlv(0x03, b"\x00" + tlv(0x02, b"\x05")),
    )
    with pytest.raises(errors.MalformedAlgorithm, match="never NULL"):
        alg.decode_public_key(dsa_null)


# ---------------------------------------------------------------- algorithms.dsa

# 1024/160 is the smallest (L, N) pair of FIPS 186-4 that sigwire's LEGACY admits, and the fastest to
# generate; these keys only ever sign test certificates.
_DSA_ROOT = dsa.generate_private_key(key_size=1024)  # noqa: S505


def _dsa_spki_without_parameters(key: dsa.DSAPublicKey) -> bytes:
    """RFC 3279 section 2.3.2: an id-dsa AlgorithmIdentifier of one component, the key an INTEGER."""
    y = key.public_numbers().y
    integer = tlv(0x02, y.to_bytes(y.bit_length() // 8 + 1, "big"))
    return tlv(0x30, tlv(0x30, bytes.fromhex("06072a8648ce380401")) + tlv(0x03, b"\x00" + integer))


def test_dsa_is_refused_by_the_strict_policy_and_verified_under_legacy() -> None:
    """Row `algorithms.dsa`: PORTFOLIO.md section 9 item 15 (the sigwire decision) keeps DSA out of
    `sigwire.verify.DEFAULT` and in `LEGACY`."""
    leaf_key = _DSA_ROOT.parameters().generate_private_key()
    leaf = mint(leaf_key, _DSA_ROOT, subject="leaf", issuer="root")
    root = mint(_DSA_ROOT, _DSA_ROOT, subject="root", issuer="root")
    with pytest.raises(errors.SignaturePolicyRefused, match="dsa"):
        check_signature(leaf.der, root.der)
    result = check_signature(leaf.der, root.der, policy=sigwire.verify.LEGACY)
    assert (result.scheme, result.hash_name, result.key) == ("dsa", "sha256", "DSA-1024/160")
    tbs_content, rest = parts(leaf.der)
    flipped = join(tbs_content[:-1] + bytes([tbs_content[-1] ^ 1]), rest)
    with pytest.raises(errors.SignatureInvalid):
        check_signature(flipped, root.der, policy=sigwire.verify.LEGACY)


def test_dsa_parameters_are_inherited_along_the_path() -> None:
    """RFC 3279 section 2.3.2 and RFC 5280 section 6.1.4(e): a DSA key that omits its parameters
    takes the issuer's. The CA certificate below carries a parameterless SPKI, re-signed by the
    root, and the leaf it signs validates only with the root's parameters."""
    from pkix.anchors import load_anchor
    from pkix.result import PathInputs, path_walk

    ca_key = _DSA_ROOT.parameters().generate_private_key()
    root = mint(_DSA_ROOT, _DSA_ROOT, subject="root", issuer="root")
    ca = mint(ca_key, _DSA_ROOT, subject="ca", issuer="root")
    full_spki = ca.certificate.subject_public_key_info
    bare_spki = _dsa_spki_without_parameters(ca_key.public_key())
    tbs_content, _rest = parts(ca.der)
    tbs = tlv(0x30, tbs_content.replace(full_spki, bare_spki))
    signature = _DSA_ROOT.sign(tbs, hashes.SHA256())
    top, _ = asn1core.decode(ca.der, der=True)
    bare_ca = tlv(0x30, tbs + top.children[1].raw + tlv(0x03, b"\x00" + signature))
    leaf_key = _DSA_ROOT.parameters().generate_private_key()
    leaf = mint(leaf_key, ca_key, subject="leaf", issuer="ca")

    anchor = load_anchor(root.der)
    at = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
    legacy = PathInputs(signature_policy=sigwire.verify.LEGACY)
    result = path_walk([leaf.der, bare_ca], anchor, at, legacy)
    assert result.valid, result.steps
    # Section 6.1.5(d): the target carries parameters of its own, and those are the output.
    assert result.working_public_key_parameters is not None
    assert result.working_public_key_parameters.q == leaf_key.parameters().parameter_numbers().q
    # The same CA key with nothing to inherit from cannot verify the leaf.
    with pytest.raises(errors.MalformedAlgorithm, match="none are inherited"):
        check_signature_with_spki(leaf.der, bare_spki, policy=sigwire.verify.LEGACY)
    # Under the strict default the path stops at the first DSA signature.
    strict = path_walk([leaf.der, bare_ca], anchor, at)
    assert strict.status == "invalid"
    assert strict.failure is not None
    assert "signature policy" in strict.failure.detail
