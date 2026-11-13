"""RFC 5280 section 6.1.3 step (a)(2): the validity period includes the current time.

Section 4.1.2.5: "The validity period for a certificate is the period of time from notBefore
through notAfter, inclusive." The boundary tests are the ones that fail if an off-by-one slips in;
the rest pin what the result says about the dates it read.
"""

from __future__ import annotations

import datetime
import pathlib

import asn1core
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from support import join, mint, parts

from pkix import errors
from pkix.validity import check_validity

UTC = datetime.UTC
FIX = pathlib.Path(__file__).resolve().parent / "fixtures"

NOT_BEFORE = datetime.datetime(2024, 1, 1, 0, 0, 0)
NOT_AFTER = datetime.datetime(2034, 1, 1, 12, 30, 45)
SECOND = datetime.timedelta(seconds=1)


@pytest.fixture(scope="module")
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def cert(key: ec.EllipticCurvePrivateKey) -> bytes:
    return mint(key, key, not_before=NOT_BEFORE, not_after=NOT_AFTER).der


def test_validity_period_boundaries_are_inclusive(cert: bytes) -> None:
    not_before = NOT_BEFORE.replace(tzinfo=UTC)
    not_after = NOT_AFTER.replace(tzinfo=UTC)

    at_start = check_validity(cert, not_before)
    assert (at_start.ok, at_start.reason) == (True, "ok")
    at_end = check_validity(cert, not_after)
    assert (at_end.ok, at_end.reason) == (True, "ok")

    early = check_validity(cert, not_before - SECOND)
    assert (early.ok, early.reason) == (False, "not_yet_valid")
    late = check_validity(cert, not_after + SECOND)
    assert (late.ok, late.reason) == (False, "expired")
    # An instant between two whole seconds is still after notAfter: nothing is rounded away.
    sliver = check_validity(cert, not_after + datetime.timedelta(microseconds=1))
    assert sliver.reason == "expired"


def test_the_result_carries_the_dates_it_decided_from(cert: bytes) -> None:
    result = check_validity(cert, datetime.datetime(2030, 6, 1, tzinfo=UTC))
    assert result.not_before == NOT_BEFORE.replace(tzinfo=UTC)
    assert result.not_after == NOT_AFTER.replace(tzinfo=UTC)
    assert result.at == datetime.datetime(2030, 6, 1, tzinfo=UTC)
    assert result.no_expiration is False
    assert result.encoding_issue is None


def test_another_timezone_names_the_same_instant(cert: bytes) -> None:
    plus_nine = datetime.timezone(datetime.timedelta(hours=9))
    # 2024-01-01 08:59:59 at +09:00 is 2023-12-31 23:59:59 UTC, one second before notBefore.
    assert check_validity(
        cert, datetime.datetime(2024, 1, 1, 8, 59, 59, tzinfo=plus_nine)
    ).reason == ("not_yet_valid")
    assert check_validity(cert, datetime.datetime(2024, 1, 1, 9, 0, 0, tzinfo=plus_nine)).ok


def test_naive_datetime_is_refused(cert: bytes) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        check_validity(cert, datetime.datetime(2030, 1, 1))
    with pytest.raises(TypeError):
        check_validity(cert, "2030-01-01")  # type: ignore[arg-type]


def test_no_expiration_sentinel_never_expires(key: ec.EllipticCurvePrivateKey) -> None:
    forever = mint(
        key, key, not_before=NOT_BEFORE, not_after=datetime.datetime(9999, 12, 31, 23, 59, 59)
    )
    result = check_validity(forever.der, datetime.datetime(9000, 1, 1, tzinfo=UTC))
    assert result.ok
    assert result.no_expiration is True
    # The sentinel is the last representable instant, and the period is inclusive of it.
    assert check_validity(forever.der, asn1core.NO_EXPIRATION).ok


def test_generalizedtime_before_2050_is_valid_and_flagged(cert: bytes) -> None:
    """Section 4.1.2.5 tells a CA to use UTCTime through 2049; real CAs have not always, and the
    date is still a date. The period is honoured and the spelling is described, not refused."""
    certificate = asn1core.parse_certificate(cert)
    window = certificate.validity
    spelled = b"\x18\x0f" + NOT_BEFORE.strftime("%Y%m%d%H%M%SZ").encode()
    body = spelled + window.not_after_raw
    new_validity = b"\x30" + asn1core.encode_length(len(body)) + body
    tbs_content, rest = parts(cert)
    rewritten = join(tbs_content.replace(window.raw, new_validity), rest)
    result = check_validity(rewritten, NOT_BEFORE.replace(tzinfo=UTC))
    assert result.ok
    assert result.encoding_issue is not None
    assert "GeneralizedTime" in result.encoding_issue


def test_two_digit_year_49_and_50_century(key: ec.EllipticCurvePrivateKey) -> None:
    """Section 4.1.2.5.1: YY >= 50 is 19YY and YY < 50 is 20YY. The window below is written 500101
    to 491231, so reading it wrongly would make an empty or a century-long period."""
    wide = mint(
        key,
        key,
        not_before=datetime.datetime(1950, 1, 1),
        not_after=datetime.datetime(2049, 12, 31, 23, 59, 59),
    )
    assert wide.certificate.validity.not_before.year == 1950
    assert wide.certificate.validity.not_after.year == 2049
    assert check_validity(wide.der, datetime.datetime(2000, 1, 1, tzinfo=UTC)).ok
    assert check_validity(
        wide.der, datetime.datetime(1949, 12, 31, 23, 59, 59, tzinfo=UTC)
    ).reason == ("not_yet_valid")
    assert check_validity(wide.der, datetime.datetime(2050, 1, 1, tzinfo=UTC)).reason == "expired"


def test_a_real_certificate_is_valid_inside_its_period() -> None:
    der = (FIX / "anchors" / "isrg-root-x1.der").read_bytes()
    window = asn1core.parse_certificate(der).validity
    assert check_validity(der, window.not_before).ok
    assert check_validity(der, window.not_after).ok
    assert check_validity(der, window.not_after + SECOND).reason == "expired"
    # Passing the parsed object gives the same answer as passing the bytes.
    parsed = asn1core.parse_certificate(der)
    assert check_validity(parsed, window.not_before) == check_validity(der, window.not_before)


def test_garbage_der_raises_a_named_error_not_a_leak() -> None:
    at = datetime.datetime(2030, 1, 1, tzinfo=UTC)
    with pytest.raises(errors.MalformedCertificate, match="not a DER certificate"):
        check_validity(b"\x30\x03\x02\x01", at)
    with pytest.raises(errors.MalformedCertificate):
        check_validity(b"", at)
    # MalformedCertificate is both a PkixError and a ValueError, so either except catches it.
    assert issubclass(errors.MalformedCertificate, errors.PkixError)
    assert issubclass(errors.MalformedCertificate, ValueError)
    with pytest.raises(TypeError):
        check_validity("not bytes", at)  # type: ignore[arg-type]
