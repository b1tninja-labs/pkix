"""RFC 5280 section 6.3.3 as `revocation.CrlChecker` runs it: rows `revocation.idp`,
`revocation.indirect_crl`, `revocation.separate_crl_key` and `revocation.delta_crl`.

Certificates and CRLs are minted with `cryptography` (a dev dependency), each authority with a key
of its own, because step (f) is about which key signed a CRL. NIST PKITS sections 4.4, 4.5, 4.14
and 4.15 exercise the same steps against an independent corpus (`tests/test_pkits.py`); these tests
run without it.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence

import asn1core
import asn1core.extensions
from builders import dn
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from pkix.anchors import load_anchor
from pkix.result import PathInputs, PathResult, path_walk
from pkix.revocation import ALL_REASONS, CrlChecker, RevocationRequest

AT = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
START = datetime.datetime(2024, 1, 1)
THIS_UPDATE = datetime.datetime(2025, 1, 1)
NEXT_UPDATE = datetime.datetime(2026, 1, 1)

ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
CA_KEY = ec.generate_private_key(ec.SECP256R1())
CRL_KEY = ec.generate_private_key(ec.SECP256R1())
INDIRECT_KEY = ec.generate_private_key(ec.SECP256R1())
LEAF_KEY = ec.generate_private_key(ec.SECP256R1())

type Ext = tuple[x509.ExtensionType, bool]

CA_USAGE = x509.KeyUsage(False, False, False, False, False, True, True, False, False)
SIGN_ONLY = x509.KeyUsage(False, False, False, False, False, True, False, False, False)
CRL_ONLY = x509.KeyUsage(False, False, False, False, False, False, True, False, False)
URI_1 = x509.UniformResourceIdentifier("http://crl.test/1.crl")
URI_2 = x509.UniformResourceIdentifier("http://crl.test/2.crl")
URI_DELTA = x509.UniformResourceIdentifier("http://crl.test/delta.crl")


def _cert(
    subject: str,
    issuer: str,
    public: ec.EllipticCurvePublicKey,
    signer: ec.EllipticCurvePrivateKey,
    *,
    serial: int,
    ca: bool = False,
    usage: x509.KeyUsage | None = None,
    extensions: Sequence[Ext] = (),
) -> bytes:
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject))
        .issuer_name(dn(issuer))
        .public_key(public)
        .serial_number(serial)
        .not_valid_before(START)
        .not_valid_after(START + datetime.timedelta(days=3650))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    if usage is not None:
        builder = builder.add_extension(usage, True)
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    return builder.sign(signer, hashes.SHA256()).public_bytes(Encoding.DER)


ROOT = _cert("Root", "Root", ROOT_KEY.public_key(), ROOT_KEY, serial=1, ca=True, usage=CA_USAGE)
ANCHOR = load_anchor(ROOT)


def _crl(
    issuer: str,
    signer: ec.EllipticCurvePrivateKey,
    *,
    revoked: Sequence[tuple[int, x509.ReasonFlags | None, Sequence[Ext]]] = (),
    extensions: Sequence[Ext] = (),
    number: int = 1,
) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(dn(issuer))
        .last_update(THIS_UPDATE)
        .next_update(NEXT_UPDATE)
        .add_extension(x509.CRLNumber(number), False)
    )
    for serial, reason, entry_extensions in revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(datetime.datetime(2025, 2, 1))
        )
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), False)
        for value, critical in entry_extensions:
            entry = entry.add_extension(value, critical)
        builder = builder.add_revoked_certificate(entry.build())
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    return builder.sign(signer, hashes.SHA256()).public_bytes(Encoding.DER)


def _idp(
    *,
    full_name: Sequence[x509.GeneralName] | None = None,
    users: bool = False,
    cas: bool = False,
    reasons: frozenset[x509.ReasonFlags] | None = None,
    indirect: bool = False,
) -> Ext:
    value = x509.IssuingDistributionPoint(
        full_name=None if full_name is None else list(full_name),
        relative_name=None,
        only_contains_user_certs=users,
        only_contains_ca_certs=cas,
        only_some_reasons=reasons,
        indirect_crl=indirect,
        only_contains_attribute_certs=False,
    )
    return value, True


def _dps(*points: x509.DistributionPoint) -> Ext:
    return x509.CRLDistributionPoints(list(points)), False


CA = _cert("CA", "Root", CA_KEY.public_key(), ROOT_KEY, serial=2, ca=True, usage=CA_USAGE)
ROOT_CRL = _crl("Root", ROOT_KEY)


def _leaf(serial: int = 100, extensions: Sequence[Ext] = ()) -> bytes:
    return _cert("Leaf", "CA", LEAF_KEY.public_key(), CA_KEY, serial=serial, extensions=extensions)


def _walk(
    leaf: bytes,
    crls: Sequence[bytes],
    *,
    certificates: Sequence[bytes] = (),
    use_deltas: bool = True,
    explicit_deltas: bool = False,
) -> PathResult:
    checker = CrlChecker(
        [ROOT_CRL, *crls],
        certificates=[CA, *certificates],
        use_deltas=use_deltas,
        explicit_deltas=explicit_deltas,
    )
    return path_walk([leaf, CA], ANCHOR, AT, PathInputs(revocation=checker))


def _leaf_answer(result: PathResult) -> str:
    """The revocation step's detail for the leaf (certificate 2)."""
    steps = [s for s in result.steps if s.index == 2 and s.step == "6.1.3(a)(3) revocation"]
    assert steps, result.steps
    return f"{steps[0].outcome}: {steps[0].detail}"


# ---- revocation.idp: steps (b)(2), (d), (e) -------------------------------------------------


def test_an_issuing_distribution_point_scope_is_processed_not_refused():
    users = _crl("CA", CA_KEY, extensions=[_idp(users=True)])
    assert _walk(_leaf(), [users]).valid
    only_cas = _crl("CA", CA_KEY, extensions=[_idp(cas=True)])
    result = _walk(_leaf(), [only_cas])
    assert result.status == "invalid"
    assert "undetermined" in _leaf_answer(result)
    assert "(b)(2)(iii)" in _leaf_answer(result)


def test_idp_distribution_point_names_must_match_the_certificates():
    leaf = _leaf(extensions=[_dps(x509.DistributionPoint([URI_1], None, None, None))])
    matching = _crl("CA", CA_KEY, extensions=[_idp(full_name=[URI_1])])
    assert _walk(leaf, [matching]).valid
    elsewhere = _crl("CA", CA_KEY, extensions=[_idp(full_name=[URI_2])])
    result = _walk(leaf, [elsewhere])
    assert result.status == "invalid"
    assert "(b)(2)(i)" in _leaf_answer(result)


COMPROMISE = frozenset(
    {
        x509.ReasonFlags.key_compromise,
        x509.ReasonFlags.ca_compromise,
        x509.ReasonFlags.aa_compromise,
    }
)
ROUTINE = frozenset(
    {
        x509.ReasonFlags.affiliation_changed,
        x509.ReasonFlags.superseded,
        x509.ReasonFlags.cessation_of_operation,
        x509.ReasonFlags.certificate_hold,
        x509.ReasonFlags.privilege_withdrawn,
    }
)


def test_only_some_reasons_crls_must_together_cover_every_reason():
    """Section 6.3.3 (d), (e), (l): reasons_mask grows CRL by CRL until it is all-reasons."""
    assert len(ALL_REASONS) == 8  # the named reasons of section 4.2.1.13, "unused" aside
    compromise = _crl("CA", CA_KEY, extensions=[_idp(reasons=COMPROMISE)])
    routine = _crl("CA", CA_KEY, extensions=[_idp(reasons=ROUTINE)])
    assert _walk(_leaf(), [compromise, routine]).valid
    result = _walk(_leaf(), [compromise])
    assert result.status == "invalid"
    assert "covers the reasons" in _leaf_answer(result)
    revoked = _crl(
        "CA",
        CA_KEY,
        revoked=[(100, x509.ReasonFlags.key_compromise, ())],
        extensions=[_idp(reasons=COMPROMISE)],
    )
    assert _leaf_answer(_walk(_leaf(), [revoked, routine])).startswith("failed: revoked")


# ---- revocation.indirect_crl: steps (b)(1) and section 5.3.3 --------------------------------

INDIRECT = _cert(
    "Indirect Issuer", "Root", INDIRECT_KEY.public_key(), ROOT_KEY, serial=3, usage=CRL_ONLY
)


def _indirect_leaf() -> bytes:
    point = x509.DistributionPoint(None, None, None, [x509.DirectoryName(dn("Indirect Issuer"))])
    return _leaf(extensions=[_dps(point)])


def _certificate_issuer(name: str) -> Ext:
    return x509.CertificateIssuer([x509.DirectoryName(dn(name))]), True


def test_an_indirect_crl_attributes_each_entry_to_its_certificate_issuer():
    other = _crl(
        "Indirect Issuer",
        INDIRECT_KEY,
        revoked=[(100, None, [_certificate_issuer("Other CA")])],
        extensions=[_idp(indirect=True)],
    )
    result = _walk(_indirect_leaf(), [other], certificates=[INDIRECT])
    assert result.valid, result.steps
    assert "separate CRL signer" in _leaf_answer(result)
    ours = _crl(
        "Indirect Issuer",
        INDIRECT_KEY,
        revoked=[(100, None, [_certificate_issuer("CA")])],
        extensions=[_idp(indirect=True)],
    )
    assert _leaf_answer(_walk(_indirect_leaf(), [ours], certificates=[INDIRECT])).startswith(
        "failed: revoked"
    )


def test_a_crl_issuer_named_in_the_dp_must_assert_indirect_crl():
    direct = _crl("Indirect Issuer", INDIRECT_KEY)
    result = _walk(_indirect_leaf(), [direct], certificates=[INDIRECT])
    assert result.status == "invalid"
    assert "(b)(1)" in _leaf_answer(result)


# ---- revocation.separate_crl_key: step (f) ----------------------------------------------------


def _split_ca() -> tuple[bytes, bytes]:
    """A CA whose certificate-signing key and CRL-signing key are certified separately by Root."""
    signing = _cert("CA", "Root", CA_KEY.public_key(), ROOT_KEY, serial=2, ca=True, usage=SIGN_ONLY)
    crl_signer = _cert("CA", "Root", CRL_KEY.public_key(), ROOT_KEY, serial=4, usage=CRL_ONLY)
    return signing, crl_signer


def test_a_separate_crl_signing_key_is_validated_from_the_same_anchor():
    signing, crl_signer = _split_ca()
    leaf = _leaf()
    crl = _crl("CA", CRL_KEY)
    checker = CrlChecker([ROOT_CRL, crl], certificates=[signing, crl_signer])
    result = path_walk([leaf, signing], ANCHOR, AT, PathInputs(revocation=checker))
    assert result.valid, result.steps
    assert "separate CRL signer, serial 4" in _leaf_answer(result)
    # The CRL signer's own certificate is revoked by Root: its key validates nothing.
    revoked_signer = CrlChecker(
        [_crl("Root", ROOT_KEY, revoked=[(4, None, ())]), crl],
        certificates=[signing, crl_signer],
    )
    result = path_walk([leaf, signing], ANCHOR, AT, PathInputs(revocation=revoked_signer))
    assert result.status == "invalid"
    assert "CRL signer path does not validate" in _leaf_answer(result)
    # Without the CRL signer's certificate there is no key to validate in step (f).
    alone = CrlChecker([ROOT_CRL, crl], certificates=[signing])
    result = path_walk([leaf, signing], ANCHOR, AT, PathInputs(revocation=alone))
    assert result.status == "invalid"
    assert "undetermined" in _leaf_answer(result)


# ---- revocation.delta_crl: steps (c), (h), (i), section 5.2.4 ----------------------------------


def _freshest() -> Ext:
    return x509.FreshestCRL([x509.DistributionPoint([URI_DELTA], None, None, None)]), False


def _delta(base: int, number: int, revoked: Sequence[tuple[int, x509.ReasonFlags | None]]) -> bytes:
    return _crl(
        "CA",
        CA_KEY,
        revoked=[(serial, reason, ()) for serial, reason in revoked],
        extensions=[(x509.DeltaCRLIndicator(base), True)],
        number=number,
    )


def test_a_delta_crl_is_merged_with_the_complete_crl_it_updates():
    leaf = _leaf(extensions=[_freshest()])
    complete = _crl("CA", CA_KEY, extensions=[_freshest()], number=10)
    revoking = _delta(10, 11, [(100, x509.ReasonFlags.key_compromise)])
    answer = _leaf_answer(_walk(leaf, [complete, revoking]))
    assert answer.startswith("failed: revoked")
    assert "delta CRL" in answer
    # Section 5.2.4(c): a delta whose base is newer than the complete CRL cannot update it.
    too_new = _delta(12, 13, [(100, x509.ReasonFlags.key_compromise)])
    assert _walk(leaf, [complete, too_new]).valid
    # use-deltas unset (section 6.1.1 input of section 6.3.3): the delta is not consulted.
    assert _walk(leaf, [complete, revoking], use_deltas=False).valid


def test_explicit_deltas_reads_a_delta_nothing_points_at():
    """Row `revocation.crl_explicit_delta`: RFC 5280 sec. 6.3.3 (c), (h), (i) are conditioned on
    use-deltas alone; only the *obtaining* of step (a) mentions the freshest CRL extension."""
    leaf = _leaf()  # no FreshestCRL on the certificate...
    complete = _crl("CA", CA_KEY, number=10)  # ...nor on the CRL
    revoking = _delta(10, 11, [(100, x509.ReasonFlags.key_compromise)])
    assert _walk(leaf, [complete, revoking]).valid  # default: the delta is left unread
    answer = _leaf_answer(_walk(leaf, [complete, revoking], explicit_deltas=True))
    assert answer.startswith("failed: revoked")
    assert "delta CRL" in answer
    # The delta still has to combine with the complete CRL (sec. 5.2.4 (c)) and be current.
    too_new = _delta(12, 13, [(100, x509.ReasonFlags.key_compromise)])
    assert _walk(leaf, [complete, too_new], explicit_deltas=True).valid
    # use-deltas unset wins over explicit_deltas.
    assert _walk(leaf, [complete, revoking], use_deltas=False, explicit_deltas=True).valid
    # A delta that releases a held certificate is applied the same way.
    held = _crl("CA", CA_KEY, revoked=[(100, x509.ReasonFlags.certificate_hold, ())], number=10)
    released = _delta(10, 11, [(100, x509.ReasonFlags.remove_from_crl)])
    assert "certificateHold" in _leaf_answer(_walk(leaf, [held, released]))
    assert _walk(leaf, [held, released], explicit_deltas=True).valid


def _answer(
    leaf: bytes, crls: Sequence[bytes], *, explicit_deltas: bool = False, serial: int = 100
):
    certificate = asn1core.parse_certificate(leaf)
    ca = asn1core.parse_certificate(CA)
    checker = CrlChecker([ROOT_CRL, *crls], certificates=[CA], explicit_deltas=explicit_deltas)
    return checker(
        RevocationRequest(
            certificate=certificate,
            issuer_name=ca.subject,
            issuer_spki=ca.subject_public_key_info,
            issuer_certificate=ca,
            at=AT,
            index=2,
            anchor=ANCHOR,
        )
    )


def test_a_revoked_answer_carries_reason_code_date_and_origin():
    """Row `revocation.answer_details`: the structured fields of step (i)/(j), RFC 5280 5.3.1."""
    leaf = _leaf(extensions=[_freshest()])
    complete = _crl(
        "CA",
        CA_KEY,
        revoked=[(100, x509.ReasonFlags.superseded, ())],
        extensions=[_freshest()],
        number=10,
    )
    answer = _answer(leaf, [complete])
    assert (answer.status, answer.reason_code, answer.on_delta) == ("revoked", 4, False)
    assert answer.revocation_date == datetime.datetime(2025, 2, 1, tzinfo=datetime.UTC)
    delta = _delta(10, 11, [(100, x509.ReasonFlags.key_compromise)])
    answer = _answer(leaf, [complete, delta])
    assert (answer.status, answer.reason_code, answer.on_delta) == ("revoked", 1, True)
    # No reason code extension: step (i)(2) says unspecified, which is 0, and not None.
    bare = _crl("CA", CA_KEY, revoked=[(100, None, ())])
    answer = _answer(_leaf(), [bare])
    assert (answer.status, answer.reason_code) == ("revoked", 0)
    # Every other status leaves the fields unset.
    good = _answer(_leaf(serial=101), [bare])
    assert good.status == "good"
    assert (good.reason_code, good.revocation_date, good.on_delta) == (None, None, False)


def test_an_indirect_crl_answer_reads_the_entry_of_its_own_certificate_issuer():
    """Two entries for one serial, told apart by certificateIssuer (sec. 5.3.3): the answer's
    reason is the matching one, which revokekit could not read back for itself."""
    other = x509.CertificateIssuer([x509.DirectoryName(dn("Elsewhere"))])
    crl = _crl(
        "CA",
        CA_KEY,
        revoked=[
            (100, x509.ReasonFlags.key_compromise, [(other, True)]),
            (
                100,
                x509.ReasonFlags.superseded,
                [(x509.CertificateIssuer([x509.DirectoryName(dn("CA"))]), True)],
            ),
        ],
    )
    answer = _answer(_leaf(), [crl])
    assert (answer.status, answer.reason_code) == ("revoked", 4)


def test_a_delta_crl_takes_a_certificate_off_hold():
    leaf = _leaf(extensions=[_freshest()])
    held = _crl(
        "CA",
        CA_KEY,
        revoked=[(100, x509.ReasonFlags.certificate_hold, ())],
        extensions=[_freshest()],
        number=10,
    )
    assert "certificateHold" in _leaf_answer(_walk(leaf, [held]))
    released = _delta(10, 11, [(100, x509.ReasonFlags.remove_from_crl)])
    assert _walk(leaf, [held, released]).valid


def test_a_delta_crl_alone_is_never_a_complete_crl():
    result = _walk(_leaf(), [_delta(10, 11, [])])
    assert result.status == "invalid"
    assert "never used as a complete CRL" in _leaf_answer(result)


def test_asn1core_reads_the_crl_extensions_the_checker_uses():
    """PORTFOLIO.md section 9 item 15: one DER reader. The IDP is asn1core's decoder's output."""
    crl = asn1core.parse_crl(_crl("CA", CA_KEY, extensions=[_idp(users=True, indirect=True)]))
    (idp,) = [e for e in crl.extensions if e.dotted_oid == "2.5.29.28"]
    decoded = asn1core.extensions.parse_issuing_distribution_point(idp.value)
    assert decoded.only_contains_user_certs
    assert decoded.indirect_crl
