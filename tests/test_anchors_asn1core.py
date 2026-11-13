"""The anchors module reads through `asn1core` and verifies through `validity`, with no `cryptography`.

RFC 5280 section 6.1.1(d) hands path processing a name, an algorithm, a key and parameters, and
section 4.1.1.3 binds a signature to the DER tbsCertificate as it arrived. Both are statements
about bytes, so the anchor keeps the stored slices and these tests look for them in the input.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import tomllib

import asn1core
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from support import join, mint, parts, tlv

from pkix import errors
from pkix.anchors import load_anchor

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
FIX = HERE / "fixtures"


def der(*names: str) -> bytes:
    return FIX.joinpath(*names).read_bytes()


def test_anchor_carries_stored_spki_and_tbs_slices() -> None:
    raw = der("anchors", "isrg-root-x1.der")
    anchor = load_anchor(raw)
    parsed = asn1core.parse_certificate(raw)
    assert anchor.spki in raw
    assert anchor.spki == parsed.subject_public_key_info
    # The codec's own SPKI digest is over exactly the stored bytes the anchor holds.
    assert asn1core.spki_sha256(raw) == hashlib.sha256(anchor.spki).hexdigest()
    assert anchor.tbs is not None
    assert anchor.tbs in raw
    assert anchor.tbs == parsed.tbs_certificate


def test_anchor_name_comparison_uses_rfc4518() -> None:
    """Section 7.1: two spellings of one distinguished name are the same name."""
    key = ec.generate_private_key(ec.SECP256R1())
    lower = load_anchor(mint(key, key, subject="Example  Root", issuer="Example  Root").der)
    upper = load_anchor(mint(key, key, subject="example root", issuer="EXAMPLE ROOT").der)
    assert lower.issuer == upper.issuer  # case and inner-space differences are not differences
    assert lower.issuer.rfc4514() != upper.issuer.rfc4514()
    other = load_anchor(mint(key, key, subject="Another Root", issuer="Another Root").der)
    assert other.issuer != lower.issuer


def test_runtime_dependencies_exclude_cryptography() -> None:
    """`cryptography` is a dev dependency here: pkix reaches it, if at all, only through `sigwire[verify]`,
    which owns the signature arithmetic (the owner's rule of 2026-11-12)."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime = {re.split(r"[<>=!~\[ ]", entry, maxsplit=1)[0] for entry in project["dependencies"]}
    assert runtime == {"asn1core", "sigwire"}
    dev = {
        re.split(r"[<>=!~\[ ]", entry, maxsplit=1)[0]
        for entry in project["optional-dependencies"]["dev"]
    }
    assert "cryptography" in dev


def test_package_source_never_imports_cryptography() -> None:
    offenders = [
        path.name
        for path in (ROOT / "pkix").rglob("*.py")
        if any(
            line.lstrip().startswith(("import cryptography", "from cryptography"))
            for line in path.read_text(encoding="utf-8").splitlines()
        )
    ]
    assert offenders == []


def test_v1_root_is_loaded() -> None:
    """A version 1 certificate has no extensions and is a legal anchor: section 6.1.1(d) asks for a
    name and a key, not for a profile. (Whether it may be a path member is `chain.may_issue`'s
    question, and that fails closed.)"""
    key = ec.generate_private_key(ec.SECP256R1())
    v3 = mint(key, key, subject="Old Root", issuer="Old Root")
    rest = parts(v3.der)[1]
    top, _ = asn1core.decode(v3.der, der=True)
    fields = list(top.children[0].children)
    # drop [0] version and [3] extensions: what remains is a v1 TBSCertificate
    kept = [f for f in fields if not (f.tag.is_context(0) or f.tag.is_context(3))]
    v1 = join(b"".join(f.raw for f in kept), rest)
    parsed = asn1core.parse_certificate(v1)
    assert parsed.version == 0
    anchor = load_anchor(v1)
    assert anchor.issuer == parsed.subject
    # The signature no longer covers these bytes, so it is not self-signed, and says so honestly.
    assert anchor.self_issued is True
    assert anchor.self_signed is False


def test_self_issued_and_self_signed_are_different_facts() -> None:
    """A re-issuance under the same name looks self-signed to anyone who only reads names."""
    k1 = ec.generate_private_key(ec.SECP256R1())
    k2 = ec.generate_private_key(ec.SECP256R1())
    reissued = mint(k1, k2, subject="Same Name", issuer="Same Name")  # k2 signs k1's key
    anchor = load_anchor(reissued.der)
    assert anchor.self_issued is True
    assert anchor.self_signed is False


def test_anchor_verify_checks_signatures_under_the_anchor_key() -> None:
    chain = [der("chains", f"letsencrypt.org-{i}.der") for i in range(4)]
    x1 = load_anchor(der("anchors", "isrg-root-x1.der"))
    # The cross-certificate (chain[3]) is signed by Root X1, and the anchor says so.
    result = x1.verify(chain[3])
    assert (result.scheme, result.key) == ("rsa-pkcs1v15", "RSA-4096")
    with pytest.raises(errors.SignatureInvalid):
        x1.verify(chain[0])
    x2 = load_anchor(der("anchors", "isrg-root-x2-cross-signed.der"))
    assert x2.self_signed is False
    assert x2.verify(chain[2]).key == "P-384"


def test_anchor_verify_is_loud_when_the_key_algorithm_is_not_supported() -> None:
    """An anchor whose key pkix cannot verify under never passes quietly."""
    key = ec.generate_private_key(ec.SECP256R1())
    minted = mint(key, key)
    spki = minted.certificate.subject_public_key_info
    # Rewrite the SPKI to name an algorithm pkix does not know (1.2.3.4), keeping the key bits.
    algorithm = tlv(0x30, bytes.fromhex("06032a0304"))
    top, _ = asn1core.decode(spki, der=True)
    odd_spki = tlv(0x30, algorithm + top.children[1].raw)
    tbs_content, rest = parts(minted.der)
    odd = join(tbs_content.replace(spki, odd_spki), rest)
    anchor = load_anchor(odd)
    assert anchor.algorithm == "1.2.3.4"
    assert anchor.self_signed is False
    with pytest.raises(errors.SignatureUnsupported):
        anchor.verify(minted.der)


def test_non_certificate_input_names_the_error() -> None:
    with pytest.raises(errors.MalformedCertificate, match="not a DER certificate"):
        load_anchor(b"\x30\x03\x02\x01")
