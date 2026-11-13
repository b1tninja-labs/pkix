"""Decoders for the extensions path validation reads (RFC 5280 section 4.2.1).

`asn1core` hands over an extension's payload as bytes and leaves the meaning to this package, so the
shapes that section 6.1 consumes are read here: basic constraints, key usage, certificate policies,
policy mappings, policy constraints and inhibit anyPolicy. Name constraints and alternative names
live in `pkix.names`.

Every decoder takes the `asn1core.Extension` (or None) and refuses a value that is not DER of the
documented type with `MalformedExtension`. None in, None out: absence is information and is never
confused with an empty value.
"""

from __future__ import annotations

from dataclasses import dataclass

import asn1core
import asn1core.extensions

from .errors import MalformedExtension

__all__ = [
    "ANY_POLICY",
    "BasicConstraints",
    "PolicyConstraints",
    "PolicyInformation",
    "key_usage",
    "parse_basic_constraints",
    "parse_certificate_policies",
    "parse_inhibit_any_policy",
    "parse_key_usage",
    "parse_policy_constraints",
    "parse_policy_mappings",
]

BASIC_CONSTRAINTS = "2.5.29.19"
KEY_USAGE = "2.5.29.15"
CERTIFICATE_POLICIES = "2.5.29.32"
POLICY_MAPPINGS = "2.5.29.33"
POLICY_CONSTRAINTS = "2.5.29.36"
INHIBIT_ANY_POLICY = "2.5.29.54"
ANY_POLICY = "2.5.29.32.0"

# RFC 5280 section 4.2.1.3, KeyUsage ::= BIT STRING { digitalSignature (0) ... decipherOnly (8) }.
_KEY_USAGE_BITS = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)


def _decode(ext: asn1core.Extension, what: str) -> asn1core.Node:
    try:
        node, end = asn1core.decode(ext.value, der=True)
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"{what} is not DER: {exc}") from exc
    if end != len(ext.value):
        raise MalformedExtension(f"{what} has trailing octets after its value")
    return node


def _universal(node: asn1core.Node, number: int) -> bool:
    return node.tag.is_universal() and node.tag.number == number


def _context(node: asn1core.Node, number: int) -> bool:
    return node.tag.tag_class is asn1core.TagClass.context and node.tag.number == number


def _integer(node: asn1core.Node, what: str) -> int:
    if not node.payload:
        raise MalformedExtension(f"{what} is not an INTEGER")
    value = int.from_bytes(node.payload, "big", signed=True)
    if value < 0:
        raise MalformedExtension(f"{what} is negative; the type is INTEGER (0..MAX)")
    return value


def _oid(node: asn1core.Node, what: str) -> str:
    if not _universal(node, 6) or node.payload is None:
        raise MalformedExtension(f"{what} is not an OBJECT IDENTIFIER")
    try:
        return ".".join(str(arc) for arc in asn1core.decode_oid(node.payload))
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"{what} is not a valid OBJECT IDENTIFIER: {exc}") from exc


@dataclass(frozen=True, slots=True)
class BasicConstraints:
    """RFC 5280 section 4.2.1.9: `cA BOOLEAN DEFAULT FALSE`, `pathLenConstraint INTEGER OPTIONAL`."""

    ca: bool
    path_length: int | None


def parse_basic_constraints(ext: asn1core.Extension | None) -> BasicConstraints | None:
    if ext is None:
        return None
    node = _decode(ext, "basicConstraints")
    if not _universal(node, 16) or not node.constructed:
        raise MalformedExtension("basicConstraints is not a SEQUENCE")
    ca = False
    path_length: int | None = None
    rest = list(node.children)
    if rest and _universal(rest[0], 1):
        if rest[0].payload != b"\xff":
            raise MalformedExtension("basicConstraints cA is not DER TRUE (FALSE is the DEFAULT)")
        ca = True
        rest.pop(0)
    if rest and _universal(rest[0], 2):
        path_length = _integer(rest[0], "pathLenConstraint")
        rest.pop(0)
    if rest:
        raise MalformedExtension("basicConstraints has unexpected fields")
    return BasicConstraints(ca=ca, path_length=path_length)


def parse_key_usage(ext: asn1core.Extension | None) -> frozenset[str] | None:
    """The set bits of KeyUsage by name (RFC 5280 section 4.2.1.3), or None when absent.

    A bit beyond the ninth is refused rather than ignored: RFC 5280 names nine and a tenth would be
    a document this code has not read.
    """
    if ext is None:
        return None
    # The DER reading is asn1core's (`asn1core.extensions.parse_key_usage`; PORTFOLIO.md section 9
    # item 15 makes asn1core the one reader of the standard extensions). It refuses a value that is
    # not a BIT STRING, a trailing 0 bit (X.690 11.2.2) and a value with no bit set (RFC 5280
    # section 4.2.1.3). What the bits mean to path validation, and the refusal of a bit RFC 5280
    # does not name, stay here.
    try:
        usage = asn1core.extensions.parse_key_usage(ext.value)
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"keyUsage: {exc}") from exc
    unnamed = sorted(bit for bit in usage.bits if bit >= len(_KEY_USAGE_BITS))
    if unnamed:
        raise MalformedExtension(f"keyUsage sets bit {unnamed[0]}, which RFC 5280 does not name")
    return frozenset(usage.names)


def key_usage(certificate: asn1core.Certificate) -> frozenset[str] | None:
    """The certificate's keyUsage bits, or None when the extension is absent."""
    return parse_key_usage(certificate.extension(KEY_USAGE))


@dataclass(frozen=True, slots=True)
class PolicyInformation:
    """One PolicyInformation: the OID in dotted form and each qualifier's whole DER encoding."""

    policy: str
    qualifiers: tuple[bytes, ...]


def parse_certificate_policies(
    ext: asn1core.Extension | None,
) -> tuple[PolicyInformation, ...] | None:
    """RFC 5280 section 4.2.1.4. A policy listed twice is refused: the section forbids it."""
    if ext is None:
        return None
    node = _decode(ext, "certificatePolicies")
    if not _universal(node, 16) or not node.constructed or not node.children:
        raise MalformedExtension("certificatePolicies is not a non-empty SEQUENCE")
    out: list[PolicyInformation] = []
    seen: set[str] = set()
    for item in node.children:
        if not _universal(item, 16) or not item.constructed or not 1 <= len(item.children) <= 2:
            raise MalformedExtension("a PolicyInformation is a SEQUENCE of one or two fields")
        oid = _oid(item.children[0], "policyIdentifier")
        qualifiers: tuple[bytes, ...] = ()
        if len(item.children) == 2:
            quals = item.children[1]
            if not _universal(quals, 16) or not quals.constructed or not quals.children:
                raise MalformedExtension("policyQualifiers is not a non-empty SEQUENCE")
            qualifiers = tuple(q.raw for q in quals.children)
        if oid in seen:
            raise MalformedExtension(f"certificatePolicies lists {oid} more than once")
        seen.add(oid)
        out.append(PolicyInformation(oid, qualifiers))
    return tuple(out)


def parse_policy_mappings(
    ext: asn1core.Extension | None,
) -> tuple[tuple[str, str], ...] | None:
    """RFC 5280 section 4.2.1.5 as (issuerDomainPolicy, subjectDomainPolicy) pairs, in order."""
    if ext is None:
        return None
    node = _decode(ext, "policyMappings")
    if not _universal(node, 16) or not node.constructed or not node.children:
        raise MalformedExtension("policyMappings is not a non-empty SEQUENCE")
    pairs: list[tuple[str, str]] = []
    for item in node.children:
        if not _universal(item, 16) or len(item.children) != 2:
            raise MalformedExtension("a policy mapping is a SEQUENCE of two policy identifiers")
        pairs.append(
            (
                _oid(item.children[0], "issuerDomainPolicy"),
                _oid(item.children[1], "subjectDomainPolicy"),
            )
        )
    return tuple(pairs)


@dataclass(frozen=True, slots=True)
class PolicyConstraints:
    """RFC 5280 section 4.2.1.11: either field may be absent."""

    require_explicit_policy: int | None
    inhibit_policy_mapping: int | None


def parse_policy_constraints(ext: asn1core.Extension | None) -> PolicyConstraints | None:
    if ext is None:
        return None
    node = _decode(ext, "policyConstraints")
    if not _universal(node, 16) or not node.constructed:
        raise MalformedExtension("policyConstraints is not a SEQUENCE")
    require: int | None = None
    inhibit: int | None = None
    expect = 0
    for child in node.children:
        if _context(child, 0) and expect == 0:
            require = _integer(child, "requireExplicitPolicy")
            expect = 1
        elif _context(child, 1) and expect <= 1:
            inhibit = _integer(child, "inhibitPolicyMapping")
            expect = 2
        else:
            raise MalformedExtension("policyConstraints has an unexpected or misordered field")
    return PolicyConstraints(require, inhibit)


def parse_inhibit_any_policy(ext: asn1core.Extension | None) -> int | None:
    if ext is None:
        return None
    node = _decode(ext, "inhibitAnyPolicy")
    if not _universal(node, 2):
        raise MalformedExtension("inhibitAnyPolicy is not an INTEGER")
    return _integer(node, "inhibitAnyPolicy")
