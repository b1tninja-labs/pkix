"""General names and name constraints (RFC 5280 sections 4.2.1.6, 4.2.1.10, 6.1.3(b)-(c), 6.1.4(g)).

Name constraints bind every certificate below the one that carries them: "all subject names in
subsequent certificates in a certification path MUST be located" in the permitted space, and a name
matching an excluded subtree "is invalid regardless of information appearing in the permittedSubtrees"
(section 4.2.1.10). This module decodes the extension, keeps the running `permitted_subtrees` and
`excluded_subtrees` state of section 6.1.2(b) and (c), updates it as section 6.1.4(g) says
(intersection for permitted, union for excluded), and checks a certificate against it.

Name forms with a comparison here: directoryName (RFC 5280 section 7.1, through `asn1core`),
dNSName, rfc822Name, uniformResourceIdentifier (host part) and iPAddress. For the forms the document
leaves undefined (otherName, x400Address, ediPartyName, registeredID), a constraint that covers a
name of that form is not guessed at: section 4.2.1.10 says "the application MUST either process the
constraint or reject the certificate", and `UnsupportedConstraint` is the rejection.

Decisions where the text is silent or was changed, each also in docs/rfc-map.md:

* RFC 9549 section 2.2 removes the mailbox constraint ("root@example.com") from rfc822Name. A
  constraint carrying "@" is refused as unsupported, not read the old way.
* dNSName constraint with a leading period (".example.com") is not in section 4.2.1.10's DNS
  paragraph, which says "host.example.com" and "adding zero or more labels". It is read the way the
  same section reads URI and mailbox constraints: one or more labels, the bare host excluded.
* DNS comparison is a case-insensitive exact match label by label (RFC 9549 section 2.3). A name
  that is not ASCII is not an A-label and is refused as malformed.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field

import asn1core

from .errors import MalformedExtension, UnsupportedConstraint

__all__ = [
    "GeneralName",
    "NameConstraints",
    "NameViolation",
    "Subtree",
    "certificate_names",
    "check_certificate",
    "constraint_holds",
    "parse_general_name",
    "parse_name_constraints",
    "parse_subject_alt_name",
]

SUBJECT_ALT_NAME = "2.5.29.17"
NAME_CONSTRAINTS = "2.5.29.30"
EMAIL_ADDRESS = (1, 2, 840, 113549, 1, 9, 1)

_KINDS = {
    0: "otherName",
    1: "rfc822Name",
    2: "dNSName",
    3: "x400Address",
    4: "directoryName",
    5: "ediPartyName",
    6: "uniformResourceIdentifier",
    7: "iPAddress",
    8: "registeredID",
}
_SUPPORTED = frozenset(
    {"rfc822Name", "dNSName", "directoryName", "uniformResourceIdentifier", "iPAddress"}
)

type NameValue = str | bytes | asn1core.Name


@dataclass(frozen=True, slots=True)
class GeneralName:
    """One GeneralName: its choice by name and its value.

    `value` is `str` for rfc822Name, dNSName, uniformResourceIdentifier and registeredID (dotted),
    an `asn1core.Name` for directoryName, and the content octets for iPAddress; for the forms with
    no comparison here it is the whole encoding.
    """

    kind: str
    value: NameValue


@dataclass(frozen=True, slots=True)
class Subtree:
    """A GeneralSubtree: `base` with `minimum` and `maximum` (RFC 5280 section 4.2.1.10)."""

    base: GeneralName
    minimum: int = 0
    maximum: int | None = None


@dataclass(frozen=True, slots=True)
class NameConstraints:
    """The running constraint state, or one extension's contribution to it.

    A name type absent from `permitted` is unconstrained; present with no subtrees it permits
    nothing (an intersection that came out empty). `excluded` only ever grows.
    """

    permitted: Mapping[str, tuple[Subtree, ...]] = field(default_factory=dict)
    excluded: Mapping[str, tuple[Subtree, ...]] = field(default_factory=dict)

    def restrict(self, extension: NameConstraints) -> NameConstraints:
        """RFC 5280 section 6.1.4(g): intersect the permitted subtrees, union the excluded ones.

        A name type the extension's permittedSubtrees does not mention is left as it was.
        """
        permitted = dict(self.permitted)
        for kind, new in extension.permitted.items():
            old = permitted.get(kind)
            permitted[kind] = new if old is None else _intersect(kind, old, new)
        excluded = dict(self.excluded)
        for kind, new in extension.excluded.items():
            excluded[kind] = tuple(dict.fromkeys((*excluded.get(kind, ()), *new)))
        return NameConstraints(permitted, excluded)


@dataclass(frozen=True, slots=True)
class NameViolation:
    """One name that RFC 5280 section 6.1.3(b) or (c) rejects, and which of the two."""

    name: GeneralName
    reason: str  # "not_permitted" (step b) or "excluded" (step c)


def _ia5(payload: bytes | None, what: str) -> str:
    if payload is None:
        raise MalformedExtension(f"{what} is not a primitive string")
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MalformedExtension(f"{what} is not IA5String (ASCII): {exc}") from exc


def parse_general_name(node: asn1core.Node) -> GeneralName:
    """RFC 5280 section 4.2.1.6's GeneralName CHOICE."""
    if node.tag.tag_class is not asn1core.TagClass.context or node.tag.number not in _KINDS:
        raise MalformedExtension(f"not a GeneralName choice: tag {node.tag!r}")
    kind = _KINDS[node.tag.number]
    if kind in ("rfc822Name", "dNSName", "uniformResourceIdentifier"):
        return GeneralName(kind, _ia5(node.payload, kind))
    if kind == "iPAddress":
        if node.payload is None:
            raise MalformedExtension("iPAddress is not an OCTET STRING")
        return GeneralName(kind, node.payload)
    if kind == "directoryName":
        if not node.constructed or len(node.children) != 1:
            raise MalformedExtension("directoryName is an explicitly tagged Name")
        try:
            return GeneralName(kind, asn1core.parse_name(node.children[0]))
        except asn1core.Asn1Error as exc:
            raise MalformedExtension(f"directoryName is not a Name: {exc}") from exc
    if kind == "registeredID":
        if node.payload is None:
            raise MalformedExtension("registeredID is not an OBJECT IDENTIFIER")
        return GeneralName(kind, ".".join(str(a) for a in asn1core.decode_oid(node.payload)))
    return GeneralName(kind, node.raw)


def _sequence(ext: asn1core.Extension, what: str) -> asn1core.Node:
    try:
        node, end = asn1core.decode(ext.value, der=True)
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"{what} is not DER: {exc}") from exc
    if end != len(ext.value) or not node.tag.is_universal() or node.tag.number != 16:
        raise MalformedExtension(f"{what} is not a single SEQUENCE")
    return node


def parse_subject_alt_name(ext: asn1core.Extension | None) -> tuple[GeneralName, ...] | None:
    """RFC 5280 section 4.2.1.6: `GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName`."""
    if ext is None:
        return None
    node = _sequence(ext, "subjectAltName")
    if not node.children:
        raise MalformedExtension("subjectAltName is empty; GeneralNames has at least one name")
    return tuple(parse_general_name(child) for child in node.children)


def _base_distance(node: asn1core.Node, what: str) -> int:
    if not node.payload:
        raise MalformedExtension(f"{what} is not an INTEGER")
    value = int.from_bytes(node.payload, "big", signed=True)
    if value < 0:
        raise MalformedExtension(f"{what} is negative; BaseDistance is INTEGER (0..MAX)")
    return value


def _subtrees(node: asn1core.Node) -> dict[str, list[Subtree]]:
    if not node.children:
        raise MalformedExtension("GeneralSubtrees has at least one GeneralSubtree")
    out: dict[str, list[Subtree]] = {}
    for item in node.children:
        if not item.tag.is_universal() or item.tag.number != 16 or not item.children:
            raise MalformedExtension("a GeneralSubtree is a non-empty SEQUENCE")
        base = parse_general_name(item.children[0])
        minimum, maximum = 0, None
        for extra in item.children[1:]:
            if extra.tag.tag_class is asn1core.TagClass.context and extra.tag.number == 0:
                minimum = _base_distance(extra, "minimum")
            elif extra.tag.tag_class is asn1core.TagClass.context and extra.tag.number == 1:
                maximum = _base_distance(extra, "maximum")
            else:
                raise MalformedExtension("a GeneralSubtree has an unexpected field")
        if base.kind == "iPAddress" and len(base.value) not in (8, 32):  # type: ignore[arg-type]
            raise MalformedExtension(
                "an iPAddress constraint is 8 or 32 octets: address and mask (RFC 5280 sec. 4.2.1.10)"
            )
        out.setdefault(base.kind, []).append(Subtree(base, minimum, maximum))
    return out


def parse_name_constraints(ext: asn1core.Extension | None) -> NameConstraints | None:
    """RFC 5280 section 4.2.1.10. At least one of the two subtree fields must be present."""
    if ext is None:
        return None
    node = _sequence(ext, "nameConstraints")
    permitted: dict[str, tuple[Subtree, ...]] = {}
    excluded: dict[str, tuple[Subtree, ...]] = {}
    seen = 0
    for child in node.children:
        if child.tag.tag_class is asn1core.TagClass.context and child.tag.number == 0 and seen == 0:
            permitted = {k: tuple(v) for k, v in _subtrees(child).items()}
            seen = 1
        elif (
            child.tag.tag_class is asn1core.TagClass.context and child.tag.number == 1 and seen < 2
        ):
            excluded = {k: tuple(v) for k, v in _subtrees(child).items()}
            seen = 2
        else:
            raise MalformedExtension("nameConstraints has an unexpected or misordered field")
    if not seen:
        raise MalformedExtension(
            "nameConstraints is an empty sequence, which RFC 5280 section 4.2.1.10 forbids"
        )
    return NameConstraints(permitted, excluded)


# --- comparison -----------------------------------------------------------------------------


def _is_dotted(base: str) -> bool:
    return base.startswith(".")


def _dns_within(name: str, base: str) -> bool:
    name, base = name.lower(), base.lower()
    if not base:
        return True
    if _is_dotted(base):
        return name.endswith(base)
    return name == base or name.endswith("." + base)


def _host_within(host: str, base: str) -> bool:
    """URI hosts and mailbox hosts: a bare base names one host, a dotted base names its domain."""
    host, base = host.lower(), base.lower()
    if not base:
        return True
    if _is_dotted(base):
        return host.endswith(base)
    return host == base


def _uri_host(uri: str) -> str | None:
    """The host of a URI if it is a fully qualified domain name, else None (RFC 5280 sec. 4.2.1.10).

    None covers every case the section says to reject: no authority, or an authority whose host is
    an IP address (including a bracketed IPv6 literal).
    """
    scheme, colon, rest = uri.partition(":")
    if not colon or not scheme or not rest.startswith("//"):
        return None
    authority = rest[2:]
    for stop in "/?#":
        authority = authority.split(stop, 1)[0]
    host = authority.rpartition("@")[2]
    if host.startswith("["):
        return None
    head, colon, port = host.rpartition(":")
    if colon and (port.isdigit() or not port):
        host = head
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None
    if host.replace(".", "").isdigit():
        return None
    return host


def _mask_ok(base: bytes) -> tuple[bytes, bytes]:
    half = len(base) // 2
    return base[:half], base[half:]


def _ip_within(address: bytes, base: bytes) -> bool:
    network, mask = _mask_ok(base)
    if len(address) != len(network):
        return False  # a different address family is not in the subtree
    return all((a & m) == (n & m) for a, n, m in zip(address, network, mask, strict=True))


def _subset(kind: str, inner: Subtree, outer: Subtree) -> bool:
    """Whether every name `inner` admits is admitted by `outer` (for the intersection of 6.1.4(g))."""
    a, b = inner.base.value, outer.base.value
    if kind == "directoryName":
        return asn1core.within(a, b)  # type: ignore[arg-type]
    if kind == "iPAddress":
        na, ma = _mask_ok(a)  # type: ignore[arg-type]
        nb, mb = _mask_ok(b)  # type: ignore[arg-type]
        if len(na) != len(nb):
            return False
        wider = all((x & y) == y for x, y in zip(ma, mb, strict=True))
        return wider and _ip_within(na, b)  # type: ignore[arg-type]
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError(f"{kind} subtrees hold strings")
    a, b = a.lower(), b.lower()
    if kind == "dNSName":
        if not b:
            return True
        if _is_dotted(b):
            return a.endswith(b)
        return a.lstrip(".") == b or a.lstrip(".").endswith("." + b)
    if not b:
        return True
    if _is_dotted(b):
        return a.endswith(b)
    return a == b and not _is_dotted(a)


def _intersect(
    kind: str, old: tuple[Subtree, ...], new: tuple[Subtree, ...]
) -> tuple[Subtree, ...]:
    if kind not in _SUPPORTED:
        return tuple(dict.fromkeys((*old, *new)))  # not evaluated; a name of this kind is refused
    kept = [n for n in new if any(_subset(kind, n, o) for o in old)]
    kept += [o for o in old if any(_subset(kind, o, n) for n in new)]
    return tuple(dict.fromkeys(kept))


def _within(name: GeneralName, subtree: Subtree) -> bool:
    kind, value, base = name.kind, name.value, subtree.base.value
    if kind == "directoryName":
        return asn1core.within(value, base)  # type: ignore[arg-type]
    if kind == "iPAddress":
        if len(value) not in (4, 16):  # type: ignore[arg-type]
            raise MalformedExtension("an iPAddress name is 4 or 16 octets (RFC 5280 sec. 4.2.1.6)")
        return _ip_within(value, base)  # type: ignore[arg-type]
    if not isinstance(value, str) or not isinstance(base, str):
        raise TypeError(f"{kind} names and subtrees hold strings")
    if kind == "dNSName":
        return _dns_within(value, base)
    if kind == "rfc822Name":
        if "@" in base:
            raise UnsupportedConstraint(
                "a mailbox name constraint (RFC 9549 sec. 2.2 removed them from RFC 5280 sec. 4.2.1.10)"
            )
        local, at, host = value.rpartition("@")
        if not at or not local or not host:
            raise MalformedExtension(f"rfc822Name {value!r} is not local-part@host")
        return _host_within(host, base)
    # uniformResourceIdentifier
    host_name = _uri_host(value)
    if host_name is None:
        return False  # sec. 4.2.1.10: such a URI under a URI constraint is rejected
    return _host_within(host_name, base)


def constraint_holds(
    name: GeneralName, constraints: NameConstraints, at_issuance: bool = False
) -> bool:
    """RFC 5280 sec. 6.1.3(b) and (c) for one name: permitted somewhere, and excluded nowhere.

    `at_issuance` is the exception the section gives self-issued certificates: "If certificate i is
    self-issued and it is not the final certificate in the path, skip this step". A caller that knows
    the certificate is such an intermediate passes True and gets True without a comparison.

    A name form with no constraint of its kind is acceptable ("Restrictions apply only when the
    specified name form is present"). Raises `UnsupportedConstraint` when a constraint covers a form
    this module does not evaluate, or carries a minimum or maximum that is not 0 and absent, because
    section 4.2.1.10 requires processing those or rejecting the certificate.
    """
    if at_issuance:
        return True
    kind = name.kind
    permitted = constraints.permitted.get(kind)
    excluded = constraints.excluded.get(kind, ())
    if permitted is None and not excluded:
        return True
    if kind not in _SUPPORTED:
        raise UnsupportedConstraint(
            f"a name constraint covers {kind}, which pkix does not evaluate"
        )
    for subtree in (*excluded, *(permitted or ())):
        if subtree.minimum != 0 or subtree.maximum is not None:
            raise UnsupportedConstraint(
                "a name constraint has a minimum other than 0 or a maximum "
                "(RFC 5280 sec. 4.2.1.10 requires minimum 0 and maximum absent)"
            )
    if any(_within(name, s) for s in excluded):
        return False
    return permitted is None or any(_within(name, s) for s in permitted)


def certificate_names(
    certificate: asn1core.Certificate, constraints: NameConstraints
) -> list[GeneralName]:
    """The names sections 4.2.1.10 and 6.1.3(b) apply constraints to.

    The subject distinguished name when non-empty; every subjectAltName entry; and, when the
    certificate has no subjectAltName and rfc822Name is constrained, each emailAddress attribute of
    the subject ("the rfc822Name constraint MUST be applied to the attribute of type emailAddress").
    """
    names: list[GeneralName] = []
    if certificate.subject.rdnsets:
        names.append(GeneralName("directoryName", certificate.subject))
    alt = parse_subject_alt_name(certificate.extension(SUBJECT_ALT_NAME))
    if alt is not None:
        names.extend(alt)
    elif "rfc822Name" in constraints.permitted or "rfc822Name" in constraints.excluded:
        for rdn in certificate.subject.rdnsets:
            names.extend(
                GeneralName("rfc822Name", attribute.value)
                for attribute in rdn
                if attribute.oid == EMAIL_ADDRESS
            )
    return names


def check_certificate(
    certificate: asn1core.Certificate, constraints: NameConstraints, *, final: bool
) -> tuple[NameViolation, ...]:
    """RFC 5280 sec. 6.1.3(b) and (c) for one certificate of a path; empty means both steps hold.

    `final` says it is the last certificate of the path, the one self-issued certificates are not
    exempt for. The two steps are told apart in each violation's `reason`.
    """
    if certificate.self_issued and not final:
        return ()
    found: list[NameViolation] = []
    for name in certificate_names(certificate, constraints):
        if constraint_holds(name, constraints):
            continue
        in_excluded = any(_within(name, s) for s in constraints.excluded.get(name.kind, ()))
        found.append(NameViolation(name, "excluded" if in_excluded else "not_permitted"))
    return tuple(found)
