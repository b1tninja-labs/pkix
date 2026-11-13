"""Name constraints: RFC 5280 sections 4.2.1.10, 6.1.3(b)-(c) and 6.1.4(g), with RFC 9549's changes."""

from __future__ import annotations

import ipaddress

import asn1core
import pytest
from builders import certificate, dn
from cryptography import x509

from pkix.errors import MalformedExtension, UnsupportedConstraint
from pkix.names import (
    GeneralName,
    NameConstraints,
    Subtree,
    check_certificate,
    constraint_holds,
    parse_name_constraints,
    parse_subject_alt_name,
)


def sub(kind: str, base, minimum: int = 0, maximum: int | None = None) -> Subtree:
    return Subtree(GeneralName(kind, base), minimum, maximum)


def permit(kind: str, *bases) -> NameConstraints:
    return NameConstraints(permitted={kind: tuple(sub(kind, b) for b in bases)})


def exclude(kind: str, *bases) -> NameConstraints:
    return NameConstraints(excluded={kind: tuple(sub(kind, b) for b in bases)})


def holds(kind: str, value, constraints: NameConstraints) -> bool:
    return constraint_holds(GeneralName(kind, value), constraints)


def ip(text: str, mask: str | None = None) -> bytes:
    base = ipaddress.ip_address(text).packed
    if mask is None:
        return base
    return base + ipaddress.ip_address(mask).packed


def test_a_name_form_with_no_constraint_is_acceptable():
    """Sec. 4.2.1.10: "Restrictions apply only when the specified name form is present"."""
    constraints = permit("dNSName", "example.com")
    assert holds("rfc822Name", "a@other.org", constraints)
    assert holds("iPAddress", ip("10.0.0.1"), constraints)


def test_dns_constraint_adds_zero_or_more_labels_on_the_left():
    """Sec. 4.2.1.10 DNS paragraph: www.host.example.com satisfies host.example.com, host1 does not."""
    constraints = permit("dNSName", "host.example.com")
    assert holds("dNSName", "host.example.com", constraints)
    assert holds("dNSName", "www.host.example.com", constraints)
    assert not holds("dNSName", "host1.example.com", constraints)
    assert not holds("dNSName", "xhost.example.com", constraints)


def test_dns_comparison_ignores_case_and_matches_whole_labels():
    """RFC 9549 sec. 2.3: a case-insensitive exact match on a label-by-label basis."""
    constraints = permit("dNSName", "Example.COM")
    assert holds("dNSName", "WWW.example.com", constraints)
    assert not holds("dNSName", "notexample.com", constraints)


def test_excluded_wins_over_permitted():
    """Sec. 4.2.1.10: an excluded match is invalid "regardless of" the permitted subtrees."""
    constraints = NameConstraints(
        permitted={"dNSName": (sub("dNSName", "example.com"),)},
        excluded={"dNSName": (sub("dNSName", "bad.example.com"),)},
    )
    assert holds("dNSName", "good.example.com", constraints)
    assert not holds("dNSName", "x.bad.example.com", constraints)


def test_a_permitted_set_that_intersected_to_nothing_permits_nothing():
    """Sec. 6.1.4(g)(1): the intersection of example.com and example.net is the empty set."""
    state = permit("dNSName", "example.com").restrict(permit("dNSName", "example.net"))
    assert state.permitted["dNSName"] == ()
    assert not holds("dNSName", "example.com", state)
    assert not holds("dNSName", "example.net", state)


def test_intersection_keeps_the_narrower_subtree():
    """Sec. 6.1.4(g)(1): the intersection of example.com and foo.example.com is foo.example.com."""
    state = permit("dNSName", "example.com").restrict(permit("dNSName", "foo.example.com"))
    assert [s.base.value for s in state.permitted["dNSName"]] == ["foo.example.com"]
    assert holds("dNSName", "a.foo.example.com", state)
    assert not holds("dNSName", "bar.example.com", state)


def test_a_name_type_the_new_extension_omits_is_unchanged():
    """Sec. 6.1.4(g)(1): "If permittedSubtrees does not include a particular name type, the
    permitted_subtrees state variable is unchanged for that name type"."""
    state = permit("dNSName", "example.com").restrict(permit("rfc822Name", "example.com"))
    assert holds("dNSName", "a.example.com", state)
    assert not holds("dNSName", "a.example.org", state)
    assert not holds("rfc822Name", "x@example.org", state)


def test_excluded_subtrees_are_a_union():
    """Sec. 6.1.4(g)(2): the union of example.com and example.net is both name spaces."""
    state = exclude("dNSName", "example.com").restrict(exclude("dNSName", "example.net"))
    assert not holds("dNSName", "a.example.com", state)
    assert not holds("dNSName", "a.example.net", state)
    assert holds("dNSName", "a.example.org", state)


def test_a_dotted_dns_constraint_needs_at_least_one_label():
    """Not in the DNS paragraph; read as the URI and mailbox paragraphs read a leading period."""
    constraints = permit("dNSName", ".example.com")
    assert holds("dNSName", "host.example.com", constraints)
    assert not holds("dNSName", "example.com", constraints)


def test_email_constraint_on_a_host_and_on_a_domain():
    """Sec. 4.2.1.10 mailbox paragraph, as RFC 9549 sec. 2.2 leaves it."""
    host = permit("rfc822Name", "example.com")
    assert holds("rfc822Name", "root@example.com", host)
    assert holds("rfc822Name", "root@EXAMPLE.com", host)
    assert not holds("rfc822Name", "root@sub.example.com", host)
    domain = permit("rfc822Name", ".example.com")
    assert holds("rfc822Name", "root@sub.example.com", domain)
    assert not holds("rfc822Name", "root@example.com", domain)


def test_a_mailbox_constraint_is_refused_because_rfc_9549_removed_it():
    with pytest.raises(UnsupportedConstraint, match="mailbox"):
        holds("rfc822Name", "root@example.com", permit("rfc822Name", "root@example.com"))


def test_an_email_name_without_a_host_is_malformed():
    with pytest.raises(MalformedExtension):
        holds("rfc822Name", "no-at-sign", permit("rfc822Name", "example.com"))


def test_uri_constraint_applies_to_the_host_part():
    """Sec. 4.2.1.10 URI paragraph: ".example.com" is satisfied by host.example.com, not example.com."""
    domain = permit("uniformResourceIdentifier", ".example.com")
    assert holds("uniformResourceIdentifier", "https://host.example.com:8443/p?q#f", domain)
    assert holds("uniformResourceIdentifier", "https://u:p@my.host.example.com/", domain)
    assert not holds("uniformResourceIdentifier", "https://example.com/", domain)
    host = permit("uniformResourceIdentifier", "host.example.com")
    assert holds("uniformResourceIdentifier", "ftp://HOST.example.com/x", host)
    assert not holds("uniformResourceIdentifier", "ftp://a.host.example.com/x", host)


@pytest.mark.parametrize(
    "uri",
    [
        "mailto:a@example.com",
        "https://192.0.2.1/",
        "https://[2001:db8::1]/",
        "urn:example:x",
        "/rel",
    ],
)
def test_a_uri_with_no_fqdn_host_is_rejected_under_a_uri_constraint(uri):
    """Sec. 4.2.1.10: no authority, or an IP address as the host, "the application MUST reject"."""
    constrained = permit("uniformResourceIdentifier", ".example.com")
    assert not holds("uniformResourceIdentifier", uri, constrained)
    # ... but only when a URI constraint exists: with none, the name form is unconstrained.
    assert holds("uniformResourceIdentifier", uri, permit("dNSName", "example.com"))


def test_ipv4_constraint_is_an_address_and_a_mask():
    """Sec. 4.2.1.10: 192.0.2.0/24 is C0 00 02 00 FF FF FF 00."""
    constraints = permit("iPAddress", ip("192.0.2.0", "255.255.255.0"))
    assert constraints.permitted["iPAddress"][0].base.value == bytes.fromhex("c0000200ffffff00")
    assert holds("iPAddress", ip("192.0.2.77"), constraints)
    assert not holds("iPAddress", ip("192.0.3.1"), constraints)
    # A different family is not in the subtree.
    assert not holds("iPAddress", ip("2001:db8::1"), constraints)


def test_ipv6_constraint_and_exclusion():
    constraints = NameConstraints(
        permitted={"iPAddress": (sub("iPAddress", ip("2001:db8::", "ffff:ffff::")),)},
        excluded={"iPAddress": (sub("iPAddress", ip("2001:db8:1::", "ffff:ffff:ffff::")),)},
    )
    assert holds("iPAddress", ip("2001:db8:2::1"), constraints)
    assert not holds("iPAddress", ip("2001:db8:1::1"), constraints)


def test_ip_intersection_keeps_the_narrower_network():
    state = permit("iPAddress", ip("10.0.0.0", "255.0.0.0")).restrict(
        permit("iPAddress", ip("10.1.0.0", "255.255.0.0"))
    )
    assert holds("iPAddress", ip("10.1.2.3"), state)
    assert not holds("iPAddress", ip("10.2.0.1"), state)


def test_directory_name_constraint_is_a_prefix_of_rdns():
    """Sec. 4.2.1.10 and sec. 7.1: the constraint's RDNs match the leading RDNs of the name."""
    base = certificate(dn("Org", "Unit"), dn("Issuer")).subject
    inside = certificate(dn("Org", "Unit", "leaf"), dn("I")).subject
    outside = certificate(dn("Other", "Unit"), dn("I")).subject
    constraints = permit("directoryName", base)
    assert holds("directoryName", inside, constraints)
    assert holds("directoryName", base, constraints)
    assert not holds("directoryName", outside, constraints)


def test_a_constraint_on_an_unevaluated_form_is_refused_not_guessed():
    """Sec. 4.2.1.10: "MUST either process the constraint or reject the certificate"."""
    constraints = permit("otherName", b"\xa0\x00")
    with pytest.raises(UnsupportedConstraint, match="otherName"):
        holds("otherName", b"\xa0\x00", constraints)


def test_a_nonzero_minimum_or_a_maximum_is_refused():
    """Sec. 4.2.1.10: "the minimum MUST be zero, and maximum MUST be absent"; otherwise process or reject."""
    for subtree in (
        sub("dNSName", "example.com", minimum=1),
        sub("dNSName", "example.com", maximum=2),
    ):
        with pytest.raises(UnsupportedConstraint, match="minimum"):
            holds("dNSName", "a.example.com", NameConstraints(permitted={"dNSName": (subtree,)}))


def test_the_issuance_exception_skips_the_comparison():
    """Sec. 6.1.3(b): a self-issued certificate that is not the last "skip this step"."""
    constraints = permit("dNSName", "example.com")
    name = GeneralName("dNSName", "evil.example.org")
    assert constraint_holds(name, constraints, at_issuance=True)
    assert not constraint_holds(name, constraints)


# --- decoding and whole-certificate checks, against certificates minted by cryptography ----------


def test_name_constraints_decode_matches_what_cryptography_minted():
    cert = certificate(
        dn("ca"),
        dn("root"),
        [
            (
                x509.NameConstraints(
                    [
                        x509.DNSName("example.com"),
                        x509.IPAddress(ipaddress.ip_network("192.0.2.0/24")),
                        x509.RFC822Name("example.org"),
                    ],
                    [x509.UniformResourceIdentifier(".bad.example.com")],
                ),
                True,
            )
        ],
    )
    parsed = parse_name_constraints(cert.extension("2.5.29.30"))
    assert parsed is not None
    assert parsed.permitted["dNSName"][0].base.value == "example.com"
    assert parsed.permitted["iPAddress"][0].base.value == bytes.fromhex("c0000200ffffff00")
    assert parsed.excluded["uniformResourceIdentifier"][0].base.value == ".bad.example.com"
    assert parse_name_constraints(None) is None


def test_an_empty_name_constraints_sequence_is_malformed():
    """Sec. 4.2.1.10: "Conforming CAs MUST NOT issue certificates where name constraints is an
    empty sequence"."""
    ext = asn1core.Extension((2, 5, 29, 30), True, b"\x30\x00", b"")
    with pytest.raises(MalformedExtension, match="empty"):
        parse_name_constraints(ext)


def test_subject_alt_name_decodes_every_form_the_check_uses():
    cert = certificate(
        dn("leaf"),
        dn("ca"),
        [
            (
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("a.example.com"),
                        x509.RFC822Name("u@example.com"),
                        x509.IPAddress(ipaddress.ip_address("192.0.2.9")),
                        x509.UniformResourceIdentifier("https://a.example.com/"),
                        x509.DirectoryName(dn("x")),
                    ]
                ),
                False,
            )
        ],
    )
    names = parse_subject_alt_name(cert.extension("2.5.29.17"))
    assert names is not None
    assert [n.kind for n in names] == [
        "dNSName",
        "rfc822Name",
        "iPAddress",
        "uniformResourceIdentifier",
        "directoryName",
    ]
    assert names[2].value == bytes([192, 0, 2, 9])


def _alt(*names: x509.GeneralName) -> tuple[x509.ExtensionType, bool]:
    return x509.SubjectAlternativeName(list(names)), False


def _mailbox_san(value: str, *, type_id: str = "1.3.6.1.5.5.7.8.9") -> x509.GeneralName:
    """An otherName holding a UTF8String, as RFC 9598 sec. 3 encodes SmtpUTF8Mailbox."""
    text = value.encode()
    assert len(text) < 128
    return x509.OtherName(x509.ObjectIdentifier(type_id), bytes([0x0C, len(text)]) + text)


def test_an_smtp_utf8_mailbox_is_read_and_compared_under_the_rfc822_constraints():
    """Row `names.smtp_utf8_mailbox`: RFC 9598 sec. 3 (the otherName) and sec. 6 (the constraint)."""
    cert = certificate(
        dn("leaf"),
        dn("ca"),
        [_alt(_mailbox_san("学生@elementary.school.example.com"))],
    )
    (name,) = parse_subject_alt_name(cert.extension("2.5.29.17")) or ()
    assert (name.kind, name.value) == ("SmtpUTF8Mailbox", "学生@elementary.school.example.com")
    # Figure 1 of RFC 9598: one rfc822Name constraint covers both forms of the address.
    host = permit("rfc822Name", "elementary.school.example.com")
    assert check_certificate(cert, host, final=True) == ()
    assert [
        v.reason for v in check_certificate(cert, permit("rfc822Name", "example.org"), final=True)
    ] == ["not_permitted"]
    assert [
        v.reason
        for v in check_certificate(cert, exclude("rfc822Name", ".school.example.com"), final=True)
    ] == ["excluded"]
    # Figure 1 (2): the domain is an A-label, compared octet for octet after lowercasing.
    assert holds(
        "SmtpUTF8Mailbox",
        "医生@XN--PSS25C.example.com",
        permit("rfc822Name", "xn--pss25c.example.com"),
    )
    # A dNSName constraint says nothing about a mailbox.
    assert holds("SmtpUTF8Mailbox", "学@a.example.com", permit("dNSName", "other.example"))
    # A mailbox constraint is still refused (RFC 9549 sec. 2.2), whichever form meets it.
    with pytest.raises(UnsupportedConstraint, match="mailbox"):
        holds("SmtpUTF8Mailbox", "学@a.example.com", permit("rfc822Name", "学@a.example.com"))


def test_a_malformed_smtp_utf8_mailbox_is_refused_and_another_other_name_stays_opaque():
    def read(*names: x509.GeneralName):
        cert = certificate(dn("leaf"), dn("ca"), [_alt(*names)])
        return parse_subject_alt_name(cert.extension("2.5.29.17"))

    for bad in (
        "﻿学@a.example.com",  # a byte order mark (sec. 3)
        "学@例え.example.com",  # a U-label domain (sec. 3)
        "学",  # no domain
        "@a.example.com",  # no local part
    ):
        with pytest.raises(MalformedExtension):
            read(_mailbox_san(bad))
    other = read(_mailbox_san("x@y", type_id="1.3.6.1.4.1.99999.1"))
    assert other is not None
    assert other[0].kind == "otherName"
    # The type-id is the only thing that makes it a mailbox: an unconstrained other form is fine.
    assert holds("otherName", b"", NameConstraints())


def test_check_certificate_checks_subject_and_every_alternative_name():
    constraints = permit("dNSName", "example.com")
    ok = certificate(dn("leaf"), dn("ca"), [_alt(x509.DNSName("a.example.com"))])
    bad = certificate(
        dn("leaf"),
        dn("ca"),
        [_alt(x509.DNSName("a.example.com"), x509.DNSName("b.example.org"))],
    )
    assert check_certificate(ok, constraints, final=True) == ()
    violations = check_certificate(bad, constraints, final=True)
    assert [(v.name.value, v.reason) for v in violations] == [("b.example.org", "not_permitted")]
    excluded = check_certificate(ok, exclude("dNSName", "example.com"), final=True)
    assert [v.reason for v in excluded] == ["excluded"]


def test_a_subject_directory_name_is_checked_and_an_empty_one_is_not():
    """Sec. 4.2.1.10: directoryName constraints apply to the subject "when the certificate includes
    a non-empty subject field"."""
    base = certificate(dn("Org"), dn("r")).subject
    constraints = permit("directoryName", base)
    assert check_certificate(certificate(dn("Org", "x"), dn("ca")), constraints, final=True) == ()
    violations = check_certificate(certificate(dn("Elsewhere"), dn("ca")), constraints, final=True)
    assert [v.reason for v in violations] == ["not_permitted"]
    empty = certificate(
        x509.Name([]),
        dn("ca"),
        [(x509.SubjectAlternativeName([x509.DNSName("a.example.com")]), True)],
    )
    assert check_certificate(empty, constraints, final=True) == ()


def test_self_issued_certificates_are_exempt_unless_final():
    """Sec. 6.1.3(b)/(c) and 4.2.1.10: "unless the certificate is the final certificate in the path"."""
    constraints = permit("dNSName", "example.com")
    name = dn("same")
    self_issued = certificate(name, name, [_alt(x509.DNSName("evil.example.org"))])
    assert check_certificate(self_issued, constraints, final=False) == ()
    assert len(check_certificate(self_issued, constraints, final=True)) == 1


def test_email_in_the_subject_is_constrained_when_there_is_no_alt_name():
    """Sec. 4.2.1.10: with rfc822Name constraints and no subjectAltName, the constraint "MUST be
    applied to the attribute of type emailAddress in the subject distinguished name"."""
    constraints = permit("rfc822Name", "example.com")
    inside = certificate(dn("u", email="u@example.com"), dn("ca"))
    outside = certificate(dn("u", email="u@example.org"), dn("ca"))
    assert check_certificate(inside, constraints, final=True) == ()
    assert [v.name.value for v in check_certificate(outside, constraints, final=True)] == [
        "u@example.org"
    ]
    with_alt = certificate(
        dn("u", email="u@example.org"), dn("ca"), [_alt(x509.DNSName("a.example.com"))]
    )
    assert check_certificate(with_alt, constraints, final=True) == ()
