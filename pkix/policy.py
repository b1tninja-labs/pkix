"""Certificate policy processing: RFC 5280 section 6.1 with RFC 9618's policy graph.

RFC 5280 sections 6.1.2 to 6.1.6 describe a `valid_policy_tree` that grows exponentially when several
issuer policies map to one subject policy. RFC 9618 section 4 replaces the tree with a directed
acyclic `valid_policy_graph`, "bounded linearly by the total number of certificate policies and
policy mappings", and its sections 5.2 to 5.6 are the replacement text for the steps that touch it.
This module is that procedure: the graph has at most one node per (depth, policy OID), a node names
its parents by OID, and nothing here ever expands the graph back into a tree (RFC 9618 section 5.6:
"Computing this structure is NOT RECOMMENDED").

Steps not touched by RFC 9618 are RFC 5280's: the explicit_policy, policy_mapping and
inhibit_anyPolicy counters of section 6.1.2(d) to (f), their decrement and reduction in section
6.1.4(h) to (j), and the wrap-up of section 6.1.5(a) and (b). The other steps of section 6.1 (name
constraints, signatures, basic constraints) are other modules' and this one does not make them.

The input is the path in the order `pkix.chain.candidates()` returns it, target first, without the
trust anchor, because RFC 5280 section 6.1.1(a) keeps the anchor a separate input. Policy information
carried by the anchor is not processed, as section 6.1 specifies.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import asn1core

from .extensions import (
    ANY_POLICY,
    CERTIFICATE_POLICIES,
    INHIBIT_ANY_POLICY,
    POLICY_CONSTRAINTS,
    POLICY_MAPPINGS,
    PolicyInformation,
    parse_certificate_policies,
    parse_inhibit_any_policy,
    parse_policy_constraints,
    parse_policy_mappings,
)

__all__ = [
    "PolicyOutcome",
    "resolve",
]


@dataclass(slots=True)
class _Node:
    policy: str
    qualifiers: frozenset[bytes]
    expected: set[str]
    parents: set[str] = field(default_factory=set)  # policy OIDs of the depth above


@dataclass(frozen=True, slots=True)
class PolicyOutcome:
    """What RFC 5280 section 6.1.6 returns, as RFC 9618 section 5.6 rewrites it.

    `succeeded` is the closing test of section 6.1.5: "either (1) the value of explicit_policy is
    greater than zero, or (2) the user_constrained_policy_set is not empty". A False carries a
    `reason` naming the step that failed.

    The valid_policy_tree is not an output (RFC 9618 section 4.2): `authority_constrained` and
    `user_constrained` map each policy OID to the qualifiers collected for it, as DER, sorted.
    `graph_nodes` is the size of the final graph and is reported so a caller, and a test, can see it
    stays linear in the certificates.
    """

    succeeded: bool
    reason: str | None
    explicit_policy: int
    authority_constrained: Mapping[str, tuple[bytes, ...]]
    user_constrained: Mapping[str, tuple[bytes, ...]]
    graph_nodes: int


class _Graph:
    """The valid_policy_graph: one dict of nodes per depth, keyed by valid_policy."""

    def __init__(self) -> None:
        self.levels: list[dict[str, _Node]] = [
            {ANY_POLICY: _Node(ANY_POLICY, frozenset(), {ANY_POLICY})}
        ]

    def size(self) -> int:
        return sum(len(level) for level in self.levels)

    def prune(self, through: int) -> None:
        """Delete childless nodes at depth `through` and shallower, upward (steps (d)(3), (b)(3)(ii))."""
        for depth in range(min(through, len(self.levels) - 2), -1, -1):
            below = self.levels[depth + 1]
            has_child = {parent for node in below.values() for parent in node.parents}
            self.levels[depth] = {k: v for k, v in self.levels[depth].items() if k in has_child}

    def empty_at(self, depth: int) -> bool:
        return not self.levels[depth]


def _process_policies(
    graph: _Graph,
    depth: int,
    policies: Sequence[PolicyInformation],
    inhibit_any_policy: int,
    self_issued: bool,
    final: bool,
) -> None:
    """RFC 9618 section 5.3, step (d)(1) to (3), for certificate number `depth`."""
    above = graph.levels[depth - 1]
    level: dict[str, _Node] = {}
    graph.levels.append(level)
    any_qualifiers: frozenset[bytes] | None = None
    for info in policies:
        if info.policy == ANY_POLICY:
            any_qualifiers = frozenset(info.qualifiers)
            continue
        qualifiers = frozenset(info.qualifiers)
        # (d)(1)(i): parents are the depth i-1 nodes whose expected_policy_set holds P-OID.
        parents = {node.policy for node in above.values() if info.policy in node.expected}
        if parents:
            level[info.policy] = _Node(info.policy, qualifiers, {info.policy}, parents)
        elif ANY_POLICY in above:
            # (d)(1)(ii): no match, so hang it from the anyPolicy node of depth i-1.
            level[info.policy] = _Node(info.policy, qualifiers, {info.policy}, {ANY_POLICY})
    if any_qualifiers is not None and (inhibit_any_policy > 0 or (not final and self_issued)):
        # (d)(2): each expected policy value (anyPolicy included) not already a node at depth i.
        wanted = {value for node in above.values() for value in node.expected}
        for value in sorted(wanted):
            if value in level:
                continue
            parents = {node.policy for node in above.values() if value in node.expected}
            level[value] = _Node(value, any_qualifiers, {value}, parents)
    graph.prune(depth - 1)


def _apply_mappings(
    graph: _Graph,
    depth: int,
    mappings: Sequence[tuple[str, str]],
    policy_mapping: int,
    any_qualifiers: frozenset[bytes],
) -> None:
    """RFC 9618 section 5.4, step (b), for certificate number `depth` (the one just processed)."""
    equivalents: dict[str, set[str]] = {}
    for issuer_domain, subject_domain in mappings:
        equivalents.setdefault(issuer_domain, set()).add(subject_domain)
    level = graph.levels[depth]
    for issuer_domain, subjects in equivalents.items():
        if policy_mapping > 0:
            if issuer_domain in level:
                level[issuer_domain].expected = set(subjects)  # (b)(1)
            elif ANY_POLICY in level:
                # (b)(2): a child of the anyPolicy node of depth i-1.
                level[issuer_domain] = _Node(
                    issuer_domain, any_qualifiers, set(subjects), {ANY_POLICY}
                )
        else:
            level.pop(issuer_domain, None)  # (b)(3)(i)
    if policy_mapping == 0:
        graph.prune(depth - 1)  # (b)(3)(ii)


def _collect_qualifiers(graph: _Graph, depth: int, node: _Node) -> tuple[bytes, ...]:
    """The node's qualifiers with its ancestors' and descendants' (RFC 9618 section 5.5(g)(4)(ii))."""
    found: set[bytes] = set(node.qualifiers)
    frontier = {node.policy}
    for d in range(depth, 0, -1):
        parents = {p for policy in frontier for p in graph.levels[d][policy].parents}
        for parent in parents:
            found |= graph.levels[d - 1][parent].qualifiers
        frontier = parents
    frontier = {node.policy}
    for d in range(depth, len(graph.levels) - 1):
        children = {
            policy for policy, child in graph.levels[d + 1].items() if child.parents & frontier
        }
        for child_policy in children:
            found |= graph.levels[d + 1][child_policy].qualifiers
        frontier = children
    return tuple(sorted(found))


def _failure(reason: str, explicit_policy: int) -> PolicyOutcome:
    return PolicyOutcome(False, reason, explicit_policy, {}, {}, 0)


def resolve(
    chain: Sequence[bytes | asn1core.Certificate],
    expected: set[str] | None = None,
    *,
    initial_explicit_policy: bool = False,
    initial_policy_mapping_inhibit: bool = False,
    initial_inhibit_any_policy: bool = False,
) -> PolicyOutcome:
    """Policy processing of one path, RFC 5280 sec. 6.1.2 to 6.1.5 as replaced by RFC 9618 sec. 5.

    `chain` is target first and excludes the trust anchor. `expected` is the user-initial-policy-set
    as OIDs in dotted form, or None for any-policy. The three keyword flags are the inputs of section
    6.1.1(f), (g) and (h): each sets its counter to 0 instead of n+1.

    A policy failure is an outcome, not an exception: `succeeded` is False and `reason` says which
    step failed. A certificate whose policy extensions are not well-formed raises
    `MalformedExtension`, because a path with an unreadable extension has not been processed.
    """
    certificates = [
        c if isinstance(c, asn1core.Certificate) else asn1core.parse_certificate(c) for c in chain
    ]
    n = len(certificates)
    if n == 0:
        raise ValueError("a path has at least one certificate: RFC 5280 sec. 6.1.1(a)")
    explicit_policy = 0 if initial_explicit_policy else n + 1
    policy_mapping = 0 if initial_policy_mapping_inhibit else n + 1
    inhibit_any_policy = 0 if initial_inhibit_any_policy else n + 1

    graph: _Graph | None = _Graph()
    # Section 6.1 numbers the certificate nearest the anchor 1 and the target n.
    for i, certificate in enumerate(reversed(certificates), start=1):
        final = i == n
        policies = parse_certificate_policies(certificate.extension(CERTIFICATE_POLICIES))
        self_issued = certificate.self_issued
        if graph is not None:
            if policies is not None:
                _process_policies(graph, i, policies, inhibit_any_policy, self_issued, final)
                if graph.empty_at(i):
                    graph = None  # no valid policies remain, so the graph is NULL
            else:
                graph = None  # (e)
        if explicit_policy == 0 and graph is None:  # (f)
            return _failure(
                f"certificate {i}: explicit_policy is 0 and the valid_policy_graph is NULL "
                "(RFC 5280 sec. 6.1.3(f))",
                0,
            )
        constraints = parse_policy_constraints(certificate.extension(POLICY_CONSTRAINTS))
        if final:
            if explicit_policy != 0:  # 6.1.5(a)
                explicit_policy -= 1
            if constraints is not None and constraints.require_explicit_policy == 0:  # 6.1.5(b)
                explicit_policy = 0
            continue
        mappings = parse_policy_mappings(certificate.extension(POLICY_MAPPINGS))
        if mappings is not None:
            if any(ANY_POLICY in pair for pair in mappings):
                return _failure(
                    f"certificate {i}: a policy mapping names anyPolicy (RFC 5280 sec. 6.1.4(a))",
                    explicit_policy,
                )
            if graph is not None:
                any_qualifiers: frozenset[bytes] = frozenset()
                for info in policies or ():
                    if info.policy == ANY_POLICY:
                        any_qualifiers = frozenset(info.qualifiers)
                _apply_mappings(graph, i, mappings, policy_mapping, any_qualifiers)
                if graph.empty_at(i):
                    graph = None
        if not self_issued:  # (h)
            explicit_policy = max(explicit_policy - 1, 0)
            policy_mapping = max(policy_mapping - 1, 0)
            inhibit_any_policy = max(inhibit_any_policy - 1, 0)
        if constraints is not None:  # (i)
            if constraints.require_explicit_policy is not None:
                explicit_policy = min(explicit_policy, constraints.require_explicit_policy)
            if constraints.inhibit_policy_mapping is not None:
                policy_mapping = min(policy_mapping, constraints.inhibit_policy_mapping)
        skip = parse_inhibit_any_policy(certificate.extension(INHIBIT_ANY_POLICY))
        if skip is not None:  # (j)
            inhibit_any_policy = min(inhibit_any_policy, skip)

    authority: dict[str, tuple[bytes, ...]] = {}
    size = 0
    if graph is not None:
        size = graph.size()
        # RFC 9618 section 5.5(g)(2) and (3).
        for depth, level in enumerate(graph.levels):
            for node in level.values():
                if (node.policy != ANY_POLICY and node.parents == {ANY_POLICY}) or (
                    node.policy == ANY_POLICY and depth == n
                ):
                    authority[node.policy] = _collect_qualifiers(graph, depth, node)
    user = dict(authority)
    if expected is not None:  # (g)(6)
        user = {policy: q for policy, q in authority.items() if policy in expected}
        if ANY_POLICY in authority:
            for policy in expected:
                user.setdefault(policy, authority[ANY_POLICY])
    if explicit_policy > 0 or user:
        return PolicyOutcome(True, None, explicit_policy, authority, user, size)
    return PolicyOutcome(
        False,
        "explicit_policy is 0 and the user_constrained_policy_set is empty (RFC 9618 sec. 5.5)",
        explicit_policy,
        authority,
        user,
        size,
    )
