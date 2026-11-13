"""Policy processing: RFC 5280 section 6.1 as replaced by RFC 9618 section 5 (the policy graph).

Paths are written target first, as `chain.candidates()` returns them, without the trust anchor.
"""

from __future__ import annotations

import time

import asn1core
from builders import certificate, dn, oid
from cryptography import x509

from pkix.policy import resolve

ANY = "2.5.29.32.0"
A, B, C, D = (
    "1.3.6.1.4.1.99999.1",
    "1.3.6.1.4.1.99999.2",
    "1.3.6.1.4.1.99999.3",
    "1.3.6.1.4.1.99999.4",
)


def pol(*policies: str) -> tuple[x509.ExtensionType, bool]:
    return x509.CertificatePolicies([x509.PolicyInformation(oid(p), None) for p in policies]), False


def _tlv(tag: int, body: bytes) -> bytes:
    assert len(body) < 128 or len(body) < 65536
    if len(body) < 128:
        return bytes([tag, len(body)]) + body
    return bytes([tag, 0x82]) + len(body).to_bytes(2, "big") + body


def _oid_der(dotted: str) -> bytes:
    return _tlv(6, asn1core.encode_oid(tuple(int(a) for a in dotted.split("."))))


def mapping(*pairs: tuple[str, str]) -> tuple[x509.ExtensionType, bool]:
    """PolicyMappings is not in `cryptography`'s API, so it goes in as DER (RFC 5280 sec. 4.2.1.5)."""
    body = b"".join(_tlv(0x30, _oid_der(a) + _oid_der(b)) for a, b in pairs)
    return x509.UnrecognizedExtension(oid("2.5.29.33"), _tlv(0x30, body)), False


def constraints(require=None, inhibit=None) -> tuple[x509.ExtensionType, bool]:
    return x509.PolicyConstraints(require, inhibit), True


def path(*extension_sets: list) -> list:
    """Certificates target first; each argument is one certificate's extensions, leaf first."""
    return [
        certificate(dn(f"cert{i}"), dn(f"cert{i + 1}"), exts)
        for i, exts in enumerate(extension_sets)
    ]


def test_a_path_with_matching_policies_succeeds_with_the_common_set():
    outcome = resolve(path([pol(A, B)], [pol(A, B, C)]))
    assert outcome.succeeded
    assert set(outcome.user_constrained) == {A, B}


def test_a_policy_the_ca_does_not_assert_is_not_valid():
    outcome = resolve(path([pol(A, D)], [pol(A, B)]))
    assert set(outcome.authority_constrained) == {A}


def test_user_initial_policy_set_intersects_the_result():
    """RFC 9618 sec. 5.5(g)(6)(i): elements outside the user-initial-policy-set are removed."""
    chain = path([pol(A, B)], [pol(A, B)])
    assert set(resolve(chain, {A}).user_constrained) == {A}
    assert not resolve(chain, {C}, initial_explicit_policy=True).succeeded


def test_any_policy_in_the_path_is_returned_as_any_policy():
    outcome = resolve(path([pol(ANY)], [pol(ANY)]))
    assert outcome.succeeded
    assert set(outcome.user_constrained) == {ANY}


def test_any_policy_in_the_user_set_case_expands_to_the_users_policies():
    """RFC 9618 sec. 5.5(g)(6)(ii): anyPolicy in the authority set admits each user-initial policy."""
    outcome = resolve(path([pol(ANY)], [pol(ANY)]), {A, B})
    assert set(outcome.user_constrained) == {A, B}


def test_a_leaf_policy_under_an_any_policy_ca_is_valid():
    """RFC 9618 sec. 5.3(d)(1)(ii): no match, but an anyPolicy node of depth i-1 exists."""
    outcome = resolve(path([pol(A)], [pol(ANY)]))
    assert set(outcome.user_constrained) == {A}


def test_explicit_policy_required_and_no_policies_fails():
    """RFC 5280 sec. 6.1.3(e), (f): no certificatePolicies makes the graph NULL, and with
    explicit_policy at 0 that fails."""
    chain = path([], [pol(A)])
    assert resolve(chain).succeeded  # not required: a NULL graph is acceptable
    outcome = resolve(chain, initial_explicit_policy=True)
    assert not outcome.succeeded
    assert "6.1.3(f)" in (outcome.reason or "")


def test_require_explicit_policy_in_a_ca_turns_the_requirement_on_below_it():
    """Sec. 6.1.4(i)(1): requireExplicitPolicy 0 in the CA makes explicit_policy 0 for the leaf."""
    ca = [pol(A), constraints(require=0)]
    assert not resolve(path([], ca)).succeeded
    assert resolve(path([pol(A)], ca)).succeeded


def test_require_explicit_policy_of_zero_in_the_target_is_honoured_at_wrap_up():
    """Sec. 6.1.5(b): requireExplicitPolicy 0 in the final certificate sets explicit_policy to 0."""
    assert not resolve(path([constraints(require=0)], [pol(A)])).succeeded
    assert resolve(path([pol(A), constraints(require=0)], [pol(A)])).succeeded


def test_the_explicit_policy_counter_counts_non_self_issued_certificates():
    """Sec. 6.1.4(h)(1): requireExplicitPolicy N bites after N more non-self-issued certificates."""
    ca = [pol(A), constraints(require=1)]
    inter = [pol(A)]
    # CA requires explicit policy after 1 more certificate: the intermediate is fine, the leaf is not.
    assert resolve(path([pol(A)], inter, ca)).succeeded
    assert not resolve(path([], inter, ca)).succeeded


def test_policy_mapping_maps_the_issuer_policy_to_the_subject_policy():
    """Sec. 6.1.4(b)(1) in RFC 9618 sec. 5.4: the CA's A is equivalent to the leaf's B."""
    chain = path([pol(B)], [pol(A), mapping((A, B))])
    outcome = resolve(chain, {A})
    assert outcome.succeeded
    assert set(outcome.user_constrained) == {A}


def test_a_policy_not_mapped_does_not_satisfy_the_ca_policy():
    chain = path([pol(C)], [pol(A), mapping((A, B))])
    outcome = resolve(chain, None)
    assert set(outcome.authority_constrained) == set()  # A has no child: the leaf asserts only C


def test_inhibit_policy_mapping_deletes_the_mapped_node():
    """RFC 9618 sec. 5.4(b)(3): with policy_mapping 0 the node for ID-P is deleted."""
    chain = path([pol(B)], [pol(A), mapping((A, B))])
    outcome = resolve(chain, {A}, initial_policy_mapping_inhibit=True, initial_explicit_policy=True)
    assert not outcome.succeeded


def test_policy_constraints_inhibit_mapping_in_an_upstream_ca():
    upstream = [pol(A), constraints(inhibit=0)]
    mapped = [pol(A), mapping((A, B))]
    chain = path([pol(B)], mapped, upstream)
    # The mapping CA is at depth 2 with inhibitPolicyMapping 0 already in force.
    assert not resolve(chain, {A}, initial_explicit_policy=True).succeeded


def test_a_mapping_that_names_any_policy_fails():
    """Sec. 6.1.4(a)."""
    chain = path([pol(B)], [pol(A), mapping((A, ANY))])
    outcome = resolve(chain)
    assert not outcome.succeeded
    assert "6.1.4(a)" in (outcome.reason or "")


def test_inhibit_any_policy_stops_any_policy_matching():
    """Sec. 6.1.3(d)(2) with inhibit_anyPolicy 0: anyPolicy in the leaf no longer expands."""
    chain = path([pol(ANY)], [pol(A)])
    assert (
        resolve(chain, {A}, initial_inhibit_any_policy=True, initial_explicit_policy=True).succeeded
        is False
    )
    assert resolve(chain, {A}, initial_explicit_policy=True).succeeded


def test_inhibit_any_policy_extension_in_a_ca():
    ca = [pol(ANY), (x509.InhibitAnyPolicy(0), True)]
    chain = path([pol(ANY)], ca)
    assert not resolve(chain, {A}, initial_explicit_policy=True).succeeded


def test_a_self_issued_ca_with_any_policy_expands_even_when_any_policy_is_inhibited():
    """Row `policy.self_issued_any_policy`: RFC 9618 sec. 5.3(d)(2)(b), "i<n and the certificate is
    self-issued". inhibit_anyPolicy is 0 from the start, so (a) cannot apply and only (b) can carry
    the anyPolicy of the middle certificate over to A."""

    def build(middle_issuer: str):
        leaf = certificate(dn("leaf"), dn("mid"), [pol(A)])
        middle = certificate(dn("mid"), dn(middle_issuer), [pol(ANY)])
        root_ca = certificate(dn("mid-ca"), dn("root"), [pol(A)])
        # Target first; the path is root_ca (1), middle (2), leaf (3), n = 3.
        return [leaf, middle, root_ca]

    flags = {"initial_inhibit_any_policy": True, "initial_explicit_policy": True}
    self_issued = build("mid")
    assert self_issued[1].self_issued
    outcome = resolve(self_issued, {A}, **flags)
    assert outcome.succeeded, outcome.reason
    assert A in outcome.user_constrained
    # The same path with a middle certificate that is not self-issued gets no such expansion: its
    # level is empty, the graph is NULL, and explicit_policy is 0.
    other = build("elsewhere")
    assert not other[1].self_issued
    assert not resolve(other, {A}, **flags).succeeded


def test_a_self_issued_final_certificate_with_any_policy_does_not_expand():
    """The same sentence says i<n: for the target certificate (i = n) only inhibit_anyPolicy > 0
    permits (d)(2), so with it at 0 the anyPolicy of a self-issued target matches nothing."""
    target = certificate(dn("leaf"), dn("leaf"), [pol(ANY)])
    assert target.self_issued
    ca = certificate(dn("ca"), dn("root"), [pol(A)])
    flags = {"initial_inhibit_any_policy": True, "initial_explicit_policy": True}
    assert not resolve([target, ca], {A}, **flags).succeeded
    assert resolve([target, ca], {A}, initial_explicit_policy=True).succeeded


def test_rfc_9618_figure_4_unmatched_leaf_policy_is_dropped():
    """RFC 9618 sec. 5.3 Figure 4: Red maps to Gold and White; the leaf asserts Gold and Silver.
    Gold matches the mapped expected set; Silver matches nothing and is dropped."""
    ca = [
        pol("1.3.6.1.4.1.99999.10"),
        mapping(
            ("1.3.6.1.4.1.99999.10", "1.3.6.1.4.1.99999.11"),
            ("1.3.6.1.4.1.99999.10", "1.3.6.1.4.1.99999.12"),
        ),
    ]
    leaf = [pol("1.3.6.1.4.1.99999.11", "1.3.6.1.4.1.99999.13")]
    outcome = resolve(path(leaf, ca))
    assert set(outcome.authority_constrained) == {"1.3.6.1.4.1.99999.10"}
    assert outcome.graph_nodes == 3  # anyPolicy, Red, Gold


def test_the_exponential_example_of_rfc_9618_sec_3_2_stays_linear():
    """RFC 9618 sec. 3.2: every intermediate asserts OID1 and OID2 with the full Cartesian product of
    mappings. The tree doubles per level; the graph (sec. 4.1) has at most one node per policy per
    depth, so 60 intermediates make at most 2 nodes a level and finish at once."""
    cartesian = mapping((A, A), (A, B), (B, A), (B, B))
    intermediate = [pol(A, B), cartesian]
    chain = path([pol(A, B)], *[intermediate] * 60)
    started = time.perf_counter()
    outcome = resolve(chain)
    elapsed = time.perf_counter() - started
    assert outcome.succeeded
    assert set(outcome.authority_constrained) == {A, B}
    assert outcome.graph_nodes <= 2 * 61 + 1
    assert elapsed < 5


def test_the_depth_and_node_limits_of_rfc_9618_sec_6_reject_a_path_that_reaches_them():
    """Row `policy.limits`: sections 6.2 and 6.3 as opt-in ceilings. A limit that is not reached
    changes nothing; one that is reached fails the path and names itself."""
    intermediate = [pol(A, B), mapping((A, A), (A, B), (B, A), (B, B))]
    chain = path([pol(A, B)], *[intermediate] * 10)  # 11 certificates
    open_ended = resolve(chain)
    assert open_ended.succeeded
    nodes = open_ended.graph_nodes
    assert resolve(chain, max_depth=11, max_nodes=nodes + 100).succeeded
    too_deep = resolve(chain, max_depth=10)
    assert not too_deep.succeeded
    assert "11 certificates" in (too_deep.reason or "")
    assert "6.2" in (too_deep.reason or "")
    too_big = resolve(chain, max_nodes=5)
    assert not too_big.succeeded
    assert "over the limit of 5" in (too_big.reason or "")
    assert "6.3" in (too_big.reason or "")


def test_qualifiers_are_collected_across_the_path():
    """RFC 9618 sec. 5.5(g)(4)(ii): a policy's qualifiers come from the node, its ancestors and descendants."""
    cps = x509.PolicyInformation(oid(A), ["https://example.com/cps"])
    ca = [(x509.CertificatePolicies([cps]), False)]
    outcome = resolve(path([pol(A)], ca))
    assert len(outcome.user_constrained[A]) == 1
    assert b"https://example.com/cps" in outcome.user_constrained[A][0]


# --- a differential oracle: the RFC 5280 policy tree, which RFC 9618 says the graph "computes the same
# policies as". It is exponential and is used here only on paths of up to four certificates. --------


class _TreeNode:
    def __init__(self, policy, expected, parent):
        self.policy, self.expected, self.parent = policy, set(expected), parent


def _tree_resolve(specs, user):
    """RFC 5280 sec. 6.1.2-6.1.5 verbatim, on a tree. `specs` is nearest-the-anchor first."""
    n = len(specs)
    levels = [[_TreeNode(ANY, {ANY}, None)]]
    tree_null = False
    explicit, mapping_ctr, inhibit_any = n + 1, n + 1, n + 1

    def prune(through):
        for d in range(through, -1, -1):
            parents = {id(c.parent) for c in levels[d + 1]}
            levels[d] = [x for x in levels[d] if id(x) in parents]

    for i, spec in enumerate(specs, start=1):
        final = i == n
        if spec["policies"] is not None and not tree_null:
            new = []
            levels.append(new)
            for policy in [p for p in spec["policies"] if p != ANY]:
                matched = False
                for parent in levels[i - 1]:
                    if policy in parent.expected:
                        new.append(_TreeNode(policy, {policy}, parent))
                        matched = True
                if not matched:
                    for parent in levels[i - 1]:
                        if parent.policy == ANY:
                            new.append(_TreeNode(policy, {policy}, parent))
            if ANY in spec["policies"] and inhibit_any > 0:
                for parent in levels[i - 1]:
                    for value in sorted(parent.expected):
                        if not any(c.parent is parent and c.policy == value for c in new):
                            new.append(_TreeNode(value, {value}, parent))
            prune(i - 1)
            if not new:
                tree_null = True
        elif spec["policies"] is None:
            tree_null = True
        if explicit == 0 and tree_null:
            return False
        if final:
            if explicit != 0:
                explicit -= 1
            if spec["require"] == 0:
                explicit = 0
            break
        if spec["mappings"] and not tree_null:
            for issuer_policy in dict.fromkeys(a for a, _ in spec["mappings"]):
                subjects = {b for a, b in spec["mappings"] if a == issuer_policy}
                if mapping_ctr > 0:
                    hit = [x for x in levels[i] if x.policy == issuer_policy]
                    for x in hit:
                        x.expected = set(subjects)
                    if not hit:
                        for parent in levels[i - 1]:
                            if parent.policy == ANY and any(x.policy == ANY for x in levels[i]):
                                levels[i].append(_TreeNode(issuer_policy, subjects, parent))
                else:
                    levels[i] = [x for x in levels[i] if x.policy != issuer_policy]
                    prune(i - 1)
            if not levels[i]:
                tree_null = True
        explicit = max(explicit - 1, 0)
        mapping_ctr = max(mapping_ctr - 1, 0)
        inhibit_any = max(inhibit_any - 1, 0)
        if spec["require"] is not None:
            explicit = min(explicit, spec["require"])
        if spec["inhibit_map"] is not None:
            mapping_ctr = min(mapping_ctr, spec["inhibit_map"])
        if spec["inhibit_any"] is not None:
            inhibit_any = min(inhibit_any, spec["inhibit_any"])
    if tree_null:
        return explicit > 0
    if user is not None:
        node_set = [x for lvl in levels[1:] for x in lvl if x.parent.policy == ANY]
        doomed = {id(x) for x in node_set if x.policy not in user and x.policy != ANY}
        changed = True
        while changed:
            changed = False
            for lvl in levels[1:]:
                for x in lvl:
                    if id(x) not in doomed and id(x.parent) in doomed:
                        doomed.add(id(x))
                        changed = True
        for d in range(1, len(levels)):
            levels[d] = [x for x in levels[d] if id(x) not in doomed]
        top = [x for x in levels[n] if x.policy == ANY]
        if top:
            present = {x.policy for x in node_set if id(x) not in doomed}
            parent = next(x for x in levels[n - 1] if x.policy == ANY)
            for policy in sorted(user - present):
                levels[n].append(_TreeNode(policy, {policy}, parent))
            levels[n] = [x for x in levels[n] if x.policy != ANY]
        prune(n - 1)
        tree_null = not levels[0]
    return explicit > 0 or not tree_null


def test_the_graph_agrees_with_the_rfc_5280_tree_on_random_small_paths():
    import random

    rng = random.Random(9618)
    tally = {True: 0, False: 0}
    pool = [A, B, C, ANY]
    for trial in range(250):
        n = rng.randint(1, 4)
        specs = []
        for _ in range(n):
            policies = None if rng.random() < 0.1 else rng.sample(pool, rng.randint(1, 3))
            mappings = None
            if rng.random() < 0.5:
                mappings = [
                    (rng.choice([A, B, C]), rng.choice([A, B, C])) for _ in range(rng.randint(1, 3))
                ]
            specs.append(
                {
                    "policies": policies,
                    "mappings": mappings,
                    "require": rng.choice([None, None, 0, 1, 2]),
                    "inhibit_map": rng.choice([None, None, 0, 1]),
                    "inhibit_any": rng.choice([None, None, 0, 1]),
                }
            )
        user = rng.choice([None, {A}, {B, C}])
        extension_sets = []
        for k, spec in enumerate(specs):
            exts = []
            if spec["policies"] is not None:
                exts.append(pol(*spec["policies"]))
            if spec["mappings"] and k != n - 1:
                exts.append(mapping(*spec["mappings"]))
            if spec["require"] is not None or spec["inhibit_map"] is not None:
                exts.append(constraints(spec["require"], spec["inhibit_map"]))
            if spec["inhibit_any"] is not None:
                exts.append((x509.InhibitAnyPolicy(spec["inhibit_any"]), True))
            extension_sets.append(exts)
        if specs[-1]["mappings"]:
            specs[-1] = {**specs[-1], "mappings": None}
        outcome = resolve(path(*reversed(extension_sets)), user)
        expected_ok = _tree_resolve(specs, user)
        tally[expected_ok] += 1
        assert outcome.succeeded == expected_ok, (trial, specs, user)
    assert min(tally.values()) > 30, tally
