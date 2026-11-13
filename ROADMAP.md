# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation pkix could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `anchors.load_anchor()` | RFC 5280 sec. 6.1.1(d); RFC 6818 | `[ok]` | `tests/test_obligations.py::test_a_trust_anchor_carries_the_name_and_key_that_sec_611_requires` | M1 |
| `chain.candidates()` | RFC 5280 sec. 6.1.1(a), 6.1.3(a)(4), 7.1, 4.2.1.9 | `[ok]` | `tests/test_chain_candidates.py::test_the_served_chain_is_one_candidate_path` | M1 |
| `anchors.rebase` | RFC 5280 sec. 6.1.1(d), 4.1.1.3 | `[ok]` | `tests/test_anchors_asn1core.py::test_anchor_carries_stored_spki_and_tbs_slices` | M1 |
| `anchors.no_cryptography` | the owner's dependency rule of 2026-11-12 | `[ok]` | `tests/test_anchors_asn1core.py::test_package_source_never_imports_cryptography` | M2 |
| `anchors.verify` | RFC 5280 sec. 6.1.3(a)(1) | `[ok]` | `tests/test_anchors_asn1core.py::test_anchor_verify_checks_signatures_under_the_anchor_key` | M2 |
| `validity.check_validity()` | RFC 5280 sec. 6.1.3(a)(2), 4.1.2.5 | `[ok]` | `tests/test_validity.py::test_validity_period_boundaries_are_inclusive` | M2 |
| `validity.unsigned_certificate` | RFC 9925 sec. 3.1, 4 | `[ok]` | `tests/test_signatures.py::test_an_unsigned_certificate_is_refused_as_a_path_signature` | M2 |
| `algorithms.oid_table` | RFC 3279 sec. 2.2; RFC 4055 sec. 5; RFC 5758 sec. 3.2; RFC 8017 erratum 5154 | `[ok]` | `tests/test_signatures.py::test_every_signature_oid_maps_to_the_hash_its_document_names` | M2 |
| `validity.check_signature()` | RFC 5280 sec. 6.1.3(a)(1), 4.1.1.2, 4.1.1.3; RFC 3279; RFC 4055 sec. 3.1, 5; RFC 5480 sec. 2; RFC 5758 sec. 3.2; RFC 8410 sec. 3, 6; arithmetic by `sigwire[verify]` | `[part]` | `tests/test_signatures.py::test_differential_against_cryptography` | M2 |
| `algorithms.rehome` | design: `asn1core` owns structure (PORTFOLIO.md section 9 item 15). `_algorithms.decode_public_key` reads the SPKI through `asn1core.keys.parse_spki`, which enforces RFC 3279 sec. 2.3.1 and 2.3.2, RFC 5480 sec. 2.1.1 and 2.2 and RFC 8410 sec. 3; pkix keeps only which keys it verifies with. signeddata and revokekit already left `_algorithms` | `[ok]` | `tests/test_signatures.py::test_public_keys_are_read_by_asn1core_parse_spki` | M2 |
| `algorithms.ec_compressed` | RFC 5480 sec. 2.2 (compressed points MAY be supported) | `[ ]` | (to be written) | M2 |
| `algorithms.rsassa_pss_key` | RFC 4055 sec. 3.1, 3.3; RFC 5756; RFC 8017 sec. A.2.3 and erratum 5111 | `[ ]` | (to be written) | M2 |
| `algorithms.ed448` | RFC 8410 sec. 3; RFC 8032 sec. 5.2 | `[ ]` | (to be written) | M2 |
| `algorithms.ml_dsa` | RFC 9881 | `[ ]` | (to be written) | M2 |
| `algorithms.dsa` | RFC 3279 sec. 2.2.2, 2.3.2; RFC 5758 sec. 3.1; parameter inheritance of RFC 5280 sec. 6.1.2(d)-(f), 6.1.4(e)-(f), 6.1.5(c)-(e). Verified by `sigwire.verify.dsa`: refused by `sigwire.verify.DEFAULT` as a policy refusal and admitted by `LEGACY` (PORTFOLIO.md section 9 item 15). PKITS 4.1.4 and 4.1.5 validate under `LEGACY` | `[ok]` | `tests/test_signatures.py::test_dsa_is_refused_by_the_strict_policy_and_verified_under_legacy`; `tests/test_signatures.py::test_dsa_parameters_are_inherited_along_the_path`; `tests/test_pkits.py::test_dsa_cases_are_refused_under_the_strict_policy` | M2 |
| `extensions.key_usage_asn1core` | PORTFOLIO.md section 9 item 15: keyUsage read by `asn1core.extensions.parse_key_usage` (X.690 11.2.2 trailing zero bits refused) | `[ok]` | `tests/test_path_walk.py::test_key_usage_is_read_by_asn1core_and_a_trailing_zero_bit_is_refused` | M3 |
| `chain.ca_constraints` | RFC 5280 sec. 6.1.4(k)-(n), 4.2.1.9, 4.2.1.3; RFC 5480 sec. 3 with RFC 8813; RFC 9295 | `[part]` | `tests/test_path_walk.py::test_path_length_constraint_zero_stops_a_further_ca`; `tests/test_path_walk.py::test_a_key_usage_without_key_cert_sign_is_rejected`; `tests/test_path_walk.py::test_an_intermediate_without_basic_constraints_ca_is_rejected`. Done in `result.path_walk`: (k) cA, (l)-(m) pathLen with the self-issued exemption, (n) keyCertSign. Missing: the RFC 5480/8813/9295 key-usage consistency for EC and EdDSA keys | M2 |
| `chain.critical_extensions` | RFC 5280 sec. 4.2, 6.1.4(o), 6.1.5(f) | `[ok]` | `tests/test_path_walk.py::test_an_unknown_critical_extension_fails_and_a_non_critical_one_does_not` | M2 |
| `chain.issuer_binding` | RFC 5280 sec. 6.1.3(a)(1), (a)(4), 4.2.1.1, 4.2.1.2 | `[part]` | `tests/test_path_walk.py::test_an_issuer_that_is_not_the_working_issuer_name_breaks_the_path`. Done: (a)(1) under the working key and (a)(4) by section 7.1 name comparison. Missing: key identifiers (4.2.1.1, 4.2.1.2) as a discovery aid | M2 |
| `validity.version1_ca` | RFC 5280 sec. 6.1.4(k): a v1 or v2 intermediate "MUST" be verified out of band "or reject"; pkix rejects | `[part]` | Coded in `result._prepare`; no v1 certificate is minted by a test yet (`cryptography` cannot build one) | M2 |
| `names.constraint_holds()` | RFC 5280 sec. 6.1.3(b), (c), 4.2.1.10, 7; RFC 9549 sec. 2.2-2.5 | `[ok]` | `tests/test_names.py::test_excluded_wins_over_permitted`; `tests/test_names.py::test_intersection_keeps_the_narrower_subtree`; `tests/test_names.py::test_a_constraint_on_an_unevaluated_form_is_refused_not_guessed` | M3 |
| `names.idn_email` | RFC 9549 sec. 2.3-2.5 (RFC 8399 is obsolete); RFC 9598 (RFC 8398 is obsolete) | `[part]` | `tests/test_names.py::test_a_mailbox_constraint_is_refused_because_rfc_9549_removed_it`. Done: mailbox constraints refused, host part compared case-insensitively, DNS label-by-label. Missing: U-label to A-label conversion of non-ASCII names (SmtpUTF8Mailbox is row `names.smtp_utf8_mailbox`) | M3 |
| `policy.resolve()` | RFC 5280 sec. 6.1.2-6.1.5 as replaced by RFC 9618 sec. 5.1-5.6 | `[ok]` | `tests/test_policy.py::test_the_graph_agrees_with_the_rfc_5280_tree_on_random_small_paths` | M4 |
| `policy.graph` | RFC 9618 sec. 4.1, 4.2 and 5.2-5.5: the policy graph, linear in the certificates | `[ok]` | `tests/test_policy.py::test_the_exponential_example_of_rfc_9618_sec_3_2_stays_linear` | M4 |
| `policy.limits` | RFC 9618 sec. 6.2, 6.3 (fallback bounds on depth and size; defence in depth once the graph exists): `resolve(max_depth=, max_nodes=)` and `PathInputs.policy_max_depth` / `policy_max_nodes`, off by default because the document names no number; a path that reaches a limit fails the policy step naming it | `[ok]` | `tests/test_policy.py::test_the_depth_and_node_limits_of_rfc_9618_sec_6_reject_a_path_that_reaches_them`; `tests/test_path_walk.py::test_the_policy_limits_of_rfc_9618_sec_6_are_inputs_of_the_walk` | M4 |
| `revocation.status_of()` | RFC 5280 sec. 6.1.3(a)(3), 6.3; RFC 6960 | `[ ]` | `tests/test_obligations.py::status_of` | M5 |
| `revocation.crl_checker` | RFC 5280 sec. 6.3.3 (a) to (l) and its last paragraph, with RFC 10007 sec. 4 for (f); sec. 5.2 and 5.3 critical extensions. Fails closed: no usable CRL is UNDETERMINED; a CRL signature pkix cannot verify is "unsupported" | `[ok]` | `tests/test_path_walk.py::test_a_revoked_leaf_fails_and_an_absent_crl_fails_closed`; `tests/test_path_walk.py::test_a_crl_pkix_cannot_verify_is_unsupported_not_good`; the four rows below | M5 |
| `revocation.idp` | RFC 5280 sec. 5.2.5, 6.3.3(b)(2), (d), (e), (l): issuing distribution point (decoded by `asn1core.extensions.parse_issuing_distribution_point`), distribution point names (sec. 4.2.1.13, nameRelativeToCRLIssuer included), onlyContains*, onlySomeReasons and reasons_mask. PKITS 4.14.1-4.14.23, 4.5.3-4.5.8 | `[ok]` | `tests/test_crl_processing.py::test_an_issuing_distribution_point_scope_is_processed_not_refused`; `tests/test_crl_processing.py::test_idp_distribution_point_names_must_match_the_certificates`; `tests/test_crl_processing.py::test_only_some_reasons_crls_must_together_cover_every_reason` | M5 |
| `revocation.indirect_crl` | RFC 5280 sec. 6.3.3(b)(1) cRLIssuer with indirectCRL, sec. 5.3.3 certificateIssuer (each entry attributed to the issuer named last). PKITS 4.14.24-4.14.35 | `[ok]` | `tests/test_crl_processing.py::test_an_indirect_crl_attributes_each_entry_to_its_certificate_issuer`; `tests/test_crl_processing.py::test_a_crl_issuer_named_in_the_dp_must_assert_indirect_crl` | M5 |
| `revocation.separate_crl_key` | RFC 5280 sec. 6.3.3(f): a path for a CRL signer other than the certificate issuer's key, from the same trust anchor (`RevocationRequest.anchor`), revocation included, signers drawn from `CrlChecker(certificates=...)`. PKITS 4.4.19-4.4.21 and the self-issued key-rollover cases of 4.5, 4.6, 4.9, 4.11, 4.12, 4.13.19 | `[ok]` | `tests/test_crl_processing.py::test_a_separate_crl_signing_key_is_validated_from_the_same_anchor` | M5 |
| `revocation.delta_crl` | RFC 5280 sec. 5.2.4 (a)-(d), 6.3.3(a)(2), (c), (h), (i), (k): the current delta CRL with matching issuer, IDP and AKI whose BaseCRLNumber the complete CRL reaches, verified under the step (f) key and searched first; `use_deltas=False` ignores deltas. PKITS 4.15.1-4.15.8 | `[ok]` | `tests/test_crl_processing.py::test_a_delta_crl_is_merged_with_the_complete_crl_it_updates`; `tests/test_crl_processing.py::test_a_delta_crl_takes_a_certificate_off_hold`; `tests/test_crl_processing.py::test_a_delta_crl_alone_is_never_a_complete_crl` | M5 |
| `revocation.crl_explicit_delta` | RFC 5280 sec. 6.3.3 (c), (h), (i) are conditioned on use-deltas alone; only the *obtaining* in step (a) mentions the freshest CRL extension. `CrlChecker(explicit_deltas=True)` applies a delta the caller holds whether or not the certificate or CRL carries FreshestCRL. Default unchanged. Proposed by revokekit `rk.crl-explicit-delta` | `[ok]` | `tests/test_crl_processing.py::test_explicit_deltas_reads_a_delta_nothing_points_at` | M5 |
| `revocation.answer_details` | RFC 5280 sec. 5.3, 5.3.1, 6.3.3 (i), (j): `RevocationAnswer.reason_code` (0 when the entry has no reason code, step (i)(2)), `revocation_date` and `on_delta` of the entry that decided, found by sec. 5.3.3's certificateIssuer rule; None or False for every other status. Proposed by revokekit `rk.crl-answer-details` | `[ok]` | `tests/test_crl_processing.py::test_a_revoked_answer_carries_reason_code_date_and_origin`; `tests/test_crl_processing.py::test_an_indirect_crl_answer_reads_the_entry_of_its_own_certificate_issuer` | M5 |
| `revocation.no_rev_avail` | RFC 9608 sec. 4: step (a)(3) is skipped for noRevAvail or ocsp-nocheck | `[ok]` | `tests/test_revocation.py::test_no_rev_avail_skips_revocation_checking`; `tests/test_revocation.py::test_no_rev_avail_on_a_ca_is_invalid` | M5 |
| `revocation.crl_issuer_key_usage` | RFC 10007 sec. 4: amended step (f) of RFC 5280 sec. 6.3.3 | `[ok]` | `tests/test_revocation.py::test_a_v3_crl_issuer_without_key_usage_now_fails` | M5 |
| `revocation.crl_signature` | RFC 5280 sec. 5.1.1, 6.3.3; verify through `validity.check_signature_with_spki` | `[ok]` | `tests/test_revocation.py::test_a_tampered_crl_fails_its_signature` | M5 |
| `extensions.decoders` | RFC 5280 sec. 4.2.1.3, 4.2.1.4, 4.2.1.5, 4.2.1.9, 4.2.1.11, 4.2.1.14: basic constraints, key usage, policies, mappings, constraints, inhibitAnyPolicy; `asn1core`'s `dk.named-bits` row would take keyUsage | `[ok]` | `tests/test_revocation.py::test_the_key_usage_bits_are_read_by_name` | M3 |
| `names.check_certificate()` | RFC 5280 sec. 6.1.3(b), (c), 4.2.1.10 (subject DN, subjectAltName, emailAddress fallback, self-issued exemption) | `[ok]` | `tests/test_names.py::test_self_issued_certificates_are_exempt_unless_final` | M3 |
| `revocation.skips_revocation()` | RFC 9608 sec. 3, 4 | `[ok]` | `tests/test_revocation.py::test_no_rev_avail_with_an_ocsp_access_method_is_invalid_but_ca_issuers_is_fine` | M5 |
| `revocation.check_crl_issuer_key_usage()` | RFC 10007 sec. 4 | `[ok]` | `tests/test_revocation.py::test_a_v1_or_v2_crl_issuer_is_exempt` | M5 |
| `revocation.check_crl_signature()` | RFC 5280 sec. 5.1.1, 5.1.1.2, 6.3.3 | `[ok]` | `tests/test_revocation.py::test_a_crl_whose_two_algorithm_fields_differ_is_refused` | M5 |
| `result.path_walk` | RFC 5280 sec. 6.1.2 to 6.1.5 as one pass: signatures, dates, revocation through a caller's checker, issuer names, `NameConstraints.restrict()` state, basic constraints and pathLen (k)-(m), keyUsage (n), critical extensions (o) and 6.1.5(f), then `policy.resolve()` (RFC 9618). Three answers: valid, invalid, unsupported; every step recorded | `[ok]` | `tests/test_path_walk.py::test_a_well_formed_path_validates_and_records_every_step`; `tests/test_pkits.py::test_pkits_counts` | M6 |
| `names.smtp_utf8_mailbox` | RFC 9549 sec. 2.5, RFC 9598 sec. 3 and 6 (otherName SmtpUTF8Mailbox, id-on 9): read as a `GeneralName` of kind `SmtpUTF8Mailbox`, refused when it carries a BOM, has no `@` or local part, or a non-ASCII domain (sec. 3: A-labels only), and compared under the rfc822Name constraints as sec. 6 sets out (local part stripped, domain compared octet for octet after lowercasing). Not checked: that an ASCII local part used rfc822Name (an issuer obligation, sec. 3), and U-label to A-label conversion | `[ok]` | `tests/test_names.py::test_an_smtp_utf8_mailbox_is_read_and_compared_under_the_rfc822_constraints`; `tests/test_names.py::test_a_malformed_smtp_utf8_mailbox_is_refused_and_another_other_name_stays_opaque` | M3 |
| `policy.self_issued_any_policy` | RFC 9618 sec. 5.3(d)(2)(b): anyPolicy in a self-issued certificate with `i<n` expands as if its policies were listed, even with inhibit_anyPolicy 0; the target (`i=n`) does not. Mutation-checked: dropping the branch fails the first test | `[ok]` | `tests/test_policy.py::test_a_self_issued_ca_with_any_policy_expands_even_when_any_policy_is_inhibited`; `tests/test_policy.py::test_a_self_issued_final_certificate_with_any_policy_does_not_expand` | M4 |
| `result.validate()` | RFC 5280 sec. 6: `chain.candidates()` then `path_walk()` per candidate | `[ok]` | `tests/test_path_walk.py::test_validate_discovers_the_path_through_the_pool` | M6 |
| `result.provenance` | design: strategy constitution item 5 | `[ ]` | (to be written) | M6 |
| `corpus.path_validation` | NIST PKITS 1.0.1 (247 cases of section 4), fetched by `tools/fetch_pkits.py` into a cache outside the tree, pinned by size and sha256; outcomes in `tests/pkits_cases.py` | `[ok]` | `tests/test_pkits.py::test_pkits_counts`: **247 pass, 0 not applicable, 0 fail** (2026-11-13; 178/69/0 before the revocation rows and DSA). The test skips, loudly, without the cached corpus | M6 |
| `deps.sigprim_pin` | design: `sigwire[verify]` (merged from the retired `sigprim`, 2026-11-13) is unpublished, so CI and the wheel cannot resolve it yet | `[ ]` | (to be written) | M6 |
| `store.remember()` | design | `[ ]` | `tests/test_obligations.py::remember` | - |
| `m7.document` | MS-CAB and MS-CTL: no retrievable copy, see below | `[ ]` | (to be written) | M7 |
| `cab.member()` | MS-CAB (vendor format, not an RFC). **Blocked by `m7.document`.** | `[ ]` | `tests/test_obligations.py::cab_member` | M7 |
| `ctl.root_program()` | MS-CTL (vendor format, not an RFC). **Blocked by `m7.document`.** | `[ ]` | `tests/test_obligations.py::ctl_root_program` | M7 |
| `ctl.signed_by_microsoft()` | MS-CTL Authenticode. **Blocked by `m7.document` and by `signeddata` (CMS/PKCS #7 verification).** | `[ ]` | `tests/test_obligations.py::ctl_signed_by_microsoft` | M7 |

### What the new rows record

Added 2026-11-13 from the group A roadmap review, each claim re-read through `rfclib` first.

- `validity.check_signature()` is `[part]`: RSASSA-PKCS1-v1_5 (the SHA-2 identifiers and SHA-1), RSASSA-PSS
  with an `rsaEncryption` key, ECDSA over P-256, P-384 and P-521, and Ed25519 verify, through `sigwire[verify]`,
  and the real Let's Encrypt chain plus synthetic certificates from `cryptography` are the corpus. Not yet
  covered, each its own row above: compressed EC points, `id-RSASSA-PSS` public keys, Ed448, ML-DSA, DSA,
  and the signature on a CRL. SHA-1 and RSA under 2048 bits are refused by the default `sigwire[verify]` policy, as
  a `SignaturePolicyRefused` that is never reported as a bad signature.
- `anchors.rebase`, `anchors.no_cryptography` and `anchors.verify` close the open question of section 5:
  `anchors` reads through `asn1core`, verifies through `validity`, and `cryptography` left the runtime
  dependencies (it stays a dev dependency, as the oracle and as the thing that mints test certificates).
  The review proposed a `verify()` that "raises until M2" and no such method existed; M2's signature check
  landed in the same change, so `TrustAnchor.verify()` works, and it raises `SignatureUnsupported` for any
  key it cannot check.
- `policy.graph`: the section 6.1.2 and 6.1.3 text of RFC 5280 describes a policy **tree** that RFC 9618
  replaces with a policy **graph**; implementing the 5280 text reintroduces the exponential growth. RFC 9618
  section 6.3 ("limit policy tree size") is an alternative mitigation for implementations that keep the
  tree, so `policy.limits` is defence in depth and not a substitute. The review cited sections 5.2 and 5.3;
  the update runs from 5.1 to 5.6.
- `revocation.crl_issuer_key_usage`: RFC 10007 section 4 requires, for a **v3** CRL issuer certificate, that
  keyUsage be present and carry cRLSign. A v1 or v2 issuer is exempt because those versions have no
  extensions. The review said "a keyUsage/cRLSign check"; the presence requirement is the new part.
- `names.idn_email`: RFC 8398 and RFC 8399 are obsolete (by RFC 9598 and RFC 9549) and are no longer listed
  as sources.
- `chain.ca_constraints`, `chain.critical_extensions`, `chain.issuer_binding`: the checks of section 6.1.4
  steps (k) to (n) and section 4.2, which the candidate search deliberately does not make. `asn1core`
  already lists `unrecognised_critical`; deciding what to do with it is this project's.
- `algorithms.rehome`: `pkix/_algorithms.py` reads AlgorithmIdentifier and SubjectPublicKeyInfo with
  `asn1core`'s codec because `asn1core` has no key decoder yet. It moves there when its `dk.spki-key` row
  lands, and the private TLV helpers that `chain.py` still carries go with it.
- `deps.sigprim_pin`: (id kept from before the merge into `sigwire[verify]` on 2026-11-13) `sigwire` is an unpublished sibling checkout, so the
  CI workflows (which check out only `asn1core`) and a built wheel cannot resolve it. Until it is
  published, `ci.yml` and `security.yml` need a second checkout step, and the call surface used here
  (`rsa.verify_pkcs1v15`, `rsa.verify_pss`, `ecdsa.verify`, `eddsa.verify_ed25519`, `hashes.lookup`,
  `policy.DEFAULT`, `policy.LEGACY`) must be pinned. `sigwire[verify]` itself reaches `cryptography` for the group
  arithmetic, which is the owner's rule for primitives; pkix does not.
- `corpus.path_validation`: the validator's honest corpus is an independent one. No suite (NIST PKITS,
  Wycheproof, BetterTLS or similar) has been fetched or verified here; choosing one, with its source,
  digest and licence, comes before M6.
- `m7.document` is the row the three M7 rows are blocked by: a copy of MS-CAB and MS-CTL, with title and
  revision, retrieved by a person who can reach one. It encodes in the matrix what the prose below says,
  because `projecthub`'s loop reads rows and not paragraphs. `ctl.signed_by_microsoft()` is also blocked by
  `signeddata`, because an Authenticode signature is CMS and none of RFC 5280 covers it.

### Round 2 (2026-11-13): M3 to M5 pieces, and the corpus decision

Read through `rfclib` first: RFC 5280 sec. 4.2.1.10, 6.1.2 to 6.1.5; RFC 9618 sec. 3 to 5 in full; RFC 9549
sec. 2; RFC 9608 sec. 2 to 4; RFC 10007 sec. 4. Errata: RFC 9618 none, RFC 10007 none, RFC 9608 one held
(eid 8012, an abstract typo), RFC 9549 one reported (eid 9230, a code point in the introduction), RFC 5280
errata 3579 on 4.2.1.4 is editorial (a type name). None changes a rule implemented here.

- `policy.resolve()` is RFC 9618's graph. The differential test compares it with a verbatim RFC 5280 policy
  tree on 250 random paths of up to four certificates (policies, mappings, requireExplicitPolicy,
  inhibitPolicyMapping, inhibitAnyPolicy, user-initial-policy-set) and fails when the mapping step is broken.
  Self-issued certificates are not in that random set: row `policy.self_issued_any_policy`.
- RFC 9618 section 5.3(d)(2) is worded differently from RFC 5280's: it iterates over policy values in the
  expected sets and creates one child per value with all parents, where RFC 5280 created one child per
  (parent, value). The code follows 9618.
- RFC 9549 section 2.2 removed mailbox constraints, so an rfc822Name constraint containing "@" raises
  `UnsupportedConstraint`. PKITS predates that and has mailbox cases: expect to mark them as expected
  differences, not failures.
- RFC 5280 section 4.2.1.10 says nothing on a dNSName constraint with a leading period; it is read as one or
  more labels, like URI and mailbox constraints. A decision, recorded in `names.py`.
- `revocation.crl_issuer_key_usage` follows RFC 10007: v3 issuer needs keyUsage present with cRLSign. A v1 or
  v2 issuer is exempt.
- RFC 9608 section 3 profile violations (noRevAvail with cA TRUE, CRL DP, freshest CRL, id-ad-ocsp) raise
  `ProfileViolationError`; the section says the relying party "MUST consider the certificate invalid".
- `validity.check_signed_data` was factored out of `check_signature_with_spki` so a CRL goes through the
  same seam; certificate behaviour is unchanged.

**Corpus decision (row `corpus.path_validation`).** NIST PKITS, "Public Key Interoperability Test Suite",
version 1.0.1 of 2011-04-14, from the NIST CSRC project page `https://csrc.nist.gov/projects/pki-testing`:
descriptions `https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf` and data
`https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip` (1.0 is kept at
`.../PKITS_v1_0_0.pdf` and `.../PKI-Research-and-Testing/documents/PKITS_data_v1_0_0.zip`). The page was
read on 2026-11-13 and carries no PKITS-specific licence or terms; its only pointer is a generic site
"Copyrights" link, and the nist.gov copyright page returned 404 when fetched. Terms are therefore **not
established**, so nothing was downloaded. The coordinator or owner decides whether NIST's generic policy
for government-authored material is enough to fetch it into scratch. Until then the validator's corpus is
synthetic certificates minted by `cryptography` (tests/builders.py) plus the recorded real chains.
PKITS was written against RFC 3280 and predates RFC 9549 (mailbox constraints) and RFC 9618 (the graph).

### Round 3 (2026-11-13): the path walk, and PKITS as the corpus

Read through `rfclib` first: RFC 5280 sec. 6.1.2(k), 6.1.3, 6.1.4, 6.1.5 and 6.3.3, and the errata list
(6 verified, none on section 6.1.3 to 6.1.5 or 6.3.3; eid 5938 on section 6.1 is wording about the
goal of validation).

- `result.path_walk` joins the existing pieces in section order and stops at the first failing step,
  as section 6.1.4 says the procedure "terminates". Its answer is valid, invalid or unsupported, and
  every step is recorded with its certificate number. Revocation is a caller's `RevocationChecker`;
  without one, `revocation_checked` is False and the walk says it did not look.
- **Spec correction to section 5 below.** The open question on version 1 CA certificates read section
  4.2.1.9 alone. Section 6.1.4(k) does decide it: for a v1 or v2 intermediate "the application MUST
  either verify that certificate i is a CA certificate through out-of-band means or reject the
  certificate". pkix rejects, which the text permits; it is no longer a guess.
- `revocation.CrlChecker` is section 6.3.3 for complete CRLs from the certificate's issuer and fails
  closed: no usable CRL is UNDETERMINED, which fails the path. One complete CRL that revokes settles
  it; a certificateHold or a "good" with delta CRLs present is "unsupported", because a delta can
  change either.
- PKITS 1.0.1: `PKITS_data.zip`, 3,052,513 octets, sha256
  `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665` (read 2026-11-13, Last-Modified
  2024-09-29, members dated 2011-04-14). The outcomes were read from `PKITS.pdf`, 5,027,216 octets,
  sha256 `506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea`. 247 cases (224 tests,
  some with several inputs): **178 pass, 69 not applicable, 0 fail**, validated at 2020-06-01Z.
  Nothing of the corpus is in the tree. PKITS predates RFC 9549, but no mailbox-constraint case
  came out "unsupported": every 4.13 case passes.
- Two PKITS certificates and one CRL (`BadCRLSignatureCACRL.crl`) declare a nonzero unused-bit count
  in signatureValue, which `asn1core` refuses; the walk reports them unreadable, and the cases
  expecting rejection pass for that reason rather than for a failed signature.

### Round 4 (2026-11-13): the CRL algorithm in full, DSA, and the 69 PKITS cases

Read through `rfclib` first: RFC 5280 sec. 4.2.1.13, 5.2.3, 5.2.4, 5.2.5, 5.3.3, 6.1.4, 6.3.3; RFC 10007
sec. 4; RFC 3279 sec. 2.2.2, 2.3.2 and its errata (5 verified, 2 held, none on those sections); RFC 5758
sec. 3.1. RFC 5280 errata on the CRL sections: none verified; 3674 (held, editorial) renames the
"distribution field" of 6.3.3(b)(2)(i) to distributionPoint, which is how it is read here.

- **PKITS 1.0.1 went from 178 pass, 69 not applicable, 0 fail to 247 pass, 0 not applicable, 0
  fail.** Every formerly not-applicable invalid case was checked to fail for the reason the PKITS
  document gives (revoked, or status undetermined), not by accident. 4.1.6 still fails because
  `asn1core` refuses its signatureValue's unused bits, as recorded in round 3.
- `CrlChecker` is now section 6.3.3 as written: per distribution point, then the assumed DP of the
  last paragraph; reasons_mask to all-reasons; (b)(1) cRLIssuer with indirectCRL; (b)(2) IDP scope;
  (f) a separate CRL signer whose path is validated from the same trust anchor; (c), (h), (i)
  delta CRLs. The old "unsupported" answers for IDPs, indirect CRLs, separate keys and present
  deltas are gone. `CrlChecker` takes `certificates=` (possible CRL signers) and `use_deltas=`.
- `asn1core` now decodes IssuingDistributionPoint, cRLNumber, deltaCRLIndicator, certificateIssuer
  and freshestCRL, and DSA keys; pkix's `_algorithms.decode_public_key` reads through
  `asn1core.keys.parse_spki` (row `algorithms.rehome`).
- Decisions the text leaves open, taken here, each a reading rather than a quotation:
  - **all-reasons excludes ReasonFlags bit 0, "unused".** Section 5.2.5 says a revoked certificate
    on a CRL with onlySomeReasons "MUST be assigned a revocation reason other than unspecified", so
    nothing can be filed under bit 0, and a partition that omits it covers every reason (cryptography
    cannot set the bit at all). PKITS 4.14.15 to 4.14.21 pass either way.
  - **A CRL may vouch for its own signer.** PKITS 4.14.30 expects the certificate of an indirect CRL
    issuer to be covered by the indirect CRL that issuer signs. While a CRL signer's path is being
    validated, its CRL is verified under the candidate's key without re-entering the same path; such
    a CRL is tried after every other CRL. Nesting is bounded at 4 (sec. 6.2 permits limits).
  - A CRL signer's path is validated with the default inputs of sec. 6.1.1 (any-policy, no
    explicit policy) and the checker's signature policy; sec. 6.3.3(f) names only the trust anchor.
  - CRLs are tried newest thisUpdate first, and a CRL without an IDP corresponds to every DP.
  - With use-deltas set and a freshest CRL present, a missing delta does not make the answer
    UNDETERMINED: the complete CRL is still complete for its scope (sec. 6.3.3(a)(2) asks to obtain
    one; it does not make its absence fatal).
- DSA: RFC 5280 sec. 6.1.4(e)-(f) carried as working_public_key_parameters for DSA only (the one
  algorithm pkix verifies whose parameters are inherited); `PathResult.working_public_key_parameters`
  is section 6.1.5(d)'s output. PKITS runs its three DSA cases under `sigwire.verify.LEGACY`.

The Milestone column places each row on the ladder in section 2, using that ladder's own wording. Two placements are a reading and not a quotation: `result.validate()` sits at M6 because the conformance trace exercises the whole-path entry point, and `store.remember()` is a design row the ladder does not place, so it carries `-`.

### Why the CTL rows belong here and not in `trustatlas`

`trustatlas` collects the published trust programs of several vendors and joins them by hash. For
Mozilla and curl that needs no parsing at all — `certdata.txt` is text, `cacert.pem` is PEM — and its
rule is that it interprets nothing. Microsoft publishes its program as a CAB containing one member,
`authroot.stl`, whose records are trust blobs in a vendor binary format; the only published form
reachable from a Linux container is served over **plain HTTP**, so the signature inside the CTL is the
sole integrity protection it has. Decoding it is protocol logic with a silent failure mode — a wrong
record boundary yields a plausible list of thumbprints, which is the exact shape of error that makes a
trust map wrong rather than merely incomplete. A second, laxer parser in the collector directory is
the failure this file's honesty rule exists to prevent, so the obligation lives here.

Pinned bytes the implementation will be tested against, from `trustatlas`'s sweep of 2026-11-07
(`tools/collect_ctl.py`; the container re-fetched and reproduced both hashes):

- `authrootstl.cab` — 80,353 octets, `sha256 c0aa761fb7d8d1e4449a8990…`, `application/vnd.ms-cab-compressed`
- `disallowedcertstl.cab` — 5,652 octets, `sha256 1f2719b100fcc59601f0dbb2…`, the blocklist

`cab.member()` is the first slice and is independently testable: a CAB's CFHEADER, CFFOLDER and CFFILE
records name its member and its uncompressed size, and the folder's compression field says whether the
member must be inflated before anything downstream can read it. `ctl.root_program()` depends on that
answer, and `ctl.signed_by_microsoft()` is what turns "bytes as delivered over HTTP" into a claim about
the program rather than about the network path.

### M7 is blocked on a document, and the block is recorded so it is not guessed around

Milestone M7 was not implemented on 2026-11-07 because the normative text could not be reached, and
every field of a CAB or a CTL would otherwise have come from a model's recollection. That is the exact
failure this project's rules exist to prevent, and it has form in this repository's neighbour: a tile
parser written against an assumed TranscriptItem prefix returned `0x00` where `0x06` was expected, and
a trust count compared against `CKT_NSS_TRUSTED_CONNECT_PEER`, a constant that does not exist. Both
looked like clean results.

What was tried, all on 2026-11-07, so the next attempt starts here rather than re-running the dead ends:

| Source attempted | Result |
|---|---|
| `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cab/` | **HTTP 404** |
| `https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CAB.pdf` | **HTTP 409** |
| the same blob for `MS-CTL.pdf`, `MS-WINCAB.pdf` | **HTTP 409** |
| web search for the CFHEADER/CFFOLDER pages | CAPTCHA, no results |
| Wikipedia's cabinet article | **no byte-level field tables at all**, and flagged as containing original research |

Re-attempted 2026-11-11, four sources the table above did not try. Still unreachable, and the
shape of the failure is now clearer than it was:

| Source attempted | Result |
|---|---|
| `https://interoperability.blob.core.windows.net/files/MS-CAB/[MS-CAB].pdf` (and MS-CTL) | **DNS does not resolve** from this environment; the host is outside the egress allow-list |
| `https://web.archive.org/cdx/search/cdx?url=learn.microsoft.com/...ms-cab*` | **HTTP 503**, so no archived copy could even be located, let alone fetched |
| `https://learn.microsoft.com/en-us/openspecs/file_formats/ms-cab/` and `.../windows_protocols/ms-ctl/` | **HTTP 404** — and this is the correction to the 2026-11-07 entry: `learn.microsoft.com` itself resolves and answers (a legacy `msdn.microsoft.com` URL returned 200 by redirecting), so the host was never the obstacle. The document is. |
| `https://learn.microsoft.com/api/search?search=CFHEADER cabinet file format` | 30 results, **none of them the specification** — no CFHEADER/CFFOLDER page exists on the site any more |

So the block is not a network policy that a different route would satisfy: Microsoft appears to
have withdrawn the MS-CAB pages from the site that carried them, the PDF archive host is
unreachable from here, and the one place that could hold a superseded copy — the Wayback
Machine — would not answer. **M7 remains blocked, and `cab.member()` stays `[ ]`.**

Two things this section should record about the loop rather than about the network. First,
`sdk-forge/loop.py next` recommended `cab.member()` on 2026-11-11 as the portfolio's next
obligation. Its arithmetic is eligibility over board fields — Active projects, row status,
milestone, dependencies — and it does not read this prose, so a block that exists only as a
paragraph and a native link is invisible to it. Second, that is precisely why the exit rule below
is written as a rule about evidence rather than about effort: the recommendation was followed far
enough to look for the document, and the document is what refused.

Two negative observations from poking the pinned CABs directly, recorded as *where it hurt*, not as
format knowledge: the CFHEADER and CFFOLDER records at the offsets tried parsed consistently with the
member name and sizes visible in the raw bytes, and **iteration of CFFILE records failed twice** on the
variable-length name field. That is the field whose exact terminator and padding rule must come from the
document, because a one-byte error there produces a file list that looks entirely plausible. No field
layout, offset, or padding rule is asserted anywhere in this file.

**Exit rule for M7, therefore:** it is implemented against a retrieved copy of the specification, with
the document's title and revision recorded in the commit that lands the code. A row may not move from
`[ ]` on the strength of a parser that agrees with itself; it moves when the pinned
`authrootstl.cab` and `disallowedcertstl.cab` fixtures parse into entries a named test asserts on, and
when `signed_by_microsoft()` has checked the signature — without which the whole exercise describes an
HTTP response rather than the Windows program.



## 2. Milestones

- M1 anchors and chain discovery with a fixture set of real chains
- M2 section 6.1.3 step (a), basic certificate processing: signature, dates, issuer matching, critical
  extensions (this line cited section 6.2 until 2026-11-13; section 6.2 is "Using the Path Validation
  Algorithm", and `validity.py` was corrected to 6.1.3 on 2026-11-07)
- M3 name constraints including excluded subtrees and the issuance-time exception
- M4 policy mapping, constraints and anyPolicy
- M5 revocation interface plus CRL and OCSP backed implementations and cross-checks against openssl verify
- M6 publication: 0.1.0 with the conformance trace against NIST and vendor path test suites
- M7 vendor program containers: CAB member extraction, then the CTL record and Authenticode rows above,
  accepted by the pinned `authrootstl.cab` and `disallowedcertstl.cab` fixtures. `trustatlas` cannot say
  what the Windows program trusts until this lands; today it can only pin the bytes it was given.

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

Read through `rfclib` on 2026-11-13; [docs/rfc-map.md](docs/rfc-map.md) carries the full table, with each
document's status, its errata and what it changes here.

- RFC 5280 carries 6 verified errata and is updated by RFC 6818, RFC 9549, RFC 9598, RFC 9608, RFC 9618,
  RFC 9925 and RFC 10007. **RFC 8398 and RFC 8399, which this line listed until 2026-11-13, are obsolete**
  (by RFC 9598 and RFC 9549 respectively); implement the successors. The updates are not editorial:
  RFC 9618 replaces the policy tree with a graph (`policy.graph`), RFC 10007 amends the CRL issuer check
  of section 6.3.3 (`revocation.crl_issuer_key_usage`), RFC 9608 amends step (a)(3) of section 6.1.3
  (`revocation.no_rev_avail`), RFC 9549 and RFC 9598 change name constraints and email names
  (`names.idn_email`), and RFC 9925 adds a placeholder signature algorithm that must never verify
  (`validity.unsigned_certificate`, done).
- RFC 5912 carries 8 verified errata.
- RFC 6960 carries 6 verified errata.
- The signature documents, each with errata: RFC 3279 (5), RFC 4055 (2, updated by RFC 5756), RFC 5480 (2,
  updated by RFC 8813), RFC 5758 (none verified), RFC 8017 (5, of which **erratum 5154** misprints the
  `sha224WithRSAEncryption` row as SHA-256; pinned by `algorithms.oid_table`), RFC 8032 (6, of which 5519
  and 5968 fix the range of S and 5930 is a missing `raise` in the reference `verify()`; enforced in
  `sigwire[verify]`) and RFC 8410 (4, updated by RFC 9295).

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a certificate parser of its own: pkix takes DER and refuses anything else, while the codec and the certificate structures belong to `asn1core` | `[no]` | a named document requires pkix to own a codec |
| any private-key operation inside `pkix/`, signing included: where a test needs a certificate signed, the signature comes from `cryptography`, which stays a dev dependency | `[no]` | a named document requires pkix to issue a certificate |
| ACME, CMP or any issuance protocol: enrollkit asks pkix whether the result is acceptable | `[no]` | a named document requires it |
| the CA/Browser Forum baseline requirements, which are a policy profile built on top, not this algorithm | `[no]` | a named document requires it |

**One row left this table on 2026-11-07 and it is recorded here rather than deleted.** "crypto
primitives of any kind" was listed above, with "a named document requires it" as the condition to
revisit. That condition is not met and no one is pretending it is: no document requires pkix to
write its own arithmetic, because RFC 5280 is indifferent to how a signature is checked. The work
became the M2 obligation `validity.check_signature()` by a maintainer decision to carry no runtime
dependency, on the reasoning in [docs/strategy.md](docs/strategy.md) — verification has no secret
input, digests and modular exponentiation are standard library, and a verifier's honest test corpus
is signatures that other implementations produced. The sentence that previously justified the
non-goal ("the one thing this project must not write itself") is corrected in `README.md` in the
same commit, because leaving it standing would make the two documents disagree about the project.

## 5. Open questions

- **Resolved 2026-11-13: `anchors` against M2.** The question was whether to write a throwaway
  `cryptography` bridge so `TrustAnchor.verify()` could check a signature before M2. Neither happened: M2's
  signature check was written instead (`validity.check_signature`, through `sigwire[verify]`), `anchors` was
  re-based onto `asn1core` in the same change, and `cryptography` is no longer imported by anything in
  `pkix/`. RFC 5280 section 6.1.1(d) does not require an anchor's own signature to verify, so `load_anchor`
  still loads a certificate whose self-signature does not check and records `self_signed` instead.
- **Answered 2026-11-13 (Round 3 above): section 6.1.4(k) lets an application reject a v1 or v2
  intermediate, and pkix does.** The question as first written: **a version 1 certificate carries no basic constraints extension at all**, and RFC 5280 §4.2.1.9
  phrases its prohibition for the case where the extension "is not present in a *version 3*
  certificate". Read closely, that sentence does not reach a v1 issuer, so the text does not say
  whether a v1 CA certificate may serve as a path member. pkix's answer is refusal (fail closed)
  until a reachable source says otherwise; the alternative — treating silence as permission — lets a
  v1 document into a path on a reading nobody verified.
- **Whether a verifier must reject a public key that is not on the curve, or not in the prime-order
  subgroup, is not a quoted MUST here.** RFC 5480 §4 raises it in lower case and attributes the
  choices to SP 800-56A, and SEC1 §2.3.3, X9.62 and FIPS 186-3 are not reachable from this
  environment. The point is validated, by `sigwire[verify]`, which raises for one that is off the curve;
  pkix reports that as `MalformedAlgorithm` (`test_an_ec_key_off_the_curve_is_malformed_not_a_verdict`).
  The decision is pkix's and sigwire[verify]'s, not the specification's, and a subgroup check beyond that is
  not made.
- **RSA-PSS salt length when the parameters do not pin it.** For a *signature*, RFC 4055 §3.1 makes
  the parameters mandatory in the signatureAlgorithm and gives `saltLength` a default of 20, so the
  salt length is always known and `check_signature` passes exactly that number to `sigwire[verify]`, never its
  "auto" mode (`test_pss_parameters_are_read_with_their_defaults`). What stays open is the
  restriction an `id-RSASSA-PSS` *key* carries (RFC 4055 §3.3), which is row `algorithms.rsassa_pss_key`.
- **MS-CAB and MS-CTL remain unreachable** (M7). The dead ends are tabulated above so the next
  attempt starts past them.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

## Board projection

`python -m projecthub sync --check` (the retired `sdk-forge/sync_roadmap.py` was its predecessor)
projects section 1 onto GitHub issues, collected on Project V2 **#2 "Protocol SDK portfolio"**. Counts as the
matrix stands on 2026-11-13: **36 rows** in section 1, of which 8 `[ok]`, 1 `[part]` and 27 `[ ]`, plus the 4
`[no]` non-goals of section 4, which are decisions and not work and are not filed.

A live read, `python -m projecthub sync --check --project pkix` on 2026-11-13, reports **36 rows, 10 rows with
issues, 20 drift items**: 19 are open rows with no issue (the rows added today) and 1 is
`validity.check_validity()`, which is now `[ok]` while issue #297 is still open. The five new `[ok]` rows
have no issue and are not drift. The previous count in this paragraph, **12 items** read through the hosted
GitHub MCP server on 2026-11-07, was stale because M1's rows closed afterwards. Rows with no issue are filed
by `projecthub sync --apply`, and closing #297 is the same run's job.
Neither write was made from here. The numbers here are a dated snapshot and not a live
count: the board is the live view and this file is the source of truth, because a board cannot refuse a row
that claims `[ok]` without a test, and `tests/test_roadmap_rows.py` can (it now checks that the named test
exists, which it did not before 2026-11-13).
