# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 5280 | Proposed Standard | 2008-05 | 2026-11-13 |
| RFC 5912 | Informational | 2010-06 | 2026-11-13 |
| RFC 6960 | Proposed Standard | 2013-06 | 2026-11-13 |
| RFC 3279 | Proposed Standard | 2002-05 | 2026-11-13 |
| RFC 4055 | Proposed Standard | 2005-06 | 2026-11-13 |
| RFC 5480 | Proposed Standard | 2009-03 | 2026-11-13 |
| RFC 5758 | Proposed Standard | 2010-01 | 2026-11-13 |
| RFC 8017 | Informational | 2016-11 | 2026-11-13 |
| RFC 8032 | Informational | 2017-01 | 2026-11-13 |
| RFC 8410 | Proposed Standard | 2018-08 | 2026-11-13 |
| RFC 9549 | Proposed Standard | 2024-03 | 2026-11-13 |
| RFC 9598 | Proposed Standard | 2024-05 | 2026-11-13 |
| RFC 9608 | Proposed Standard | 2024-06 | 2026-11-13 |
| RFC 9618 | Proposed Standard | 2024-08 | 2026-11-13 |
| RFC 9925 | Proposed Standard | 2026-02 | 2026-11-13 |
| RFC 10007 | Proposed Standard | 2026-06 | 2026-11-13 |
| RFC 8398 | Proposed Standard, **obsolete** (by RFC 9598) | 2018-05 | 2026-11-13 |
| RFC 8399 | Proposed Standard, **obsolete** (by RFC 9549) | 2018-05 | 2026-11-13 |

All dates and statuses above were read with `rfclib` (`info`) on 2026-11-13. Two documents that older
notes in this repository list as live updates of RFC 5280, RFC 8398 and RFC 8399, are obsolete: implement
RFC 9598 and RFC 9549, which replace them. Neither obsolete RFC is a source for any row.

## Who updates whom, and what each one changes in this project

| Document | Updates | Errata (verified) | What it changes for pkix |
|---|---|---|---|
| RFC 5280 | updated by RFC 6818, 9549, 9598, 9608, 9618, 9925, 10007 | 6: 3579, 5802, 5938, 6414, 7658, 7661 (none on section 4.1.1, 4.1.2.5 or 6.1.3) | the profile and the section 6 algorithm |
| RFC 6818 | RFC 5280 | 1 | clarifications on self-signed certificates and trust anchors, read with section 6.1.1(d) |
| RFC 9549 | RFC 5280, obsoletes RFC 8399 | 0 (1 on file) | name constraints (section 4.2.1.10), IDNs in GeneralName and DNs (sections 7.2, 7.3), internationalised email (section 7.5): row `names.constraint_holds()` and `names.idn_email` |
| RFC 9598 | RFC 5280, obsoletes RFC 8398 | 0 | a new otherName form for internationalised email in the subject and issuer alternative names: row `names.idn_email` |
| RFC 9608 | RFC 5280 | 0 (1 on file) | section 4: step (a)(3) of section 6.1.3 is skipped when noRevAvail or ocsp-nocheck is present: row `revocation.no_rev_avail` |
| RFC 9618 | RFC 5280 | 0 (1 on file) | sections 5.1 to 5.6 replace the policy tree of sections 6.1 to 6.1.6 with a policy graph, because the tree grows exponentially: row `policy.graph`, and `policy.resolve()` implements the graph and not the 5280 text. Section 6 lists fallback mitigations for implementations that keep the tree |
| RFC 9925 | RFC 5280 | 0 | section 4: id-alg-unsigned (1.3.6.1.5.5.7.6.36) MUST be rejected whenever a signature is verified: row `validity.unsigned_certificate` |
| RFC 10007 | RFC 5280 | 0 | section 4 amends step (f) of section 6.3.3: when the CRL issuer's certificate is v3 the keyUsage extension must be present and carry cRLSign (v1 and v2 are exempt): row `revocation.crl_issuer_key_usage` |
| RFC 3279 | updated by RFC 4055, 4491, 5480, 5758, 8692 | 5 | rsaEncryption and RSAPublicKey (section 2.3.1), ecdsa-with-SHA1 and Ecdsa-Sig-Value (section 2.2.3), id-dsa-with-sha1 and Dss-Sig-Value (section 2.2.2), id-dsa keys, Dss-Parms and their inheritance from the issuer (section 2.3.2; read through `asn1core.keys`); none of the 5 verified (or 2 held) errata is on 2.2.2 or 2.3.2 |
| RFC 4055 | RFC 3279, updated by RFC 5756 | 2: 1468 and 1676, both editorial | sha-2 PKCS #1 v1.5 identifiers (section 5), RSASSA-PSS parameters (section 3.1) |
| RFC 5480 | RFC 3279, updated by RFC 8813 | 2: 6670 (keyTransport is keyEncipherment), 8026 (sect163r2) | EC keys: namedCurve parameters, ECPoint forms (sections 2.1.1, 2.2), key usage (section 3 with RFC 8813) |
| RFC 5758 | RFC 3279 | 0 (1 on file) | ecdsa-with-SHA2 identifiers, parameters MUST be omitted (section 3.2), hash identifiers (section 2), id-dsa-with-sha224 and id-dsa-with-sha256 (section 3.1) |
| RFC 8017 | obsoletes RFC 3447 | 5: 5111, **5154**, 5235, 5577, 7405 | RSASSA-PKCS1-v1_5 and RSASSA-PSS verification (sections 8.1.2, 8.2.2, 9.1.2, 9.2) as run by `sigwire[verify]`. Erratum 5154: appendix A.2.4 labels `sha224WithRSAEncryption` as SHA-256; it is SHA-224, `{ pkcs-1 14 }` (RFC 4055 section 5 agrees) |
| RFC 8032 | none | 6: 5519, 5930, 5968, 6348, 6851, 8197 | Ed25519 verification as run by `sigwire[verify]`. 5519 and 5968 settle the range of S (0 <= S < L); 5930 is the missing `raise` in the section 6 `verify()` |
| RFC 8410 | updated by RFC 9295 | 4: 6263, 6738, 7384, 8297 | id-Ed25519 (1.3.101.112) and id-Ed448 (1.3.101.113), parameters MUST be absent (sections 3, 6); 7384 notes the sa-Ed448 and pk-Ed448 definitions missing from section 9 |
| RFC 5912 | updated by RFC 6960, 9480, 9810 | 8 | the ASN.1 modules |
| RFC 6960 | updated by RFC 8954, 9654 | 6 | OCSP status, one of the two revocation inputs |

Mentioned in this repository and **not yet read** for any row: RFC 9881 (ML-DSA identifiers, Proposed
Standard, 2025-10, 2 verified errata; row `algorithms.ml_dsa`), RFC 8692 (SHAKE with RSA-PSS and ECDSA,
updates RFC 3279; not planned) and RFC 9295 (key usage bits for Ed25519 and Ed448; read with
`chain.ca_constraints`). Their statuses above come from `info`, and no section of them is cited.

Conformance corpus, outside the RFC series: NIST PKITS 1.0.1, "Public Key Interoperability Test Suite
Certification Path Validation", NIST CSRC (`https://csrc.nist.gov/projects/pki-testing`). Data
`PKITS_data.zip`, 3,052,513 octets, sha256 `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`;
document `PKITS.pdf`, 5,027,216 octets, sha256
`506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea`; both read 2026-11-13. Written against
RFC 3280 (which RFC 5280 obsoletes) and X.509; it predates RFC 9549 and RFC 9618. Terms not established,
so the corpus lives in a cache (`tools/fetch_pkits.py`) and not in the tree. Result on 2026-11-13,
first run: 247 cases, 178 pass, 69 not applicable, 0 fail. Result on 2026-11-13 after the
revocation rows (issuing distribution points, indirect CRLs, separate CRL signing keys, delta
CRLs) and DSA under `sigwire.verify.LEGACY`: **247 pass, 0 not applicable, 0 fail**
(`tests/test_pkits.py::test_pkits_counts`).

RFC 5280 sections read in full for the CRL algorithm (2026-11-13): 4.2.1.13, 5.2.3, 5.2.4, 5.2.5,
5.3.3, 6.3.3, with RFC 10007 section 4's amendment of step (f). Errata on those sections: none
verified; 3674 (held, editorial) renames "distribution field" to "distributionPoint field" in
6.3.3(b)(2)(i); 1774 (rejected) on the step (l) loop; 7164 (rejected) on 5.2.5.

Signature arithmetic is `sigwire[verify]`'s, and the primary sources for it beyond the RFC series (FIPS 186-5,
SP 800-186) are named in sigwire[verify]'s own `docs/rfc-map.md`, not copied here.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
