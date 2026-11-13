# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `CrlChecker(explicit_deltas=True)` and `RevocationAnswer.reason_code`, `revocation_date` and `on_delta`
  (rows `revocation.crl_explicit_delta`, `revocation.answer_details`), proposed by revokekit.
- RFC 9598 SmtpUTF8Mailbox in `names` (row `names.smtp_utf8_mailbox`); RFC 9618 sec. 6.2 and 6.3 limits
  (`resolve(max_depth=, max_nodes=)`, `PathInputs.policy_max_depth` and `policy_max_nodes`).
- `validity.check_validity()`: RFC 5280 section 6.1.3 step (a)(2), inclusive of both ends, with an injected
  clock and a refusal of naive datetimes.
- `validity.check_signature()`: step (a)(1) for RSA PKCS #1 v1.5, RSA-PSS, ECDSA (P-256, P-384, P-521) and
  Ed25519, through `sigwire[verify]`, with named failures in `pkix.errors` and RFC 9925's id-alg-unsigned refused.
- `TrustAnchor.verify()`.
- `pkix.errors`.

### Changed

- `anchors` reads through `asn1core` and no longer imports `cryptography`. `TrustAnchor.issuer` is an
  `asn1core.Name`, `public_key` is the stored key octets, and `spki`, `tbs`, `self_issued` and
  `self_signed` are new fields. `cryptography` moved from the runtime to the dev dependencies and
  `sigwire[verify]` joined the runtime ones.
- The roadmap grew from 12 rows to 36 and tracks RFC 9618, RFC 10007, RFC 9608, RFC 9549, RFC 9598 and
  RFC 9925; RFC 8398 and RFC 8399 are recorded as obsolete.

Trust anchors, candidate discovery, validity and signatures are implemented; name constraints, policy,
revocation and `validate()` are stubs that raise `NotImplementedError`. [ROADMAP.md](ROADMAP.md) lists
what has to happen next.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for pkix.
- `pkix.apps` namespace reserved for composition that is not protocol behaviour.
