# Served chain, recorded 2026-11-07

Captured from one live TLS handshake with `letsencrypt.org`, through
`ssl.SSLSocket.get_unverified_chain()`, so the whole chain is recorded rather than only the leaf.
That call yields per-element DER on this interpreter, not wrapper objects. Each entry is written as
the DER that arrived, plus the PEM rendering of the same object; nothing here is re-encoded,
generated, or edited.

| File | Subject | Issuer | basicConstraints |
|---|---|---|---|
| `letsencrypt.org-0.der` | `CN=letsencrypt.org` | `CN=YE2, O=Let's Encrypt, C=US` | `SEQUENCE {}` — cA absent, so FALSE by default |
| `letsencrypt.org-1.der` | `CN=YE2, O=Let's Encrypt, C=US` | `CN=Root YE, O=ISRG, C=US` | cA TRUE, `pathLenConstraint 0` |
| `letsencrypt.org-2.der` | `CN=Root YE, O=ISRG, C=US` | `CN=ISRG Root X2, ...` | cA TRUE |
| `letsencrypt.org-3.der` | `CN=ISRG Root X2, ...` | `CN=ISRG Root X1, ...` | cA TRUE — a cross-certificate, not self-signed |

Why this particular chain, when any leaf would do:

- **Four deep.** Discovery has to walk three name-hops, which is where a search that links by
  anything other than the prepared name comparison starts to fail.
- **The last member is a cross-certificate.** `ISRG Root X2` is issued by `ISRG Root X1`, so the same
  key has an issuer inside the chain and can also be a trust anchor in its own right. That is what
  makes "the path stops where the anchor is reached" (`chain.candidates()`, RFC 5280 §6.1.1(d)) a
  testable claim instead of a guess — trusted as an anchor it yields a three-certificate path, and
  with X1 also trusted the search returns both.
- **The leaf's `basicConstraints` really is empty.** §4.2.1.9 makes an absent `cA` boolean mean the
  key "MUST NOT be used to verify certificate signatures", and `cA BOOLEAN DEFAULT FALSE` means the
  empty `SEQUENCE {}` is an assertion, not a silence. A synthetic non-CA certificate can be made to
  say the same thing, but only this one shows what a CA actually emits.

The certificates will expire. Expiry does not affect what they evidence here: discovery matches names
and reads `basicConstraints`, and validity belongs to RFC 5280 §6.1.3(a)(2) and its own row. If the
chain needs replacing, re-record from a live handshake rather than substituting a generated one, and
keep the cross-certificate at the end — that member is doing the work.
