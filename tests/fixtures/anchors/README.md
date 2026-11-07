# Anchor fixtures

Recorded real certificates, not synthetic ones. Both were published by their operator at a
stable URI and are copied here as DER so the suite never reaches the network.

| File | What it is | Fetched |
|---|---|---|
| `isrg-root-x1.der` | ISRG Root X1: self-signed, RSA key. 1391 bytes. | 2026-11-11, `https://letsencrypt.org/certs/isrgrootx1.pem` |
| `isrg-root-x2-cross-signed.der` | ISRG Root X2's EC key, **issued by** ISRG Root X1. 1124 bytes. | 2026-11-11, `https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem` |

The second file is the reason these two are here rather than one. RFC 5280 sec. 6.1.1 supplies
trust anchor information and *offers* a self-signed certificate as one way to carry it; it never
requires one, and a cross-certificate is a legal anchor. It also separates the two fields an
implementation is most tempted to confuse: this certificate was signed with
`sha256WithRSAEncryption` (`1.2.840.113549.1.1.11`) while its own `subjectPublicKeyInfo` carries
`id-ecPublicKey` (`1.2.840.10045.2.1`) with the `secp384r1` curve (`1.3.132.0.34`) as its
parameters, and its subject (`CN=ISRG Root X2`) is not its issuer (`CN=ISRG Root X1`).

**The cross-certificate expired on 2025-09-15.** That is not a defect in the fixture and must not
be "fixed" by swapping in a live one: sec. 6.1.1 makes a trust anchor trusted by how it was
delivered, and the path algorithm applies none of its checks to the anchor, so loading it must
succeed after expiry exactly as before it. A fixture that quietly still worked if `load_anchor`
grew a validity check would be worse than one that proves it has none.

To re-record them (only if a fixture is ever replaced, never to make a test pass):

    python -c "import urllib.request,pathlib;from cryptography import x509;from cryptography.hazmat.primitives.serialization import Encoding;\
[pathlib.Path('tests/fixtures/anchors/'+n+'.der').write_bytes(x509.load_pem_x509_certificate(urllib.request.urlopen(u,timeout=30).read()).public_bytes(Encoding.DER)) for n,u in [('isrg-root-x1','https://letsencrypt.org/certs/isrgrootx1.pem'),('isrg-root-x2-cross-signed','https://letsencrypt.org/certs/isrg-root-x2-cross-signed.pem')]]"
