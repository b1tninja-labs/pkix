"""Reading AlgorithmIdentifier and SubjectPublicKeyInfo down to what a verifier needs.

This is certificate structure, so it is read with `asn1core`'s codec; the arithmetic that follows is
`sigwire[verify]`'s. Every OID below was read from the document that defines it, named beside the table,
and every parameter rule is that document's own wording. Where a document is silent, the choice is
pkix's and the comment says so.

ROADMAP row `algorithms.rehome` moves this module into `asn1core` (its `dk.spki-key` row) once that
exists; until then pkix owns the interpretation and `asn1core` owns the TLVs.
"""

from __future__ import annotations

from dataclasses import dataclass

import asn1core
from asn1core import Node, Tag, TagClass

from .errors import MalformedAlgorithm, SignatureUnsupported, UnsignedCertificate

__all__ = [
    "ECDSA",
    "ED25519",
    "RSA_PKCS1V15",
    "RSA_PSS",
    "AlgorithmId",
    "EcKey",
    "Ed25519Key",
    "PublicKey",
    "RsaKey",
    "SignatureScheme",
    "decode_algorithm",
    "decode_ecdsa_signature",
    "decode_public_key",
    "decode_signature_algorithm",
    "is_null",
    "split_spki",
]

RSA_PKCS1V15 = "rsa-pkcs1v15"
RSA_PSS = "rsa-pss"
ECDSA = "ecdsa"
ED25519 = "ed25519"

_SEQUENCE = Tag(16, True, TagClass.universal)
_INTEGER = Tag(2, False, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)
_NULL = Tag(5, False, TagClass.universal)
_BIT_STRING = Tag(3, False, TagClass.universal)

# RFC 3279 sections 2.3.1 and 2.2.3 (rsaEncryption, id-ecPublicKey, ecdsa-with-SHA1), RFC 4055
# section 6 (the sha-2 WithRSAEncryption identifiers, id-RSASSA-PSS, id-mgf1), RFC 5758 sections 2
# and 3.2 (hash and ecdsa-with-SHA2 identifiers), RFC 5480 section 2.1.1.1 (named curves),
# RFC 8410 section 3 (id-Ed25519, id-Ed448) and RFC 9925 section 3.1 (id-alg-unsigned).
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
RSASSA_PSS = "1.2.840.113549.1.1.10"
ID_MGF1 = "1.2.840.113549.1.1.8"
ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
ID_ED25519 = "1.3.101.112"
ID_ED448 = "1.3.101.113"
ID_ALG_UNSIGNED = "1.3.6.1.5.5.7.6.36"

_HASH_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

_RSA_SIGNATURES = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}

_ECDSA_SIGNATURES = {
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}

_CURVES = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
}
_CURVE_BYTES = {"P-256": 32, "P-384": 48, "P-521": 66}

# RFC 4055 section 3.1: the defaults an absent field stands for.
_PSS_DEFAULT_SALT = 20


@dataclass(frozen=True, slots=True)
class AlgorithmId:
    """A decoded AlgorithmIdentifier: the OID and the parameters TLV, or None when absent."""

    oid: str
    parameters: Node | None
    raw: bytes


@dataclass(frozen=True, slots=True)
class SignatureScheme:
    """What a signatureAlgorithm asks a verifier to do."""

    algorithm: AlgorithmId
    scheme: str
    hash_name: str | None
    #: RSASSA-PSS only: the salt length the parameters name (RFC 4055 section 3.1 default 20).
    salt_length: int | None = None
    #: RSASSA-PSS only: the hash MGF1 runs over.
    mgf_hash: str | None = None


@dataclass(frozen=True, slots=True)
class RsaKey:
    n: int
    e: int


@dataclass(frozen=True, slots=True)
class EcKey:
    curve: str
    x: int
    y: int


@dataclass(frozen=True, slots=True)
class Ed25519Key:
    public: bytes


type PublicKey = RsaKey | EcKey | Ed25519Key


def _decode_one(raw: bytes, what: str) -> Node:
    """Decode exactly one DER element that is all of `raw`."""
    try:
        node, end = asn1core.decode(raw, der=True)
    except asn1core.Asn1Error as exc:
        raise MalformedAlgorithm(f"{what} is not DER: {exc}") from exc
    if end != len(raw):
        raise MalformedAlgorithm(f"{what} has {len(raw) - end} trailing octet(s)")
    return node


def is_null(node: Node) -> bool:
    return node.tag == _NULL and node.payload == b""


def _algorithm_from_node(node: Node, what: str) -> AlgorithmId:
    if node.tag != _SEQUENCE or not 1 <= len(node.children) <= 2:
        raise MalformedAlgorithm(f"{what} is not a SEQUENCE of an OID and optional parameters")
    oid_node = node.children[0]
    if oid_node.tag != _OID or oid_node.payload is None:
        raise MalformedAlgorithm(f"{what} does not start with an OBJECT IDENTIFIER")
    try:
        arcs = asn1core.decode_oid(oid_node.payload)
    except asn1core.Asn1Error as exc:
        raise MalformedAlgorithm(f"{what} carries a bad OBJECT IDENTIFIER: {exc}") from exc
    parameters = node.children[1] if len(node.children) == 2 else None
    return AlgorithmId(".".join(str(arc) for arc in arcs), parameters, node.raw)


def decode_algorithm(raw: bytes) -> AlgorithmId:
    """An AlgorithmIdentifier (RFC 5280 section 4.1.1.2) read from its stored TLV."""
    return _algorithm_from_node(_decode_one(raw, "AlgorithmIdentifier"), "AlgorithmIdentifier")


def _hash_of(node: Node, what: str) -> str:
    """A HashAlgorithm of RFC 4055 section 2.1: its parameters SHOULD be absent and MUST be NULL if
    present, so absent and NULL are both accepted and anything else is refused."""
    algorithm = _algorithm_from_node(node, what)
    if algorithm.parameters is not None and not is_null(algorithm.parameters):
        raise MalformedAlgorithm(f"{what}: hash parameters must be absent or NULL (RFC 4055 s. 6)")
    name = _HASH_OIDS.get(algorithm.oid)
    if name is None:
        raise SignatureUnsupported(
            f"{what}: hash {algorithm.oid} is not one RFC 4055 section 2.1 lists"
        )
    return name


def _pss_parameters(parameters: Node | None) -> tuple[str, str, int]:
    """RSASSA-PSS-params (RFC 4055 section 3.1): (hash, MGF1 hash, salt length).

    The module is EXPLICIT TAGS (RFC 4055 section 6), so each [n] wraps its field. Absent fields
    stand for their defaults, and the explicit spelling of a default is accepted too: section 3.1
    says validators MUST accept both for hashAlgorithm, maskGenAlgorithm and trailerField.
    """
    if parameters is None:
        raise MalformedAlgorithm("RSASSA-PSS parameters are required in a signature algorithm")
    if parameters.tag != _SEQUENCE:
        raise MalformedAlgorithm("RSASSA-PSS-params is not a SEQUENCE")
    hash_name, mgf_hash, salt, trailer = "sha1", "sha1", _PSS_DEFAULT_SALT, 1
    seen = -1
    for field in parameters.children:
        if not field.tag.constructed or field.tag.tag_class != TagClass.context:
            raise MalformedAlgorithm("RSASSA-PSS-params holds a field that is not [0]..[3]")
        number = field.tag.number
        if number <= seen or number > 3:
            raise MalformedAlgorithm("RSASSA-PSS-params fields are out of order or unknown")
        seen = number
        if len(field.children) != 1:
            raise MalformedAlgorithm(f"RSASSA-PSS-params [{number}] must wrap exactly one value")
        inner = field.children[0]
        if number == 0:
            hash_name = _hash_of(inner, "RSASSA-PSS hashAlgorithm")
        elif number == 1:
            mgf = _algorithm_from_node(inner, "RSASSA-PSS maskGenAlgorithm")
            if mgf.oid != ID_MGF1 or mgf.parameters is None:
                raise MalformedAlgorithm("RSASSA-PSS maskGenAlgorithm must be id-mgf1 with a hash")
            mgf_hash = _hash_of(mgf.parameters, "MGF1 hash")
        elif number == 2:
            salt = _small_integer(inner, "RSASSA-PSS saltLength")
        else:
            trailer = _small_integer(inner, "RSASSA-PSS trailerField")
    if trailer != 1:
        raise MalformedAlgorithm("RSASSA-PSS trailerField MUST be 1 (RFC 4055 section 3.1)")
    return hash_name, mgf_hash, salt


def _small_integer(node: Node, what: str) -> int:
    if node.tag != _INTEGER or node.payload is None:
        raise MalformedAlgorithm(f"{what} is not an INTEGER")
    try:
        value = asn1core.check_integer(node.payload)
    except asn1core.Asn1Error as exc:
        raise MalformedAlgorithm(f"{what} is not a minimal INTEGER: {exc}") from exc
    if not 0 <= value < 2**31:
        raise MalformedAlgorithm(f"{what} is out of range")
    return value


def decode_signature_algorithm(raw: bytes) -> SignatureScheme:
    """Turn a signatureAlgorithm into a scheme, a hash and the parameters that go with them.

    Raises `UnsignedCertificate` for id-alg-unsigned (RFC 9925 section 4), `SignatureUnsupported` for
    any OID not listed here, and `MalformedAlgorithm` when the parameters break the rule of the
    document that defines the OID.
    """
    algorithm = decode_algorithm(raw)
    oid, parameters = algorithm.oid, algorithm.parameters
    if oid == ID_ALG_UNSIGNED:
        raise UnsignedCertificate(
            "id-alg-unsigned: RFC 9925 section 4 - such a signature is always invalid and a "
            "validator MUST NOT accept it in a certification path"
        )
    if oid in _RSA_SIGNATURES:
        # RFC 4055 section 5: parameters MUST be NULL, and implementations MUST accept them absent.
        if parameters is not None and not is_null(parameters):
            raise MalformedAlgorithm(f"{oid}: parameters must be NULL or absent (RFC 4055 s. 5)")
        return SignatureScheme(algorithm, RSA_PKCS1V15, _RSA_SIGNATURES[oid])
    if oid in _ECDSA_SIGNATURES:
        # RFC 5758 section 3.2 and RFC 3279 section 2.2.3: the encoding MUST omit the parameters.
        if parameters is not None:
            raise MalformedAlgorithm(f"{oid}: ECDSA parameters MUST be omitted (RFC 5758 s. 3.2)")
        return SignatureScheme(algorithm, ECDSA, _ECDSA_SIGNATURES[oid])
    if oid == ID_ED25519:
        if parameters is not None:
            raise MalformedAlgorithm("Ed25519 parameters MUST be absent (RFC 8410 section 6)")
        return SignatureScheme(algorithm, ED25519, None)
    if oid == RSASSA_PSS:
        hash_name, mgf_hash, salt = _pss_parameters(parameters)
        return SignatureScheme(algorithm, RSA_PSS, hash_name, salt, mgf_hash)
    raise SignatureUnsupported(f"signature algorithm {oid} is not one pkix verifies")


def _bit_string_octets(node: Node, what: str) -> bytes:
    if node.tag != _BIT_STRING or node.payload is None:
        raise MalformedAlgorithm(f"{what} is not a BIT STRING")
    try:
        unused, data = asn1core.check_bit_string(node.payload)
    except asn1core.Asn1Error as exc:
        raise MalformedAlgorithm(f"{what} is a malformed BIT STRING: {exc}") from exc
    if unused:
        raise MalformedAlgorithm(f"{what} must be whole octets")
    return data


def _positive_integer(node: Node, what: str) -> int:
    if node.tag != _INTEGER or node.payload is None:
        raise MalformedAlgorithm(f"{what} is not an INTEGER")
    try:
        value = asn1core.check_integer(node.payload)
    except asn1core.Asn1Error as exc:
        raise MalformedAlgorithm(f"{what} is not a minimal INTEGER: {exc}") from exc
    if value <= 0:
        raise MalformedAlgorithm(f"{what} must be positive")
    return value


def split_spki(spki: bytes) -> tuple[AlgorithmId, bytes]:
    """SubjectPublicKeyInfo (RFC 5280 section 4.1.2.7) as its algorithm and its key octets.

    The key octets are the BIT STRING's content without the unused-bits octet, which must be zero:
    every key type pkix reads is a whole number of octets.
    """
    node = _decode_one(spki, "SubjectPublicKeyInfo")
    if node.tag != _SEQUENCE or len(node.children) != 2:
        raise MalformedAlgorithm("SubjectPublicKeyInfo is not a SEQUENCE of two fields")
    algorithm = _algorithm_from_node(node.children[0], "SubjectPublicKeyInfo algorithm")
    return algorithm, _bit_string_octets(node.children[1], "subjectPublicKey")


def decode_public_key(spki: bytes) -> PublicKey:
    """A SubjectPublicKeyInfo read into the numbers a verifier needs.

    rsaEncryption: parameters MUST be NULL (RFC 3279 section 2.3.1, RFC 4055 section 6), key is a
    DER RSAPublicKey. id-ecPublicKey: parameters MUST be a namedCurve (RFC 5480 section 2.1.1), the
    point must start 0x04 (uncompressed) - 0x02 and 0x03 are legal but pkix does not decompress yet -
    and any other first octet MUST be rejected (section 2.2). id-Ed25519: parameters MUST be absent
    (RFC 8410 section 3), the key is the 32 octets of the BIT STRING.
    """
    algorithm, key_octets = split_spki(spki)
    oid, parameters = algorithm.oid, algorithm.parameters

    if oid == RSA_ENCRYPTION:
        if parameters is None or not is_null(parameters):
            raise MalformedAlgorithm("rsaEncryption parameters MUST be NULL (RFC 3279 s. 2.3.1)")
        rsa_node = _decode_one(key_octets, "RSAPublicKey")
        if rsa_node.tag != _SEQUENCE or len(rsa_node.children) != 2:
            raise MalformedAlgorithm("RSAPublicKey is not SEQUENCE { modulus, publicExponent }")
        return RsaKey(
            _positive_integer(rsa_node.children[0], "RSA modulus"),
            _positive_integer(rsa_node.children[1], "RSA publicExponent"),
        )
    if oid == ID_EC_PUBLIC_KEY:
        if parameters is None or parameters.tag != _OID or parameters.payload is None:
            raise MalformedAlgorithm("id-ecPublicKey needs a namedCurve (RFC 5480 section 2.1.1)")
        try:
            curve_oid = ".".join(str(a) for a in asn1core.decode_oid(parameters.payload))
        except asn1core.Asn1Error as exc:
            raise MalformedAlgorithm(f"bad namedCurve: {exc}") from exc
        curve = _CURVES.get(curve_oid)
        if curve is None:
            raise SignatureUnsupported(f"elliptic curve {curve_oid} is not P-256, P-384 or P-521")
        width = _CURVE_BYTES[curve]
        if not key_octets or key_octets[0] not in (0x02, 0x03, 0x04):
            raise MalformedAlgorithm(
                "ECPoint first octet is not 0x02, 0x03 or 0x04 (RFC 5480 s. 2.2)"
            )
        if key_octets[0] != 0x04:
            raise SignatureUnsupported("compressed EC public keys are not decompressed yet")
        if len(key_octets) != 1 + 2 * width:
            raise MalformedAlgorithm(f"an uncompressed {curve} point is {1 + 2 * width} octets")
        return EcKey(
            curve,
            int.from_bytes(key_octets[1 : 1 + width], "big"),
            int.from_bytes(key_octets[1 + width :], "big"),
        )
    if oid == ID_ED25519:
        if parameters is not None:
            raise MalformedAlgorithm("Ed25519 parameters MUST be absent (RFC 8410 section 3)")
        if len(key_octets) != 32:
            raise MalformedAlgorithm("an Ed25519 public key is 32 octets (RFC 8032 section 5.1.5)")
        return Ed25519Key(key_octets)
    raise SignatureUnsupported(f"public key algorithm {oid} is not one pkix verifies with")


def decode_ecdsa_signature(signature: bytes) -> tuple[int, int] | None:
    """Ecdsa-Sig-Value (RFC 3279 section 2.2.3): (r, s), or None when it is not a valid encoding.

    A signature is the attacker's input, so an encoding that is not DER, has trailing octets, or
    carries a non-positive integer is an invalid signature and not an error in the caller.
    """
    try:
        node, end = asn1core.decode(signature, der=True)
        if end != len(signature) or node.tag != _SEQUENCE or len(node.children) != 2:
            return None
        return (
            _positive_integer(node.children[0], "r"),
            _positive_integer(node.children[1], "s"),
        )
    except (asn1core.Asn1Error, MalformedAlgorithm):
        return None
