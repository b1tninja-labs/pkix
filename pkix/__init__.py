"""pkix -- RFC 5280 path validation, the part Python never had.

Python can build a certificate and parse a certificate, and it cannot tell you whether a
certificate is valid. cryptography has no path validator; the one serious implementation,
certvalidator 0.11.1, has not been released since 2016-07-29 and sits on oscrypto, itself
dead since 2022-03-18.
"""

from __future__ import annotations

from . import anchors, apps, chain, cli, errors, names, policy, result, revocation, store, validity
from .anchors import Subtree, TrustAnchor, load_anchor
from .chain import candidates
from .names import constraint_holds
from .policy import resolve
from .result import validate
from .revocation import status_of
from .store import remember
from .validity import check_signature, check_validity

__version__ = "0.1.0"

__all__ = [
    "Subtree",
    "TrustAnchor",
    "__version__",
    "anchors",
    "apps",
    "candidates",
    "chain",
    "check_signature",
    "check_validity",
    "cli",
    "constraint_holds",
    "errors",
    "load_anchor",
    "names",
    "policy",
    "remember",
    "resolve",
    "result",
    "revocation",
    "status_of",
    "store",
    "validate",
    "validity",
]
