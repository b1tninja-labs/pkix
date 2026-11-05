"""trust anchor selection, including name restrictions and certificates only sets (RFC 5280
sec. 6.1).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    TrustAnchor = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "load_anchor",
]


def load_anchor(cert_der: bytes, name_restriction: str | None) -> TrustAnchor:
    """Pending behaviour defined by RFC 5280 sec. 6.1.

    Not implemented yet. See the ``anchors.load_anchor()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("load_anchor() is not implemented: RFC 5280 sec. 6.1")
