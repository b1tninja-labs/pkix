"""Basic certificate processing, RFC 5280 section 6.1.3: signature, validity, issuer, name constraints.

This cited section 6.2 until 2026-11-07; section 6.2 is "Using the Path Validation Algorithm", and the
per-certificate checks are step (a) of section 6.1.3 (outline and text read through rfclib).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Any

    Certificate = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "check_signature",
    "check_validity",
]


def check_signature(cert: Certificate, issuer: Certificate) -> None:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``validity.check_signature()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check_signature() is not implemented: RFC 5280")


def check_validity(cert: Certificate, at: datetime) -> None:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``validity.check_validity()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check_validity() is not implemented: RFC 5280")
