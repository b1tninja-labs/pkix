"""the status interface plus an allow list of trusted decisions.

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
    Status = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "status_of",
]


def status_of(cert: Certificate, issuer: Certificate, at: datetime) -> Status:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``revocation.status_of()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("status_of() is not implemented: RFC 5280")
