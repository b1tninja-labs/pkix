"""the outcome object with provenance for every decision.

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
    Result = Any  # placeholder: give it a real type in the milestone that needs it
    ValidationPolicy = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "validate",
]


def validate(leaf: Certificate, anchors: list, at: datetime, policy: ValidationPolicy) -> Result:
    """Pending behaviour defined by RFC 5280 sec. 6.

    Not implemented yet. See the ``result.validate()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("validate() is not implemented: RFC 5280 sec. 6")
