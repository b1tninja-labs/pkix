"""name forms, general names and constraint comparison, including internationalised forms.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Constraints = Any  # placeholder: give it a real type in the milestone that needs it
    GeneralName = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "constraint_holds",
]


def constraint_holds(name: GeneralName, constraints: Constraints, at_issuance: bool) -> bool:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``names.constraint_holds()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("constraint_holds() is not implemented: RFC 5280")
