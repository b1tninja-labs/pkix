"""policy mappings, constraints and anyPolicy resolution (RFC 5280).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    PolicyOutcome = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "resolve",
]


def resolve(chain: list, expected: set | None) -> PolicyOutcome:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``policy.resolve()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("resolve() is not implemented: RFC 5280")
