"""Microsoft certificate trust lists (MS-CTL) — a vendor format, not an RFC.

Placeholders until milestone M7 in ROADMAP.md lands; each stub raises rather than returning an empty
list, because "the Windows program trusts nothing" and "this build cannot read the CTL" are different
claims and only one of them is true.

Two facts about the source shape the design, both measured on 2026-11-07 by
`trustatlas/tools/collect_ctl.py`:

- the published form reachable from a Linux container is a CAB served over **plain HTTP**
  (`authrootstl.cab`, 80,353 octets, sha256 `c0aa761f…`; `disallowedcertstl.cab`, 5,652 octets,
  sha256 `1f2719b1…`), so the transport authenticates nothing;
- the only integrity protection is the signature carried inside the list, which is what
  `signed_by_microsoft()` exists to check.

Until that check exists, no caller may present `root_program()` output as what Windows trusts, as
opposed to what some bytes on the network said.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

__all__ = [
    "root_program",
    "signed_by_microsoft",
]


def root_program(stl: bytes) -> tuple[Any, ...]:
    """The entries of a trusted-root CTL, one per record.

    Not implemented yet — see the `ctl.root_program()` row and milestone M7 in ROADMAP.md. Depends on
    `pkix.cab.member()` for the bytes handed in, and on whatever the record layout turns out to be for
    the entries themselves; the shape of an entry is an open question, which is precisely why this
    returns nothing today instead of a guessed namedtuple.
    """
    raise NotImplementedError("root_program() is not implemented: MS-CTL, ROADMAP.md milestone M7")


def signed_by_microsoft(stl: bytes) -> Mapping[str, Any]:
    """Whether the list carries a signature over these bytes, and by what.

    Not implemented yet — see the `ctl.signed_by_microsoft()` row and milestone M7. This is the row
    that converts the CTL from "bytes as delivered over HTTP" into a statement about the program, and
    it is the reason the collector refuses to enumerate entries on its own.
    """
    raise NotImplementedError(
        "signed_by_microsoft() is not implemented: MS-CTL Authenticode, ROADMAP.md milestone M7"
    )
