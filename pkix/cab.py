"""Microsoft Cabinet (MS-CAB) container reading — a vendor format, not an RFC.

Every object in this module is a placeholder until milestone M7 in ROADMAP.md lands. A stub raises
instead of returning a plausible empty value: a trust map that silently answers "no members" would
report the Windows program as empty rather than refusing to speak about it.

The consumer is `pkix.ctl`, not `trustatlas`. The collector pins the CAB bytes by SHA-256 and
interprets nothing, because a wrong CFFOLDER/CFFILE boundary would produce a member that parses and a
thumbprint list that is quietly wrong. See the "Why the CTL rows belong here" section of ROADMAP.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "member",
]


def member(cab: bytes) -> Mapping[str, bytes]:
    """Members of a cabinet, keyed by the name in its CFFILE record.

    Not implemented yet — see the `cab.member()` row and milestone M7 in ROADMAP.md. The CFHEADER
    reports the folder table and file table offsets; each CFFOLDER carries the compression field that
    decides whether the member's bytes must be inflated before anything downstream can read them. That
    answer is part of the result a caller needs, so this signature will change when it lands rather
    than pretending one flag is enough.

    Raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("member() is not implemented: MS-CAB, ROADMAP.md milestone M7")
