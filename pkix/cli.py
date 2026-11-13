"""Command line entry point for pkix.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  pkix verify leaf.pem --chain intermediate.pem --anchor root.pem --at 2026-11-05T00:00:00Z"""


def build_parser():
    return argparse.ArgumentParser(
        prog="pkix",
        description="Certification path discovery and validation per RFC 5280: trust anchors, name constraints, policy mapping and constraints, CRL and OCSP status hooks, explicit result provenance",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour while the command is a stub. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print("pkix: no protocol behaviour is implemented yet; see ROADMAP.md", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
