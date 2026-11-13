#!/usr/bin/env python3
"""Fetch NIST PKITS 1.0.1 into a cache outside the repository, and refuse bytes that are not pinned.

The Public Key Interoperability Test Suite is pkix's conformance corpus (ROADMAP row
`corpus.path_validation`). The owner approved downloading certificate corpora on 2026-11-13; its
terms are not established (the NIST project page carries none of its own and the nist.gov copyright
page returned 404), so the zip and its certificates are never copied into this tree. They live in:

    $PKIX_PKITS_DIR                         when set
    %LOCALAPPDATA%\\pkix\\pkits              on Windows
    $XDG_CACHE_HOME/pkix/pkits or ~/.cache/pkix/pkits elsewhere

The pins were measured on 2026-11-13 from the URL below. A download that differs in size or SHA-256
is deleted, not used: a test suite whose corpus can change under it reports the weather.

Standard library only. Run it with `python tools/fetch_pkits.py`; `--check` verifies the cached copy
without touching the network, `--where` prints the cache path.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import sys
import tempfile
import urllib.request

URL = "https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip"
FILENAME = "PKITS_data.zip"
# Read 2026-11-13: HTTP 200, Content-Type application/x-zip-compressed, Last-Modified
# Sun, 29 Sep 2024 23:16:05 GMT. Members are dated 2011-04-14, which is PKITS 1.0.1.
SIZE = 3_052_513
SHA256 = "592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665"
# The description document the expected outcomes in tests/pkits_cases.py were read from (not
# fetched by this tool; recorded so a reader can check the same bytes):
# https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf
# 5,027,216 octets, sha256 506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea.
ENV = "PKIX_PKITS_DIR"


def cache_dir() -> pathlib.Path:
    """Where the corpus lives: never inside the repository."""
    override = os.environ.get(ENV)
    if override:
        return pathlib.Path(override)
    local = os.environ.get("LOCALAPPDATA")
    if sys.platform == "win32" and local:
        return pathlib.Path(local) / "pkix" / "pkits"
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = pathlib.Path(xdg) if xdg else pathlib.Path.home() / ".cache"
    return base / "pkix" / "pkits"


def corpus_path() -> pathlib.Path:
    return cache_dir() / FILENAME


def verify(path: pathlib.Path) -> str | None:
    """None when `path` holds the pinned bytes, else why not."""
    if not path.is_file():
        return f"{path} does not exist"
    size = path.stat().st_size
    if size != SIZE:
        return f"{path} is {size} octets, pinned {SIZE}"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != SHA256:
        return f"{path} has sha256 {digest}, pinned {SHA256}"
    return None


def fetch(target: pathlib.Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    # S310: URL is the fixed https constant above, never a caller's string.
    request = urllib.request.Request(URL, headers={"User-Agent": "pkix-fetch-pkits/1"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        data = response.read(SIZE + 1)
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=".pkits-", suffix=".part")
    partial = pathlib.Path(name)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        problem = verify(partial)
        if problem is not None:
            raise SystemExit(f"refused the download: {problem}")
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the cached copy only")
    parser.add_argument("--where", action="store_true", help="print the cache path and exit")
    args = parser.parse_args(argv)
    target = corpus_path()
    if args.where:
        print(target)
        return 0
    problem = verify(target)
    if problem is None:
        print(f"ok {target} ({SIZE} octets, sha256 {SHA256})")
        return 0
    if args.check:
        print(problem, file=sys.stderr)
        return 1
    fetch(target)
    print(f"fetched {target} ({SIZE} octets, sha256 {SHA256})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
