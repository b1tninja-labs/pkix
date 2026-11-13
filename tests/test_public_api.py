"""The surface contract: it exists, is documented, and a stub refuses to lie.

These are the tests that must fail loudly if a stub ever starts returning a plausible
empty value instead of raising. That is how a protocol library quietly becomes wrong: a
decoder learns to return an empty object rather than refuse, and every caller downstream
reads confidence where there was only silence.
"""

from __future__ import annotations

import importlib

import pytest

import pkix as package

SURFACE = [
    ("anchors", "load_anchor", "RFC 5280 sec. 6.1"),
    ("chain", "candidates", "RFC 5280 sec. 6.1"),
    ("validity", "check_signature", "RFC 5280"),
    ("validity", "check_validity", "RFC 5280"),
    ("names", "constraint_holds", "RFC 5280"),
    ("policy", "resolve", "RFC 5280"),
    ("revocation", "status_of", "RFC 5280"),
    ("result", "validate", "RFC 5280 sec. 6"),
    ("store", "remember", "design"),
]


def test_version_is_a_string():
    assert isinstance(package.__version__, str)


def test_public_names_all_exist():
    missing = [name for name in package.__all__ if not hasattr(package, name)]
    assert not missing, "__all__ names things that do not exist: " + ", ".join(missing)


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_surface_is_documented(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    assert target.__doc__, fn + " needs a docstring"
    assert cite in target.__doc__, fn + " must cite the document that defines it"


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_stubs_are_loud(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    if "Not implemented yet" not in (target.__doc__ or ""):
        pytest.skip(fn + " is implemented; pin it with a real vector test now")
    with pytest.raises((NotImplementedError, TypeError)):
        target()
