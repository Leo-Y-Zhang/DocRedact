"""The offline claim, enforced instead of asserted.

README and `docs/PRD.md` both promise that DocRedact cannot reach the network or
start a process. That promise is only worth something if something checks it, so
this module parses every source file under `src/docredact/` and inspects the
import statements directly. An AST walk is used rather than a text search because
a text search cannot tell an import from the word appearing in a comment, and
this file is full of the forbidden words itself.

`urllib.parse` is deliberately allowed: it is pure string manipulation with no
transport underneath, and `extractors.py` needs `unquote` to percent-decode a
`mailto:` href so an address cannot hide from the email detector. `urllib.request`
is what would open a connection, and it is forbidden here like the rest.
"""
from __future__ import annotations

import ast
from pathlib import Path

from conftest import PROJECT_ROOT

SRC = PROJECT_ROOT / "src" / "docredact"

# Top-level modules that can open a socket, speak HTTP, or start a process.
FORBIDDEN_ROOTS = {
    "asyncio",
    "ftplib",
    "http",
    "httpx",
    "imaplib",
    "multiprocessing",
    "poplib",
    "requests",
    "smtplib",
    "socket",
    "socketserver",
    "ssl",
    "subprocess",
    "telnetlib",
    "urllib3",
    "webbrowser",
    "xmlrpc",
}

# Modules inside an otherwise-permitted package that are forbidden anyway.
FORBIDDEN_EXACT = {
    "urllib.error",
    "urllib.request",
    "urllib.response",
    "urllib.robotparser",
}

SOURCE_FILES = sorted(SRC.rglob("*.py"))


def _imported_modules(path: Path) -> set[str]:
    """Every module name the file imports, dotted form, aliases resolved away."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        # A relative import (level > 0) is inside the package; module is None
        # for `from . import x`, so guard both.
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            names.add(node.module)
    return names


def _offending(names: set[str]) -> set[str]:
    hits = {name for name in names if name in FORBIDDEN_EXACT}
    hits |= {name for name in names if name.split(".")[0] in FORBIDDEN_ROOTS}
    return hits


def test_source_tree_is_not_empty() -> None:
    """Guard the guard: an empty file list would make every check below vacuous."""
    assert len(SOURCE_FILES) >= 10, f"expected the whole package, found {SOURCE_FILES}"


def test_no_module_imports_network_or_process_machinery() -> None:
    offenders = {
        path.relative_to(PROJECT_ROOT).as_posix(): sorted(found)
        for path in SOURCE_FILES
        if (found := _offending(_imported_modules(path)))
    }
    assert not offenders, (
        "src/docredact must not import network or subprocess machinery; "
        f"found {offenders}. If this is deliberate, the offline claims in "
        "README.md and docs/PRD.md have to change first."
    )


def test_the_only_url_namespace_import_is_the_documented_one() -> None:
    """`urllib.parse` is allowed, but only where the documents say it is used."""
    users = {
        path.relative_to(PROJECT_ROOT).as_posix(): sorted(
            name for name in _imported_modules(path) if name.split(".")[0] == "urllib"
        )
        for path in SOURCE_FILES
    }
    urllib_users = {path: names for path, names in users.items() if names}
    assert urllib_users == {"src/docredact/extractors.py": ["urllib.parse"]}, urllib_users


def test_the_detector_would_catch_a_real_violation() -> None:
    """A test that has never been seen to fail proves nothing - so fail it on purpose."""
    assert _offending({"socket"}) == {"socket"}
    assert _offending({"urllib.request"}) == {"urllib.request"}
    assert _offending({"http.client"}) == {"http.client"}
    assert _offending({"urllib.parse"}) == set()
