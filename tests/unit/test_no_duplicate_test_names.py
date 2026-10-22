# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Collection guard: no unit-test module may bind the same `test_` function or `Test*` class twice in one scope.

Python keeps only the later definition of a redefined function or class, so pytest silently collects the second copy and the
first never runs (issue #609: three `test_nd_state_machine_*` tests were shadowed this way on `develop`). CI runs no
pylint over `tests/unit/`, so this test is the only thing that catches a recurrence. Bindings made inside `if`, `try`, `with`
and loop bodies land in the enclosing scope and are scanned too; the branches of one `if` / `try` / `match` are alternatives.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

UNIT_TEST_ROOT = Path(__file__).resolve().parent


def _collected_name(node: ast.stmt) -> str | None:
    """
    # Summary

    Return the pytest-collectible name `node` binds (`test_*` function or `Test*` class), or `None`.

    ## Raises

    None
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
        return node.name
    if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
        return node.name
    return None


def _bindings(body: list[ast.stmt], report: Callable[[str, int, int], None]) -> dict[str, int]:
    """
    # Summary

    Return the first line of every collectible name `body` binds in its own scope, calling `report(name, first, again)` for each
    rebinding. Control-flow statements are walked because their bodies bind names in the enclosing scope; the branches of one `if`,
    `try` / `except` or `match` are alternatives, so a name bound in several of them counts once. Function bodies are not entered
    (a nested `def` is not collected) and class bodies are separate scopes, handled by the caller.

    ## Raises

    None
    """
    first_line: dict[str, int] = {}

    def bind(name: str, lineno: int) -> None:
        if name in first_line:
            report(name, first_line[name], lineno)
        else:
            first_line[name] = lineno

    def merge_alternatives(branches: list[list[ast.stmt]]) -> None:
        union: dict[str, int] = {}
        for branch in branches:
            for name, lineno in _bindings(branch, report).items():
                union[name] = min(union.get(name, lineno), lineno)
        for name, lineno in sorted(union.items(), key=lambda item: item[1]):
            bind(name, lineno)

    for node in body:
        name = _collected_name(node)
        if name is not None:
            bind(name, node.lineno)
        elif isinstance(node, ast.If):
            merge_alternatives([node.body, node.orelse])
        elif isinstance(node, ast.Try):
            merge_alternatives([node.body + node.orelse] + [handler.body for handler in node.handlers])
            for inner, lineno in _bindings(node.finalbody, report).items():
                bind(inner, lineno)
        elif isinstance(node, ast.Match):
            merge_alternatives([case.body for case in node.cases])
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            sequential = node.body + (node.orelse if isinstance(node, (ast.For, ast.AsyncFor, ast.While)) else [])
            for inner, lineno in _bindings(sequential, report).items():
                bind(inner, lineno)
    return first_line


def _class_defs(body: list[ast.stmt]) -> Iterator[ast.ClassDef]:
    """
    # Summary

    Yield every class defined in `body`'s own scope, including classes inside `if`, `try`, `with`, loop and `match` bodies, without
    entering function bodies or the classes themselves (each class body is a separate scope the caller scans on its own).

    ## Raises

    None
    """
    for node in body:
        if isinstance(node, ast.ClassDef):
            yield node
        elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            yield from _class_defs(node.body + getattr(node, "orelse", []))
        elif isinstance(node, ast.Try):
            yield from _class_defs(node.body + node.orelse + node.finalbody)
            for handler in node.handlers:
                yield from _class_defs(handler.body)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                yield from _class_defs(case.body)


def _duplicate_test_names(path: Path, root: Path = UNIT_TEST_ROOT) -> list[str]:
    """
    # Summary

    Return one description per `test_` function or `Test*` class that `path` binds more than once in the same scope (module level or
    inside one class), including bindings made inside `if`, `try`, `with`, `for`, `while` and `match` statements of that scope.

    ## Raises

    None
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    duplicates: list[str] = []

    def scan(body: list[ast.stmt], scope: str) -> None:
        def report(name: str, first: int, again: int) -> None:
            duplicates.append(f"{path.relative_to(root)}: {scope}{name} at lines {first} and {again}")

        _bindings(body, report)
        for node in _class_defs(body):
            scan(node.body, f"{scope}{node.name}.")

    scan(tree.body, "")
    return duplicates


def test_no_duplicate_test_names() -> None:
    """
    # Summary

    Verify no `tests/unit/**/test_*.py` module binds a `test_` function or `Test*` class name twice in one scope (module level or
    within one class, including control-flow bodies), since the earlier definition would be shadowed and never collected by pytest.

    ## Test

    - Every `test_*.py` under `tests/unit/` is parsed with `ast`
    - No module-level or class-level collectible name repeats within its scope

    ## Classes and Methods

    - None (collection guard; issue #609)
    """
    duplicates: list[str] = []
    for path in sorted(UNIT_TEST_ROOT.rglob("test_*.py")):
        duplicates.extend(_duplicate_test_names(path))
    assert not duplicates, "Shadowed test functions (only the later definition runs):\n  " + "\n  ".join(duplicates)


_IF_BLOCK_DUPLICATE = '''
def test_delete_policy():
    """First."""


if True:
    def test_delete_policy():
        """Second, shadows the first."""
'''

_TRY_BLOCK_DUPLICATE = '''
def test_delete_policy():
    """First."""


try:
    import something_optional  # noqa: F401
    def test_delete_policy():
        """Second, shadows the first."""
except ImportError:
    pass
'''

_WITH_BLOCK_DUPLICATE = '''
def test_delete_policy():
    """First."""


with open("/dev/null") as handle:
    def test_delete_policy():
        """Second, shadows the first."""
'''

_DUPLICATE_TEST_CLASS = '''
class TestPolicy:
    def test_one(self):
        """First class."""


class TestPolicy:
    def test_two(self):
        """Second class, shadows the first."""
'''

_CLASS_LEVEL_IF_DUPLICATE = '''
class TestPolicy:
    def test_one(self):
        """First."""

    if True:
        def test_one(self):
            """Second, shadows the first inside the class."""
'''

_NESTED_CLASS_DUPLICATE = '''
class TestOuter:
    class TestInner:
        def test_one(self):
            """First."""

        def test_one(self):
            """Second, shadows the first; reported once with the full scope."""
'''

_IF_ELSE_ALTERNATIVES = '''
import sys

if sys.version_info >= (3, 11):
    def test_delete_policy():
        """Only one branch binds the name."""
else:
    def test_delete_policy():
        """Only one branch binds the name."""
'''

_TRY_EXCEPT_ALTERNATIVES = '''
try:
    import something_optional  # noqa: F401

    def test_delete_policy():
        """Runs when the import works."""
except ImportError:
    def test_delete_policy():
        """Runs when it does not."""
'''

_SEPARATE_SCOPES = '''
def test_delete_policy():
    """Module level."""


class TestPolicy:
    def test_delete_policy(self):
        """Same name, different scope."""


class TestOther:
    def test_delete_policy(self):
        """Same name, different scope."""


def test_helper_closures():
    def test_delete_policy():
        """A nested def is not collected by pytest."""
    test_delete_policy()
'''


@pytest.mark.parametrize(
    "source, expected",
    [
        (_IF_BLOCK_DUPLICATE, ["test_delete_policy at lines 2 and 7"]),
        (_TRY_BLOCK_DUPLICATE, ["test_delete_policy at lines 2 and 8"]),
        (_WITH_BLOCK_DUPLICATE, ["test_delete_policy at lines 2 and 7"]),
        (_DUPLICATE_TEST_CLASS, ["TestPolicy at lines 2 and 7"]),
        (_CLASS_LEVEL_IF_DUPLICATE, ["TestPolicy.test_one at lines 3 and 7"]),
        (_NESTED_CLASS_DUPLICATE, ["TestOuter.TestInner.test_one at lines 4 and 7"]),
    ],
    ids=["if-block", "try-block", "with-block", "duplicate-test-class", "class-level-if-block", "nested-class-reported-once"],
)
def test_guard_catches_shadowing_inside_control_flow_and_duplicate_test_classes(tmp_path, source: str, expected: list[str]) -> None:
    """
    # Summary

    Verify the guard reports a `test_` function or `Test*` class rebound inside an `if`, `try` or `with` block of the same scope, and a
    `Test*` class defined twice (PR #618 review): Python keeps the later binding in every one of these cases.

    ## Test

    - Each source is written to a temporary `test_*.py` and scanned with `_duplicate_test_names`
    - Exactly the expected shadowing is reported, with the scope prefix and both line numbers

    ## Classes and Methods

    - _duplicate_test_names()
    """
    path = tmp_path / "test_probe.py"
    path.write_text(source, encoding="utf-8")

    assert _duplicate_test_names(path, root=tmp_path) == [f"test_probe.py: {item}" for item in expected]


@pytest.mark.parametrize(
    "source",
    [_IF_ELSE_ALTERNATIVES, _TRY_EXCEPT_ALTERNATIVES, _SEPARATE_SCOPES],
    ids=["if-else-alternatives", "try-except-alternatives", "separate-scopes"],
)
def test_guard_ignores_alternative_branches_and_separate_scopes(tmp_path, source: str) -> None:
    """
    # Summary

    Verify the guard does not flag a name bound in mutually exclusive branches (`if` / `else`, `try` / `except`), the same name in
    different classes, or a `def` nested inside a test function: none of these shadows a collected test (PR #618 review).

    ## Test

    - Each source is written to a temporary `test_*.py` and scanned with `_duplicate_test_names`
    - Nothing is reported

    ## Classes and Methods

    - _duplicate_test_names()
    """
    path = tmp_path / "test_probe.py"
    path.write_text(source, encoding="utf-8")

    assert not _duplicate_test_names(path, root=tmp_path)
