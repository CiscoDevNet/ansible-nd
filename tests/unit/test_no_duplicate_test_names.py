# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Collection guard: no unit-test module may define the same `test_` function twice.

Python keeps only the later definition of a redefined function, so pytest silently collects the second copy and the
first never runs (issue #609: three `test_nd_state_machine_*` tests were shadowed this way on `develop`). CI runs no
pylint over `tests/unit/`, so this test is the only thing that catches a recurrence.
"""

from __future__ import annotations

import ast
from pathlib import Path

UNIT_TEST_ROOT = Path(__file__).resolve().parent


def _duplicate_test_names(path: Path) -> list[str]:
    """
    # Summary

    Return one description per `test_` function that `path` defines more than once, at module level or inside a class.

    ## Raises

    None
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    duplicates: list[str] = []

    def scan(body: list[ast.stmt], scope: str) -> None:
        first_line: dict[str, int] = {}
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                if node.name in first_line:
                    duplicates.append(f"{path.relative_to(UNIT_TEST_ROOT)}: {scope}{node.name} at lines {first_line[node.name]} and {node.lineno}")
                else:
                    first_line[node.name] = node.lineno
            elif isinstance(node, ast.ClassDef):
                scan(node.body, f"{scope}{node.name}.")

    scan(tree.body, "")
    return duplicates


def test_no_duplicate_test_names() -> None:
    """
    # Summary

    Verify no `tests/unit/**/test_*.py` module defines a `test_` function name twice (module level or within one class),
    since the earlier definition would be shadowed and never collected by pytest.

    ## Test

    - Every `test_*.py` under `tests/unit/` is parsed with `ast`
    - No module-level or class-level `test_` name repeats within its scope

    ## Classes and Methods

    - None (collection guard; issue #609)
    """
    duplicates: list[str] = []
    for path in sorted(UNIT_TEST_ROOT.rglob("test_*.py")):
        duplicates.extend(_duplicate_test_names(path))
    assert not duplicates, "Shadowed test functions (only the later definition runs):\n  " + "\n  ".join(duplicates)
