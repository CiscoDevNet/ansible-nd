#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import pathlib


def ensure_switch_removal_status_handling(collection_root: pathlib.Path) -> bool:
    target = collection_root / "plugins/module_utils/rest/response_strategies/nd_v1_strategy.py"
    if target.is_symlink() or not target.is_file():
        raise ValueError("the ND response strategy is missing or is a symlink")
    source = target.read_text(encoding="utf-8")
    bindings = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
                and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "_MULTISTATUS_ITEM_KEYS"]
    if len(bindings) != 1:
        raise ValueError("cannot identify the ND multi-status envelope allowlist")
    value = bindings[0].value
    keys = ast.literal_eval(value)
    if not isinstance(keys, (tuple, list)) or not all(isinstance(key, str) for key in keys):
        raise ValueError("the ND multi-status envelope allowlist is not a literal sequence")
    if not {"results", "switchIds", "links"}.issubset(keys):
        raise ValueError("the ND multi-status envelope allowlist has an unsupported layout")
    if "items" in keys:
        return False
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:value.lineno - 1]) + value.col_offset
    end = sum(len(line) for line in lines[:value.end_lineno - 1]) + value.end_col_offset
    opening, closing = ("(", ")") if isinstance(keys, tuple) else ("[", "]")
    replacement = opening + ", ".join(json.dumps(key) for key in (*keys, "items")) + closing
    updated = source[:start] + replacement + source[end:]
    ast.parse(updated)
    target.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collection-root", type=pathlib.Path, default=pathlib.Path.cwd())
    args = parser.parse_args()
    try:
        changed = ensure_switch_removal_status_handling(args.collection_root)
    except (OSError, SyntaxError, TypeError, ValueError) as error:
        parser.exit(1, f"NDP_SWITCH_STATUS_PATCH_FAILED: {error}\n")
    print("NDP_SWITCH_STATUS_ENVELOPE_FIXED" if changed else "NDP_SWITCH_STATUS_ENVELOPE_READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())