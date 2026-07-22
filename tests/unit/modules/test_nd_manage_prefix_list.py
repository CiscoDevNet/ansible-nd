from __future__ import annotations

import re

from ansible_collections.cisco.nd.plugins.modules import nd_manage_prefix_list

EXPECTED_RETURN_KEYS = (
    "changed",
    "output_level",
    "before",
    "after",
    "diff",
    "proposed",
    "logs",
    "msg",
)


def _return_entry(name: str) -> str:
    pattern = rf"^{name}:\n(?P<body>(?:  .+\n)+)"
    match = re.search(pattern, nd_manage_prefix_list.RETURN, re.MULTILINE)
    assert match is not None, f"{name!r} is missing from RETURN"
    return match.group("body")


def test_nd_manage_prefix_list_return_documents_state_machine_contract() -> None:
    for key in EXPECTED_RETURN_KEYS:
        body = _return_entry(key)
        assert "description:" in body
        assert "returned:" in body
        assert "type:" in body

    assert "elements: dict" in _return_entry("before")
    assert "elements: dict" in _return_entry("after")
    assert "elements: dict" in _return_entry("diff")
    assert "elements: dict" in _return_entry("proposed")
    assert "elements: str" in _return_entry("logs")
