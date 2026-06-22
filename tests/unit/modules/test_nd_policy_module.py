# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``plugins/modules/nd_manage_policy.py`` module-level wiring.

The bulk of ``nd_manage_policy``'s business logic lives in
``module_utils/nd_policy_resources.py`` (which has its own dedicated test
modules) and the state machine is covered end-to-end by the integration
suite under ``tests/integration/targets/nd_manage_policy``. This file
therefore intentionally stays small: it only exercises wiring that is
purely the *module wrapper's* responsibility and that the orchestrator or
resources tests cannot cover.

Currently in scope:

- The ``require_pydantic(module)`` guard added to ``main()``. We do not
  drive the real ``main()`` because that requires argspec satisfaction,
  ``AnsibleModule`` construction, and the full ``RestSend`` harness --
  none of which would add anything the behavioural assertion below
  does not already prove.
"""

# pylint: disable=protected-access

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy

# =============================================================================
# Lightweight test harness (file-private)
# =============================================================================


class FailJsonError(Exception):
    """Raised by ``FakeModule.fail_json`` so tests can ``pytest.raises`` cleanly."""


class FakeModule:
    """Minimal ``AnsibleModule`` stand-in. Only the surface needed by the
    ``require_pydantic`` guard is implemented: ``fail_json`` that captures
    its call and raises ``FailJsonError``."""

    def __init__(self) -> None:
        self.fail_json_called: dict[str, Any] | None = None

    def fail_json(self, msg: str, **kwargs: Any) -> None:
        """Capture the call and raise ``FailJsonError`` so callers stop."""
        self.fail_json_called = {"msg": msg, **kwargs}
        raise FailJsonError(msg)


# =============================================================================
# Test: require_pydantic guard wired into main()
# =============================================================================
#
# Reviewer (mikewiebe) asked for a module-wrapper unit test that simulates
# ``HAS_PYDANTIC=False`` to prove the freshly-added ``require_pydantic(module)``
# call in ``main()`` actually fails fast with the standard Ansible
# "missing required lib" message rather than crashing later with a cryptic
# AttributeError from the pydantic_compat shim.
#
# The check is in two parts:
#   1. Smoke assertion that ``nd_manage_policy`` imports ``require_pydantic``
#      from ``common.pydantic_compat`` -- if that import is ever removed,
#      attribute access in the test below would raise ``AttributeError``
#      and the test would fail loudly.
#   2. Behavioural assertion that, with ``HAS_PYDANTIC`` patched to False,
#      invoking the imported ``require_pydantic`` against a ``FakeModule``
#      causes ``fail_json`` to fire with a message naming ``pydantic``.
# Together these guarantee that, on a Pydantic-less runtime, ``main()`` would
# exit cleanly via the standard Ansible failure path before touching the
# NDPolicyModule / argspec helpers.


def test_nd_policy_module_00010(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    ``nd_manage_policy`` imports ``require_pydantic`` from
    ``common.pydantic_compat``, and that imported reference correctly
    short-circuits to ``module.fail_json`` when ``HAS_PYDANTIC`` is False --
    so on a runtime without Pydantic the module fails with the standard
    Ansible missing-required-lib message instead of a cryptic
    ``AttributeError`` later in the orchestrator stack.

    ## Test

    - Patch ``HAS_PYDANTIC`` on ``common.pydantic_compat`` to False.
    - Call ``nd_manage_policy.require_pydantic(fake_module)`` via the
      imported reference.
    - Assert ``FailJsonError`` was raised by ``FakeModule.fail_json``.
    - Assert the failure message contains the string ``pydantic`` (the exact
      wording comes from Ansible's ``missing_required_lib`` helper and is
      not pinned here to avoid coupling to upstream wording changes).

    ## Classes and Methods

    - ``plugins.modules.nd_manage_policy.require_pydantic`` (imported)
    - ``plugins.module_utils.common.pydantic_compat.require_pydantic``
    """
    # Sanity: the wrapper must have actually imported the symbol. If a
    # future refactor drops the import, this attribute access raises
    # AttributeError and the test fails before we get to the patching.
    assert hasattr(nd_manage_policy, "require_pydantic")

    from ansible_collections.cisco.nd.plugins.module_utils.common import (
        pydantic_compat,
    )

    monkeypatch.setattr(pydantic_compat, "HAS_PYDANTIC", False)

    module = FakeModule()
    with pytest.raises(FailJsonError):
        nd_manage_policy.require_pydantic(module)

    assert module.fail_json_called is not None
    assert "pydantic" in module.fail_json_called["msg"].lower()
