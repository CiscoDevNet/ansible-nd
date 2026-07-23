# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``NDConfigCollection.get_diff_config`` dispatch behavior.

``get_diff_config`` forwards ``exclude_unset`` and ``allow_superset`` to the
concrete model's ``get_diff``. Because Python dispatches ``get_diff`` to the
subclass override (not to ``NDBaseModel.get_diff``), every override must accept
both keywords. These tests exercise that contract *through* ``NDConfigCollection``
rather than by calling ``get_diff`` directly, so a subclass that predates the
shared signature is caught here:

- a conforming override receives ``allow_superset`` unchanged, and its return
  value flows back out as ``no_diff`` / ``changed``.
- ``allow_superset`` defaults to ``False`` when the caller omits it.
- a non-conforming override (old ``get_diff(self, other, exclude_unset=False)``
  signature) surfaces the incompatibility as a loud ``TypeError`` -- the failure
  is intentional and is not hidden by the collection.
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import ClassVar, List, Literal, Optional

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection

# =============================================================================
# Test doubles
# =============================================================================


class _ConformingModel(NDBaseModel):
    """Override that conforms to the shared ``get_diff`` contract.

    It accepts ``allow_superset`` and lets the forwarded value drive the result,
    so a test can prove the keyword was dispatched through ``NDConfigCollection``:
    ``True`` -> "no diff" (subset), ``False`` -> "changed".
    """

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"]] = "single"

    name: str
    value: Optional[str] = None

    def get_diff(self, other: "NDBaseModel", exclude_unset: bool = False, allow_superset: bool = False) -> bool:
        return bool(allow_superset)


class _NonConformingModel(NDBaseModel):
    """Override predating the contract: it omits ``allow_superset`` by design.

    Mirrors the ``get_diff`` overrides on in-flight PRs #286/#312 that have not
    yet adopted the shared signature. Forwarding ``allow_superset`` to it must
    raise ``TypeError`` rather than be silently swallowed.
    """

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"]] = "single"

    name: str
    value: Optional[str] = None

    def get_diff(self, other: "NDBaseModel", exclude_unset: bool = False) -> bool:  # noqa: type checked at runtime
        return True


# =============================================================================
# Tests
# =============================================================================


def test_get_diff_config_forwards_allow_superset_to_override():
    """``allow_superset`` is dispatched to the concrete override unchanged.

    The conforming override returns the forwarded value, so ``True`` collapses to
    "no_diff" and ``False`` to "changed" -- both proving the keyword reached the
    subclass through ``NDConfigCollection.get_diff_config``.
    """
    existing = _ConformingModel(name="a")
    collection = NDConfigCollection(model_class=_ConformingModel, items=[existing])
    proposed = _ConformingModel(name="a")

    assert collection.get_diff_config(proposed, exclude_unset=True, allow_superset=True) == "no_diff"
    assert collection.get_diff_config(proposed, exclude_unset=True, allow_superset=False) == "changed"


def test_get_diff_config_defaults_allow_superset_to_false():
    """Omitting ``allow_superset`` forwards ``False`` to the override."""
    existing = _ConformingModel(name="a")
    collection = NDConfigCollection(model_class=_ConformingModel, items=[existing])
    proposed = _ConformingModel(name="a")

    assert collection.get_diff_config(proposed) == "changed"


def test_get_diff_config_returns_new_when_item_absent():
    """An item with no existing match short-circuits to "new" before ``get_diff``."""
    collection = NDConfigCollection(model_class=_ConformingModel, items=[_ConformingModel(name="a")])
    proposed = _ConformingModel(name="b")

    assert collection.get_diff_config(proposed, allow_superset=True) == "new"


def test_get_diff_config_nonconforming_override_raises_typeerror():
    """A non-conforming override surfaces the incompatibility loudly.

    ``get_diff_config`` forwards ``allow_superset``; the old-signature override
    rejects it and the ``TypeError`` propagates. The collection must not hide the
    mismatch by catching ``TypeError`` or inspecting the signature.
    """
    existing = _NonConformingModel(name="a")
    collection = NDConfigCollection(model_class=_NonConformingModel, items=[existing])
    proposed = _NonConformingModel(name="a")

    with pytest.raises(TypeError, match="allow_superset"):
        collection.get_diff_config(proposed, exclude_unset=True, allow_superset=True)
