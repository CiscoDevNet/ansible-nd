# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `NDBaseModel.get_diff` with controller-generated keys on models held inside containers (issue #531).

ND echoes server-populated keys (e.g. `controllerGeneratedId`) on child objects that the models retain via
`extra="allow"`. The forward `issubset` pass matches list elements bidirectionally, so an existing-side extra on a
list-contained model made an otherwise identical resource classify as changed on every run. `get_diff` must strip
`model_extra` keys from both dumps at every nesting level (nested models, list/tuple items, dict values) before the
forward compare: extras are never user intent, and `other` is not always user config (`NDOutput` diffs two controller
reads to derive `changed`, and `prepare_for_replacement` copies preserved extras onto the candidate).
"""

# pylint: disable=line-too-long

from __future__ import annotations

from typing import ClassVar, Literal

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import NetflowSettingsModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

EXPORTER_RESPONSE = {
    "exporterName": "COLLECTOR1",
    "exporterIp": "192.0.2.50",
    "vrf": "management",
    "sourceInterfaceName": "mgmt0",
    "udpPort": 2055,
}

EXPORTER_CONFIG = {
    "exporter_name": "COLLECTOR1",
    "exporter_ip": "192.0.2.50",
    "vrf": "management",
    "source_interface_name": "mgmt0",
    "udp_port": 2055,
}


def netflow_response(exporter_extra: dict | None = None) -> dict:
    """Build an ND-shaped `netflowSettings` response whose single exporter carries the given extra wire keys."""
    exporter = dict(EXPORTER_RESPONSE)
    exporter.update(exporter_extra or {})
    return {"netflow": True, "netflowExporterCollection": [exporter], "netflowRecordCollection": [], "netflowMonitorCollection": []}


def netflow_config(exporter_overrides: dict | None = None, drop: str | None = None) -> dict:
    """Build an Ansible-shaped `netflow_settings` config whose single exporter applies the given overrides, optionally dropping a key."""
    exporter = dict(EXPORTER_CONFIG)
    exporter.update(exporter_overrides or {})
    if drop is not None:
        exporter.pop(drop)
    return {"netflow": True, "netflow_exporter_collection": [exporter]}


@pytest.mark.parametrize("exclude_unset", [False, True])
def test_base_model_list_extras_00100(exclude_unset: bool) -> None:
    """
    # Summary

    An existing-side controller-generated key on a list-contained model must not classify an otherwise identical
    resource as changed (issue #531), on both the replaced/overridden and the merged paths.

    ## Test

    - An existing `NetflowSettingsModel` built from a response whose exporter carries `controllerGeneratedId`.
    - A proposed model built from config restating every user-settable exporter field identically.
    - `get_diff(proposed, exclude_unset=...)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = NetflowSettingsModel.from_response(netflow_response({"controllerGeneratedId": "exporter-74"}))
    proposed = NetflowSettingsModel.from_config(netflow_config())
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is True


@pytest.mark.parametrize("exclude_unset", [False, True])
def test_base_model_list_extras_00110(exclude_unset: bool) -> None:
    """
    # Summary

    Control: a genuine user-managed value change inside a list item is still detected once existing-side extras are
    stripped.

    ## Test

    - The existing model from `test_base_model_list_extras_00100` (exporter `udpPort` 2055 plus the controller key).
    - A proposed model whose exporter carries `udp_port` 9995.
    - `get_diff(proposed, exclude_unset=...)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = NetflowSettingsModel.from_response(netflow_response({"controllerGeneratedId": "exporter-74"}))
    proposed = NetflowSettingsModel.from_config(netflow_config({"udp_port": 9995}))
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is False


def test_base_model_list_extras_00120() -> None:
    """
    # Summary

    Control: a user-managed field removed from a list item is still a difference on the replaced/overridden path.
    Only undeclared extras are stripped; declared fields the proposed item omits keep failing the element match.

    ## Test

    - The existing model from `test_base_model_list_extras_00100` (exporter carries `udpPort`).
    - A proposed model whose exporter omits `udp_port`.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = NetflowSettingsModel.from_response(netflow_response({"controllerGeneratedId": "exporter-74"}))
    proposed = NetflowSettingsModel.from_config(netflow_config(drop="udp_port"))
    assert existing.get_diff(proposed, exclude_unset=False) is False


@pytest.mark.parametrize("exclude_unset", [False, True])
def test_base_model_list_extras_00130(exclude_unset: bool) -> None:
    """
    # Summary

    The strip is symmetric: `get_diff` is also used to compare two controller reads (`NDOutput` derives `changed` from
    `before` vs `after`), so a list-item extra present on the `other` side only must not count as a difference either.

    ## Test

    - An existing model built from a response with no extras.
    - A second model built from the same response plus `controllerGeneratedId` on the exporter, passed as `other`.
    - `get_diff(other, exclude_unset=...)` is `True` (no difference) in both directions.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    plain = NetflowSettingsModel.from_response(netflow_response())
    with_extra = NetflowSettingsModel.from_response(netflow_response({"controllerGeneratedId": "exporter-74"}))
    assert plain.get_diff(with_extra, exclude_unset=exclude_unset) is True
    assert with_extra.get_diff(plain, exclude_unset=exclude_unset) is True


class _ChildModel(NDNestedModel):
    """Minimal nested model that retains response extras, like the production NetFlow child models."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = Field(alias="name")
    value: int | None = Field(default=None, alias="value")


class _ContainerModel(NDBaseModel):
    """Minimal model holding `_ChildModel` instances in every container shape issue #531 names, plus a nested model."""

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = Field(alias="name")
    items: list[_ChildModel] = Field(default_factory=list, alias="items")
    pair: tuple[_ChildModel, ...] = Field(default=(), alias="pair")
    by_key: dict[str, _ChildModel] = Field(default_factory=dict, alias="byKey")
    child: _ChildModel | None = Field(default=None, alias="child")


CONTAINER_CONFIG = {
    "name": "c1",
    "items": [{"name": "a", "value": 1}, {"name": "b", "value": 2}],
    "pair": [{"name": "p", "value": 3}],
    "by_key": {"k": {"name": "k", "value": 4}},
    "child": {"name": "n", "value": 5},
}


def container_response(extra: dict) -> dict:
    """Build a wire-shaped `_ContainerModel` response with `extra` merged into every child object and the top level."""
    return {
        "name": "c1",
        "items": [{"name": "a", "value": 1, **extra}, {"name": "b", "value": 2, **extra}],
        "pair": [{"name": "p", "value": 3, **extra}],
        "byKey": {"k": {"name": "k", "value": 4, **extra}},
        "child": {"name": "n", "value": 5, **extra},
        **extra,
    }


@pytest.mark.parametrize("exclude_unset", [False, True])
def test_base_model_list_extras_00200(exclude_unset: bool) -> None:
    """
    # Summary

    Existing-side extras are stripped at every nesting level: top level, nested model, list items, tuple items, and
    dict values, preserving container shape and order.

    ## Test

    - An existing `_ContainerModel` built from a response carrying `serverId` on the top level and every child.
    - A proposed model built from config restating every declared field identically.
    - `get_diff(proposed, exclude_unset=...)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = _ContainerModel.from_response(container_response({"serverId": "s-1"}))
    proposed = _ContainerModel.from_config(CONTAINER_CONFIG)
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is True


@pytest.mark.parametrize("path", ["items", "pair", "by_key", "child"])
def test_base_model_list_extras_00210(path: str) -> None:
    """
    # Summary

    Control: a genuine value change inside each container shape is still detected after the existing-side strip.

    ## Test

    - The existing model from `test_base_model_list_extras_00200`.
    - A proposed model with one child's `value` changed, in the container named by `path`.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = _ContainerModel.from_response(container_response({"serverId": "s-1"}))
    config = {
        "name": "c1",
        "items": [{"name": "a", "value": 1}, {"name": "b", "value": 2}],
        "pair": [{"name": "p", "value": 3}],
        "by_key": {"k": {"name": "k", "value": 4}},
        "child": {"name": "n", "value": 5},
    }
    if path == "items":
        config["items"][1]["value"] = 99
    elif path == "pair":
        config["pair"][0]["value"] = 99
    elif path == "by_key":
        config["by_key"]["k"]["value"] = 99
    else:
        config["child"]["value"] = 99
    proposed = _ContainerModel.from_config(config)
    assert existing.get_diff(proposed, exclude_unset=False) is False
