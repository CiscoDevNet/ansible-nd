# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Campus NX-API inactive HTTP comparison without changing managed payloads."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import FabricCampusIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel


def _config(**management):
    return {"fabric_name": "campus1", "management": {"bgp_asn": "65001", **management}}


def _existing(nxapi=False, **management):
    return FabricCampusIbgpVxlanModel.from_response(
        {"name": "campus1", "management": {"type": "vxlanCampus", "bgpAsn": "65001", "nxapi": nxapi, **management}}
    )


def _snapshot(item):
    if isinstance(item, NDBaseModel):
        return (
            id(item),
            deepcopy(item.model_fields_set),
            deepcopy(item.__pydantic_private__),
            deepcopy(item.model_extra),
            item.to_payload(),
            item.to_config(),
            item.to_gathered_config(),
            item.to_diff_dict(),
            {name: _snapshot(getattr(item, name)) for name in type(item).model_fields},
        )
    if isinstance(item, list):
        return [_snapshot(value) for value in item]
    return deepcopy(item)


@pytest.mark.parametrize("exclude_unset", (False, True))
@pytest.mark.parametrize("http", (False, True))
def test_disabled_nxapi_ignores_only_inactive_http_value(exclude_unset, http):
    """An omitted controller HTTP field defaults true but cannot cause repeated writes while disabled."""
    existing = _existing()
    proposed = FabricCampusIbgpVxlanModel.from_config(_config(nxapi=False, nxapi_http=http))
    assert existing.management.nxapi_http is True
    assert "nxapi_http" not in existing.management.model_fields_set
    before_existing, before_proposed = _snapshot(existing), _snapshot(proposed)
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is True
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is True
    assert _snapshot(existing) == before_existing
    assert _snapshot(proposed) == before_proposed
    assert proposed.to_payload()["management"]["nxapiHttp"] is http


@pytest.mark.parametrize("nxapi", (False, True))
def test_merged_omitted_parent_uses_existing_nxapi_value(nxapi):
    existing = _existing(nxapi=nxapi, nxapiHttp=True)
    proposed = FabricCampusIbgpVxlanModel.from_config(_config(nxapi_http=False))
    assert "nxapi" not in proposed.management.model_fields_set
    assert proposed.management.nxapi is True
    assert existing.get_diff(proposed, exclude_unset=True) is (not nxapi)


@pytest.mark.parametrize("exclude_unset", (False, True))
@pytest.mark.parametrize(("existing_http", "proposed_http"), ((True, False), (False, True)))
def test_enabled_nxapi_detects_http_only_changes(exclude_unset, existing_http, proposed_http):
    existing = _existing(nxapi=True, nxapiHttp=existing_http)
    proposed = FabricCampusIbgpVxlanModel.from_config(_config(nxapi=True, nxapi_http=proposed_http))
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is False


@pytest.mark.parametrize("exclude_unset", (False, True))
@pytest.mark.parametrize(("old", "new"), ((False, True), (True, False)))
def test_nxapi_parent_transitions_remain_changes(exclude_unset, old, new):
    existing = _existing(nxapi=old)
    proposed = FabricCampusIbgpVxlanModel.from_config(_config(nxapi=new, nxapi_http=False))
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is False


def test_exact_omitted_parent_resets_to_enabled_default_while_merge_preserves_disabled():
    existing = _existing()
    proposed = FabricCampusIbgpVxlanModel.from_config(_config())
    assert existing.get_diff(proposed, exclude_unset=True) is True
    assert existing.get_diff(proposed, exclude_unset=False) is False


@pytest.mark.parametrize("exclude_unset", (False, True))
def test_disabled_nxapi_still_detects_unrelated_management_changes(exclude_unset):
    existing = _existing()
    proposed = FabricCampusIbgpVxlanModel.from_config(_config(nxapi=False, performance_monitoring=True))
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is False


@pytest.mark.parametrize("exclude_unset", (False, True))
def test_comparison_retains_type_error_and_absent_management_behavior(exclude_unset):
    existing = _existing()
    for other in (object(), FabricIbgpModel.from_config(_config())):
        with pytest.raises(TypeError, match="Cannot diff"):
            existing.get_diff(other, exclude_unset=exclude_unset)
    missing = FabricCampusIbgpVxlanModel.from_config({"fabric_name": "campus1"})
    assert missing.get_diff(missing, exclude_unset=exclude_unset) is True
