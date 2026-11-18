# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetFlow public enum replay versus live native-template wire identifiers."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    NetflowRecordModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import (
    ManageEbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

FAMILIES = (
    pytest.param(FabricIbgpModel, ManageIbgpFabricOrchestrator, id="ibgp"),
    pytest.param(FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator, id="ai-ibgp"),
    pytest.param(FabricEbgpModel, ManageEbgpFabricOrchestrator, id="ebgp"),
    pytest.param(FabricAiEbgpVxlanModel, ManageAiEbgpVxlanFabricOrchestrator, id="ai-ebgp"),
    pytest.param(FabricExternalConnectivityModel, ManageExternalFabricOrchestrator, id="external"),
)
TEMPLATE_NAMES = (
    ("netflowIpv4Record", "netflow_ipv4_record"),
    ("netflowLayer2Record", "netflow_l2_record"),
)


def _config(template: str) -> dict:
    return {
        "fabric_name": "fabric1",
        "management": {
            "bgp_asn": "65001",
            "netflow_settings": {
                "netflow": True,
                "netflow_record_collection": [{"record_name": "record1", "record_template": template}],
            },
        },
    }


def _preflight(model, orchestrator_class, version: str) -> None:
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    orchestrator_class(rest_send=rest).preflight([model])


def _record(data: dict, wire: bool = True) -> dict:
    return data["management"]["netflowSettings" if wire else "netflow_settings"]["netflowRecordCollection" if wire else "netflow_record_collection"][0]


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize(("public_name", "native_name"), TEMPLATE_NAMES)
def test_full_fabric_native_payload_and_public_gathered_replay(model_class, orchestrator_class, version, public_name, native_name):
    """Known aliases serialize for the live API and native GETs replay as public input."""
    config = _config(public_name)
    if model_class in (FabricEbgpModel, FabricAiEbgpVxlanModel):
        config["management"]["bgp_asn_range"] = "3001-4000"
    proposed = model_class.from_config(config, context={"state": "merged"})
    _preflight(proposed, orchestrator_class, version)
    stored = proposed.management.netflow_settings.netflow_record_collection[0]
    assert stored.record_template == public_name
    payload = proposed.to_payload()
    assert _record(payload)["recordTemplate"] == native_name
    assert _record(proposed.to_diff_dict())["recordTemplate"] == native_name
    assert stored.record_template == public_name

    existing = model_class.from_response(deepcopy(payload))
    native_stored = existing.management.netflow_settings.netflow_record_collection[0]
    assert native_stored.record_template == native_name
    gathered = existing.to_gathered_config()
    assert _record(gathered, wire=False)["record_template"] == public_name
    assert _record(existing.to_config(), wire=False)["record_template"] == public_name
    validation = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate({"state": "merged", "config": [gathered]})
    assert validation.error_messages == []
    assert not validation.unsupported_parameters
    replay = model_class.from_config(gathered, context={"state": "merged"})
    _preflight(replay, orchestrator_class, version)
    assert _record(replay.to_payload())["recordTemplate"] == native_name
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FAMILIES)
@pytest.mark.parametrize(("public_name", "native_name"), TEMPLATE_NAMES)
def test_nd_4_2_native_user_spelling_is_not_normalized_before_enum_preflight(model_class, orchestrator_class, public_name, native_name):
    """Wire serialization must not relax the older release's public-input enum."""
    config = _config(native_name)
    if model_class in (FabricEbgpModel, FabricAiEbgpVxlanModel):
        config["management"]["bgp_asn_range"] = "3001-4000"
    model = model_class.from_config(config)
    # Even exporting before preflight must leave the original supplied value intact.
    assert _record(model.to_payload())["recordTemplate"] == native_name
    assert model.management.netflow_settings.netflow_record_collection[0].record_template == native_name
    with pytest.raises(RuntimeError, match="record_template must be one of"):
        _preflight(model, orchestrator_class, "4.2.1")


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FAMILIES)
@pytest.mark.parametrize("custom", ("myCustomRecord", "custom_record", "netflowIpv6Record"))
def test_nd_4_3_custom_record_template_names_are_unchanged(model_class, orchestrator_class, custom):
    """Unknown 4.3 string names retain exact spelling across all public/wire surfaces."""
    config = _config(custom)
    if model_class in (FabricEbgpModel, FabricAiEbgpVxlanModel):
        config["management"]["bgp_asn_range"] = "3001-4000"
    model = model_class.from_config(config)
    _preflight(model, orchestrator_class, "4.3.1")
    assert _record(model.to_payload())["recordTemplate"] == custom
    assert _record(model.to_diff_dict())["recordTemplate"] == custom
    assert _record(model.to_config(), wire=False)["record_template"] == custom
    assert _record(model.to_gathered_config(), wire=False)["record_template"] == custom
    parsed = model_class.from_response(model.to_payload())
    assert _record(parsed.to_gathered_config(), wire=False)["record_template"] == custom


@pytest.mark.parametrize(("public_name", "native_name"), TEMPLATE_NAMES)
@pytest.mark.parametrize("stored_wire_name", (False, True))
@pytest.mark.parametrize("mode", (None, "payload", "config"))
def test_nested_record_serialization_context_is_explicit(public_name, native_name, stored_wire_name, mode):
    """Default-context comparison uses the same native spelling as outbound payloads."""
    record = NetflowRecordModel(
        record_name="record1",
        record_template=native_name if stored_wire_name else public_name,
    )
    context = {"mode": mode} if mode else None
    assert record.model_dump(context=context)["record_template"] == (public_name if mode == "config" else native_name)
