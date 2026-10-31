# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Concrete External VRF defaults, sparse intent and serialization contracts."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.enums import VrfType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import ExternalVrfDataModel, VrfDataModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
@pytest.mark.parametrize("wire_keys", [False, True])
def test_external_schema_requires_fabric_identity(vrf_type, wire_keys):
    schema = ExternalVrfDataModel.model_json_schema(by_alias=wire_keys)
    fabric_key = "fabricName" if wire_keys else "fabric_name"
    assert schema["properties"][fabric_key]["type"] == "string"
    assert fabric_key in schema["required"]

    config = {"vrfName": "BLUE", "vrfType": vrf_type} if wire_keys else {"vrf_name": "BLUE", "vrf_type": vrf_type}
    with pytest.raises(ValidationError, match="fabricName"):
        VrfDataModel.from_config(config)
    config[fabric_key] = "EXT"
    assert VrfDataModel.from_config(config).to_payload()["fabricName"] == "EXT"


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
@pytest.mark.parametrize("wire_keys", [False, True])
def test_external_factories_select_the_same_concrete_type_and_preserve_omission(vrf_type, wire_keys):
    config = {"fabricName": "EXT", "vrfName": "BLUE", "vrfType": vrf_type} if wire_keys else {"fabric_name": "EXT", "vrf_name": "BLUE", "vrf_type": vrf_type}
    proposed = VrfDataModel.from_config(config)
    observed = VrfDataModel.from_response({"fabricName": "EXT", "vrfName": "BLUE", "vrfType": vrf_type, "vrfStatus": "notApplicable"})
    for model in (proposed, observed):
        assert isinstance(model, ExternalVrfDataModel)
        assert model.description == ""
        assert "description" not in model.model_fields_set
        assert "description" not in model.to_config()
        assert "description" not in model.to_payload()
        assert model.to_gathered_config() == {"vrf_name": "BLUE"}
        assert model.to_diff_dict() == NDBaseModel.to_diff_dict(model)
        assert model.to_diff_dict()["description"] == ""
        assert "description" not in model.to_diff_dict(exclude_unset=True)
    for exclude_unset in (False, True):
        assert observed.get_diff(proposed, exclude_unset=exclude_unset)


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
@pytest.mark.parametrize("description", [{}, {"description": None}, {"description": ""}, {"description": "Configured"}])
def test_external_read_defaults_do_not_rewrite_input_or_gathered_presence(vrf_type, description):
    raw = {"fabricName": "EXT", "vrfName": "BLUE", "vrfType": vrf_type, **description}
    original = deepcopy(raw)
    collection = NDConfigCollection.from_api_response([raw], VrfDataModel)
    model = collection.get(("BLUE", "EXT"))
    assert raw == original
    assert isinstance(model, ExternalVrfDataModel)
    assert model.description == (description.get("description") or "")
    assert ("description" in model.model_fields_set) is (description.get("description") is not None)
    assert model.to_payload().get("description") == description.get("description")
    assert model.to_gathered_config().get("vrf_description") == description.get("description")


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
def test_external_model_defaults_preserve_sparse_intent_and_actionable_clears(vrf_type):
    identity = {"fabric_name": "EXT", "vrf_name": "BLUE", "vrf_type": vrf_type}
    current = VrfDataModel.from_response({"fabricName": "EXT", "vrfName": "BLUE", "vrfType": vrf_type, "description": "KEEP"})
    sparse = VrfDataModel.from_config(identity)
    clear = VrfDataModel.from_config({**identity, "description": ""})
    assert current.get_diff(sparse, exclude_unset=True)
    assert current.model_copy(deep=True).merge(sparse).description == "KEEP"
    assert not current.get_diff(sparse, exclude_unset=False)
    assert "description" in clear.model_fields_set
    assert clear.to_payload()["description"] == ""
    for exclude_unset in (False, True):
        assert not current.get_diff(clear, exclude_unset=exclude_unset)
    assert current.model_copy(deep=True).merge(clear).to_payload()["description"] == ""
    observed_empty = VrfDataModel.from_response({"fabricName": "EXT", "vrfName": "BLUE", "vrfType": vrf_type})
    assert observed_empty.get_diff(clear, exclude_unset=True)
    assert observed_empty.get_diff(sparse, exclude_unset=False)


@pytest.mark.parametrize("vrf_type", [value for value in VrfType.choices() if value not in ("externalConnectivity", "vxlanExternal")])
def test_non_external_factories_retain_the_existing_vrf_model(vrf_type):
    identity = {"fabricName": "FAB", "vrfName": "BLUE", "vrfType": vrf_type}
    for factory in (VrfDataModel.from_config, VrfDataModel.from_response):
        model = factory(identity)
        assert isinstance(model, VrfDataModel)
        assert not isinstance(model, ExternalVrfDataModel)
        assert model.description is None
        assert "description" not in model.to_diff_dict()
    with pytest.raises(ValidationError, match="vrfType"):
        ExternalVrfDataModel.from_config(identity)


@pytest.mark.parametrize("description", ["x" * 256, 42, [], {}])
def test_external_description_retains_schema_constraints(description):
    with pytest.raises(ValidationError, match="description"):
        VrfDataModel.from_config({"fabric_name": "EXT", "vrf_name": "BLUE", "vrf_type": "externalConnectivity", "description": description})


def test_external_null_is_read_normalization_not_a_nullable_wire_field():
    raw = {"fabricName": "EXT", "vrfName": "BLUE", "vrfType": "externalConnectivity", "description": None}
    assert ExternalVrfDataModel.from_response(raw).description == ""
    with pytest.raises(ValidationError, match="description"):
        ExternalVrfDataModel.model_validate(raw)
