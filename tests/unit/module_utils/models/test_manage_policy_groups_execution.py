# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Private execution identities must preserve public policy-group semantics."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import PolicyGroupCreate
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_execution import PolicyGroupExecution
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection

GROUP_ID = "POLICY-GROUP-101"


def config(**overrides):
    return {"name": "feature_enable", "description": "group intent", "switch_ids": ["SERIAL_A"], "template_inputs": {"featureName": "lacp"}, **overrides}


def test_generated_policy_id_does_not_invalidate_create_collection_key():
    model = PolicyGroupExecution.from_config(config())
    original_key = model.get_identifier_value()
    collection = NDConfigCollection(model_class=PolicyGroupExecution, items=[model])

    model.policy_id = GROUP_ID

    assert original_key == ("create", "group intent", "feature_enable")
    assert model.get_identifier_value() == original_key
    assert collection.get(original_key) is model
    assert model.policy_id == GROUP_ID


@pytest.mark.parametrize("factory", ["config", "response"])
def test_existing_controller_id_is_the_execution_identity(factory):
    if factory == "config":
        model = PolicyGroupExecution.from_config(config(policy_id=GROUP_ID))
    else:
        model = PolicyGroupExecution.from_response(
            {"policyId": GROUP_ID, "description": "group intent", "templateName": "feature_enable", "switchIds": ["SERIAL_A"]}
        )
    assert model.get_identifier_value() == ("policy_id", GROUP_ID)


def test_deepcopy_preserves_identity_and_isolates_configuration():
    model = PolicyGroupExecution.from_config(config(policy_id=GROUP_ID))
    copied = deepcopy(model)
    copied.template_inputs["featureName"] = "lldp"

    assert copied.get_identifier_value() == model.get_identifier_value()
    assert model.template_inputs == {"featureName": "lacp"}
    assert copied.template_inputs == {"featureName": "lldp"}


def test_merge_retains_resolved_identity_and_omitted_existing_fields():
    model = PolicyGroupExecution.from_config(config(policy_id=GROUP_ID, priority=725))
    sparse = PolicyGroupExecution.from_config({"name": "feature_enable", "policy_id": GROUP_ID, "priority": 600})

    model.merge(sparse)

    assert model.get_identifier_value() == ("policy_id", GROUP_ID)
    assert model.priority == 600
    assert model.description == "group intent"
    assert model.switch_ids == ["SERIAL_A"]
    assert model.template_inputs == {"featureName": "lacp"}


@pytest.mark.parametrize(
    "description,template_name", [("  group intent  ", " feature_enable "), ("", "feature_enable"), (" group intent", "feature_enable  ")]
)
def test_create_identity_uses_public_string_normalization(description, template_name):
    model = PolicyGroupExecution.from_config(config(name=template_name, description=description))
    public = PolicyGroupCreate.from_config(config(name=template_name, description=description))

    assert model.description == public.description
    assert model.template_name == public.template_name
    assert model.get_identifier_value() == ("create", public.description, public.template_name)


@pytest.mark.parametrize("description", [None, ""])
def test_existing_anonymous_group_keeps_explicit_id_identity(description):
    model = PolicyGroupExecution.from_config(config(policy_id=GROUP_ID, description=description))
    assert model.get_identifier_value() == ("policy_id", GROUP_ID)


def test_null_description_without_id_preserves_identifier_failure():
    model = PolicyGroupExecution.from_config(config(description=None))
    with pytest.raises(ValueError, match="Single identifier field 'execution_key' is None"):
        model.get_identifier_value()


@pytest.mark.parametrize("with_id", [False, True])
def test_execution_field_is_excluded_from_all_public_and_payload_serializations(with_id):
    values = config(**({"policy_id": GROUP_ID} if with_id else {}))
    model = PolicyGroupExecution.from_config(values)
    public = PolicyGroupCreate.from_config(values)

    assert model.to_payload() == public.to_payload()
    assert model.to_config() == public.to_config()
    assert model.to_diff_dict() == public.to_diff_dict()
    assert model.model_dump() == public.model_dump()
    assert model.model_dump(exclude_unset=True) == public.model_dump(exclude_unset=True)
    assert "execution_key" not in repr(model)
    assert "execution_key" not in model.model_dump_json()


def test_internal_identity_does_not_change_public_fields_set_or_defaults():
    values = {"name": "feature_enable", "description": "group intent"}
    model = PolicyGroupExecution.from_config(values)
    public = PolicyGroupCreate.from_config(values)
    public_fields = set(PolicyGroupCreate.model_fields)

    assert model.model_fields_set & public_fields == public.model_fields_set
    assert "priority" not in model.model_fields_set
    assert "switch_ids" not in model.model_fields_set
    assert "template_inputs" not in model.model_fields_set
    assert model.priority is None


def test_public_argument_spec_is_unchanged():
    assert PolicyGroupExecution.get_argument_spec() == PolicyGroupCreate.get_argument_spec()
    assert "execution_key" not in PolicyGroupExecution.get_argument_spec()["config"]["options"]


def test_private_identity_does_not_create_a_configuration_diff():
    first = PolicyGroupExecution.from_config(config(policy_id=GROUP_ID))
    second = PolicyGroupExecution.from_config(config(policy_id="POLICY-GROUP-102"))

    assert first.get_identifier_value() != second.get_identifier_value()
    assert first.get_diff(second, exclude_unset=True) is True
    assert first.get_diff(second) is True
