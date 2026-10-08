# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Association identity, wire aliases and state-aware validation."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchOnboardingModel


def test_payload_alias_and_identity_exact():
    model = SmartSwitchOnboardingModel.from_config(
        {"switch_id": "SerialA", "switch_name": "leaf1", "integration_name": "hypershield-a"}, context={"state": "replaced"}
    )
    assert model.to_payload() == {"switchId": "SerialA", "switchName": "leaf1", "integrationName": "hypershield-a"}
    assert model.get_identifier_value() == "SerialA"


def test_deleted_accepts_identifier_only():
    assert SmartSwitchOnboardingModel.from_config({"switch_id": "A"}, context={"state": "deleted"}).switch_id == "A"


@pytest.mark.parametrize("field", ["integration_name", "switch_name"])
def test_onboarding_requires_prepared_payload_fields(field):
    data = {"switch_id": "A", "switch_name": "leaf1", "integration_name": "h"}
    del data[field]
    with pytest.raises(ValueError, match=field):
        SmartSwitchOnboardingModel.from_config(data, context={"state": "replaced"})


def test_read_and_name_diff_normalization():
    existing = SmartSwitchOnboardingModel.from_response({"switchId": "A", "switchName": "old", "integrationName": "h", "connectivityStatus": "connected"})
    desired = SmartSwitchOnboardingModel.from_config({"switch_id": "A", "switch_name": "new", "integration_name": "h"}, context={"state": "replaced"})
    assert existing.get_diff(desired)
    assert not existing.get_diff(desired.model_copy(update={"integration_name": "other"}))


def test_no_identity_case_or_whitespace_normalization():
    assert SmartSwitchOnboardingModel(switch_id=" A ").switch_id == " A "
    with pytest.raises(ValueError):
        SmartSwitchOnboardingModel(switch_id=123)


def test_models_are_packaged_by_resource_family():
    from ansible_collections.cisco.nd.plugins.module_utils.models import smart_switches_onboarding

    assert hasattr(smart_switches_onboarding, "__path__")


def test_result_wrapper_aliases_and_independent_defaults():
    from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchOnboardingResultsModel

    parsed = SmartSwitchOnboardingResultsModel.model_validate(
        {"successResults": [{"name": " A ", "status": "futureStatus"}], "failureResults": [{"name": "b", "message": "refused"}]}
    )
    assert parsed.success_results[0].name == " A "
    assert parsed.success_results[0].status == "futureStatus"
    assert parsed.failure_results[0].message == "refused"
    assert parsed.model_dump(by_alias=True)["failureResults"][0]["name"] == "b"
    empty = SmartSwitchOnboardingResultsModel()
    empty.success_results.append(parsed.success_results[0])
    assert SmartSwitchOnboardingResultsModel().success_results == []
    assert empty.failure_results == []


@pytest.mark.parametrize("side", ["successResults", "failureResults"])
@pytest.mark.parametrize("invalid", [None, {}, "not-an-array", [{"name": 12}], [{"name": "a", "status": 12}], [{"name": "a", "message": []}]])
def test_result_wrapper_rejects_malformed_lists_or_entries(side, invalid):
    from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchOnboardingResultsModel

    with pytest.raises(ValueError):
        SmartSwitchOnboardingResultsModel.model_validate({side: invalid})


def test_deboard_request_has_only_exact_switch_identifiers():
    from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchDeboardRequestModel

    payload = {"smartSwitchIntegrations": [{"switchId": " A "}, {"switchId": "b"}]}
    model = SmartSwitchDeboardRequestModel.model_validate(payload)
    assert model.model_dump(by_alias=True) == payload
    with pytest.raises(ValueError):
        SmartSwitchDeboardRequestModel.model_validate({"smartSwitchIntegrations": [{"switchId": 123}]})
    with pytest.raises(ValueError):
        SmartSwitchDeboardRequestModel.model_validate({"smartSwitchIntegrations": [{"switchId": "a", "integrationName": "not-for-deboarding"}]})
