# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import (
    filter_gathered_response,
    validate_gathered_filters,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user.local_user import LocalUserModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.local_user import LocalUserOrchestrator

API_USER = {
    "loginID": "user1",
    "email": "user1@example.com",
    "passwordPolicy": {
        "reuseLimitation": 0,
        "timeIntervalLimitation": 0,
    },
    "rbac": {
        "domains": {
            "all": {
                "roles": ["observer", "support-engineer"],
            }
        }
    },
    "xLaunch": False,
}


def test_local_user_opts_in_to_gathered_filtering():
    assert LocalUserModel.supports_gathered_filtering is True


def test_local_user_does_not_opt_in_to_lucene_filtering():
    assert LocalUserOrchestrator.supports_gathered_server_filtering is False


def test_argument_spec_allows_gathered_login_id_filter():
    spec = LocalUserModel.get_argument_spec()

    assert spec["config"]["required"] is False
    assert spec["config"]["options"]["login_id"].get("required", False) is False
    assert "gathered" in spec["state"]["choices"]


def test_password_is_excluded_from_config_but_included_in_payload():
    model = LocalUserModel.from_config(
        {
            "login_id": "user1",
            "user_password": "Password1!",
        }
    )

    assert "user_password" not in model.to_config()
    assert model.to_payload()["password"] == "Password1!"


@pytest.mark.parametrize(
    "filter_item",
    [
        {"user_password": "Password1!"},
        {"reuse_limitation": 0},
        {"remote_user_authorization": False},
        {"security_domains": [{"name": "all"}]},
    ],
)
def test_unsupported_gathered_filters_are_rejected(filter_item):
    with pytest.raises(ValueError, match="unsupported properties"):
        validate_gathered_filters(
            filters=[filter_item],
            normalize_filter=LocalUserModel.normalize_gathered_filter,
            supported_properties=LocalUserModel.gathered_filter_properties,
        )


def test_ansible_injected_null_option_is_not_treated_as_a_filter():
    filter_item = {
        "login_id": "user1",
        "user_password": None,
    }

    # Null values are ignored by property validation — no error raised
    validate_gathered_filters(
        filters=[filter_item],
        normalize_filter=LocalUserModel.normalize_gathered_filter,
        supported_properties=LocalUserModel.gathered_filter_properties,
    )


def test_api_deserialization_does_not_mutate_response():
    response = deepcopy(API_USER)
    original = deepcopy(response)

    LocalUserModel.from_response(response)

    assert response == original


@pytest.mark.parametrize(
    ("login_id", "expected"),
    [
        ("user1", 1),
        ("missing-user", 0),
    ],
)
def test_login_id_gathered_filter(login_id, expected):
    result = filter_gathered_response(
        response_data=[deepcopy(API_USER)],
        filters=[{"login_id": login_id}],
        model_class=LocalUserModel,
        normalize_filter=LocalUserModel.normalize_gathered_filter,
    )

    assert len(result) == expected
