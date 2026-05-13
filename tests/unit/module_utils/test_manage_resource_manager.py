# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for nd_manage_resource_manager module utilities.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import logging

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_resources import (
    EpManageFabricResourcesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources import (
    NDResourceManagerModule,
    ResourceManagerDiffEngine,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_response_model import (
    ResourceManagerResponse,
)

LOG = logging.getLogger("nd.tests.resource_manager")


def _config(**overrides):
    """Build a valid merged config model with optional overrides."""
    data = {
        "entity_name": "loopback0",
        "pool_type": "ID",
        "pool_name": "LOOPBACK_ID",
        "scope_type": "device",
        "switches": ["SER1"],
        "resource": "10",
    }
    data.update(overrides)
    return ResourceManagerConfigModel.model_validate(data, context={"state": "merged"})


def _response(**overrides):
    """Build a resource response model with optional overrides."""
    data = {
        "resourceId": 101,
        "entityName": "loopback0",
        "poolName": "LOOPBACK_ID",
        "resourceValue": "10",
        "scopeDetails": {
            "scopeType": "device",
            "switchId": "SER1",
            "switchIp": "192.0.2.10",
        },
    }
    data.update(overrides)
    return ResourceManagerResponse.model_validate(data)


def _resource_manager():
    """Create a lightweight NDResourceManagerModule instance for helper tests."""
    module = object.__new__(NDResourceManagerModule)
    module.fabric = "fabric-1"
    module.log = LOG
    return module


def test_resource_manager_config_rejects_unknown_id_pool_name():
    """Unknown ID pool names remain invalid for modifying states."""
    with pytest.raises(Exception, match="pool_name 'WRONG_POOL' is not valid"):
        ResourceManagerConfigModel.model_validate(
            {
                "entity_name": "bad",
                "pool_type": "ID",
                "pool_name": "WRONG_POOL",
                "scope_type": "fabric",
                "resource": "10",
            },
            context={"state": "merged"},
        )


def test_resource_manager_config_allows_partial_gathered_filter():
    """Gathered filters may provide partial criteria without switches."""
    model = ResourceManagerConfigModel.model_validate({"scope_type": "device"}, context={"state": "gathered"})
    assert model.scope_type == "device"
    assert model.switches is None


@pytest.mark.parametrize(
    ("config", "expected_message"),
    [
        ([{"entity_name": "l3_vni_fabric"}], "Mandatory parameter 'scope_type' missing"),
        ([{"scope_type": "fabric"}], "Mandatory parameter 'pool_type' missing"),
        ([{"entity_name": "l3_vni_fabric", "pool_type": "ID", "scope_type": "fabric"}], "Mandatory parameter 'pool_name' missing"),
        ([{"pool_type": "ID", "pool_name": "VPC_ID", "scope_type": "fabric"}], "Mandatory parameter 'entity_name' missing"),
        (
            [{"entity_name": "SER1~SER2", "pool_type": "ID", "pool_name": "VPC_ID", "scope_type": "device_pair"}],
            "switches : Required parameter not found",
        ),
    ],
)
def test_resource_manager_validate_input_preserves_legacy_missing_param_messages(config, expected_message):
    """Missing-field validation keeps integration-compatible error messages."""
    module = _resource_manager()
    module.state = "deleted"
    module.config = config

    with pytest.raises(ValueError, match=expected_message):
        module._validate_input()  # pylint: disable=protected-access


def test_resource_manager_validate_configs_rejects_duplicate_entries():
    """Duplicate desired resources are rejected before diffing."""
    data = {
        "entity_name": "loopback0",
        "pool_type": "ID",
        "pool_name": "LOOPBACK_ID",
        "scope_type": "device",
        "switches": ["SER1"],
        "resource": "10",
    }
    with pytest.raises(ValueError, match="Duplicate config entries"):
        ResourceManagerDiffEngine.validate_configs([data, data], "merged", log=LOG)


def test_resource_manager_diff_detects_idempotent_resource():
    """Diffing matches existing resources by normalized identity and switch ID."""
    changes = ResourceManagerDiffEngine.compute_changes([_config()], [_response()], log=LOG)

    assert len(changes["idempotent"]) == 1
    assert changes["to_add"] == []
    assert changes["to_update"] == []


def test_resource_manager_diff_accepts_raw_dict_existing_resource():
    """Diffing also handles raw dict resources retained after response parsing failures."""
    raw_resource = {
        "resourceId": 101,
        "entityName": "loopback0",
        "poolName": "LOOPBACK_ID",
        "resourceValue": "10",
        "scopeDetails": {
            "scopeType": "device",
            "switchId": "SER1",
        },
    }

    changes = ResourceManagerDiffEngine.compute_changes([_config()], [raw_resource], log=LOG)

    assert len(changes["idempotent"]) == 1
    assert changes["to_add"] == []


def test_resource_manager_builds_link_create_payload():
    """Payload building fills all link scopeDetails fields from entity_name."""
    module = _resource_manager()
    cfg = _config(
        entity_name="SER1~Ethernet1/1~SER2~Ethernet1/2",
        pool_type="SUBNET",
        pool_name="SUBNET",
        scope_type="link",
        resource="10.0.0.0/30",
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["entityName"] == "SER1~Ethernet1/1~SER2~Ethernet1/2"
    assert payload["resourceValue"] == "10.0.0.0/30"
    assert payload["scopeDetails"]["scopeType"] == "link"
    assert payload["scopeDetails"]["srcSwitchId"] == "SER1"
    assert payload["scopeDetails"]["dstSwitchId"] == "SER2"
    assert payload["scopeDetails"]["srcInterfaceName"] == "Ethernet1/1"
    assert payload["scopeDetails"]["dstInterfaceName"] == "Ethernet1/2"


def test_resource_manager_gathered_filter_matches_switch_id_and_translates_switch_ip():
    """Gathered switch filters match switchId while output keeps switchIp."""
    module = _resource_manager()
    module.config = [{"pool_name": "LOOPBACK_ID", "switches": ["SER1"]}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(),
        _response(
            resourceId=102,
            entityName="loopback1",
            resourceValue="11",
            scopeDetails={
                "scopeType": "device",
                "switchId": "SER2",
                "switchIp": "192.0.2.11",
            },
        ),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access

    assert gathered == [
        {
            "entity_name": "loopback0",
            "pool_type": "ID",
            "pool_name": "LOOPBACK_ID",
            "scope_type": "device",
            "resource": "10",
            "switches": ["192.0.2.10"],
        }
    ]


def test_manage_fabric_resources_get_endpoint_path_and_class_name():
    """Resources GET endpoint has the correct class name, verb, and query path."""
    endpoint = EpManageFabricResourcesGet(fabric_name="fabric-1")
    endpoint.endpoint_params.pool_name = "LOOPBACK_ID"

    assert endpoint.class_name == "EpManageFabricResourcesGet"
    assert endpoint.verb == HttpVerbEnum.GET
    assert endpoint.path == "/api/v1/manage/fabrics/fabric-1/resources?poolName=LOOPBACK_ID"
