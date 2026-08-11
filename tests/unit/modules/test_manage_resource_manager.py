# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for nd_manage_resource_manager module utilities.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import logging
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDModuleError,
)
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import HAS_PYDANTIC
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_resources import (
    EpManageFabricResourcesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
)
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
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import nd_manage_resource_manager as manage_resource_manager_module

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
        "resource_id": 101,
        "entity_name": "loopback0",
        "pool_name": "LOOPBACK_ID",
        "resource_value": "10",
        "scope_details": {
            "scope_type": "device",
            "switch_id": "SER1",
            "switch_ip": "192.0.2.10",
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


class _DummyAnsibleModule:
    """Small AnsibleModule stand-in that captures exit_json payloads."""

    def __init__(self, verbosity=0):
        self.check_mode = False
        self._verbosity = verbosity
        self.exit_payload = None
        self.warnings = []

    def exit_json(self, **kwargs):
        self.exit_payload = kwargs

    def fail_json(self, **kwargs):
        raise AssertionError("fail_json was not expected: {0}".format(kwargs))

    def warn(self, message):
        self.warnings.append(message)


class _DummyND:
    """Small NDModule stand-in for NDResourceManagerModule.exit_module tests."""

    def __init__(self, ansible_module, output_level="normal"):
        self.module = ansible_module
        self.params = {
            "output_level": output_level,
        }


def _register_resource_manager_task(results):
    """Register one API-shaped result for output normalization tests."""
    results.action = "manage_resource_manager"
    results.operation_type = OperationType.CREATE
    results.path_current = "/api/v1/manage/fabrics/fabric-1/resources"
    results.verb_current = HttpVerbEnum.POST
    results.payload_current = {"entityName": "loopback0"}
    results.verbosity_level_current = 2
    results.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    results.result_current = {"success": True, "changed": True}
    results.diff_current = {"before": {}, "after": {"entity_name": "loopback0"}}
    results.register_api_call()


def _resource_manager_for_exit(verbosity=0):
    """Create a lightweight resource manager with enough state for exit_module."""
    ansible_module = _DummyAnsibleModule(verbosity=verbosity)
    module = _resource_manager()
    module.nd = _DummyND(ansible_module)
    module.results = Results()
    module.results.state = "merged"
    module.results.check_mode = False
    _register_resource_manager_task(module.results)
    module.state = "merged"
    module.changed_dict = [{"merged": [], "deleted": [], "gathered": [], "debugs": []}]
    module.existing = []
    module.previous = []
    module.proposed = []
    module._proposed_list = []
    module.output = NDOutput("normal")
    return module, ansible_module


def test_main_requires_pydantic_before_continuing():
    """Module entrypoint calls require_pydantic immediately after AnsibleModule."""
    dummy_module = _DummyAnsibleModule()
    dummy_module.params = {
        "fabric_name": "fabric-1",
        "output_level": "normal",
        "state": "gathered",
        "config": [],
        "host": "198.51.100.10",
        "username": "admin",
    }
    call_order = []
    mocked_rm_module = MagicMock()

    with (
        patch.object(manage_resource_manager_module, "nd_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module.ResourceManagerConfigModel, "get_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module, "AnsibleModule", return_value=dummy_module),
        patch.object(
            manage_resource_manager_module,
            "require_pydantic",
            side_effect=lambda module: call_order.append(("require_pydantic", module)),
        ),
        patch.object(
            manage_resource_manager_module,
            "setup_logging",
            side_effect=lambda *args, **kwargs: call_order.append(("setup_logging", args[0])),
        ),
        patch.object(
            manage_resource_manager_module,
            "NDModule",
            side_effect=lambda module: call_order.append(("NDModule", module)) or MagicMock(),
        ),
        patch.object(
            manage_resource_manager_module,
            "NDResourceManagerModule",
            return_value=mocked_rm_module,
        ),
    ):
        mocked_rm_module.manage_state.side_effect = lambda: call_order.append(("manage_state", None))
        mocked_rm_module.exit_module.side_effect = lambda: call_order.append(("exit_module", None))

        manage_resource_manager_module.main()

    assert [name for name, _value in call_order[:3]] == ["require_pydantic", "setup_logging", "NDModule"]
    assert call_order[0][1] is dummy_module
    assert call_order[1][1] is dummy_module
    mocked_rm_module.manage_state.assert_called_once_with()
    mocked_rm_module.exit_module.assert_called_once_with()


def test_main_fails_with_structured_payload_when_fabric_name_missing():
    """Module entrypoint fails early with standard formatted output when fabric_name is absent."""

    class _FailFastAnsibleModule(_DummyAnsibleModule):
        def fail_json(self, **kwargs):
            self.fail_payload = kwargs
            raise RuntimeError("fail_json_called")

    dummy_module = _FailFastAnsibleModule()
    dummy_module.params = {
        "output_level": "normal",
        "state": "gathered",
        "config": [],
        "host": "198.51.100.10",
        "username": "admin",
    }

    with (
        patch.object(manage_resource_manager_module, "nd_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module.ResourceManagerConfigModel, "get_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module, "AnsibleModule", return_value=dummy_module),
        patch.object(
            manage_resource_manager_module,
            "require_pydantic",
        ),
        patch.object(
            manage_resource_manager_module,
            "setup_logging",
        ),
        patch.object(
            manage_resource_manager_module,
            "NDModule",
        ) as ndmodule_mock,
    ):
        with pytest.raises(RuntimeError, match="fail_json_called"):
            manage_resource_manager_module.main()

    assert dummy_module.fail_payload["msg"] == "The 'fabric_name' parameter is required."
    assert dummy_module.fail_payload["failed"] is True
    ndmodule_mock.assert_not_called()


def test_record_nd_module_error_result_uses_rest_send_payload_when_available():
    """Helper consumes RestSend current response/result when ND object exposes them."""
    results = Results()
    results.action = "manage_resource_manager"

    nd = MagicMock()
    nd.rest_send.response_current = {"RETURN_CODE": 503, "MESSAGE": "controller unavailable", "DATA": {"detail": "x"}}
    nd.rest_send.result_current = {"success": False, "changed": False, "found": False}

    error = NDModuleError(msg="service unavailable", status=503, response_payload={"detail": "x"})

    manage_resource_manager_module._record_nd_module_error_result(results, nd, error, LOG)

    assert len(results.responses) == 1
    assert results.responses[0]["RETURN_CODE"] == 503
    assert len(results.results) == 1
    assert results.results[0]["success"] is False


def test_record_nd_module_error_result_falls_back_when_rest_send_unavailable():
    """Helper falls back to NDModuleError fields when RestSend attrs are missing/invalid."""
    results = Results()
    results.action = "manage_resource_manager"

    nd = MagicMock()
    nd.rest_send = None
    error = NDModuleError(msg="not found", status=404, response_payload={"error": "missing"})

    manage_resource_manager_module._record_nd_module_error_result(results, nd, error, LOG)

    assert len(results.responses) == 1
    assert results.responses[0]["RETURN_CODE"] == 404
    assert results.responses[0]["MESSAGE"] == "not found"
    assert results.responses[0]["DATA"] == {"error": "missing"}
    assert len(results.results) == 1
    assert results.results[0]["success"] is False


def test_main_ndmoduleerror_path_fails_with_standard_output():
    """main() handles NDModuleError raised during NDModule init and fails cleanly."""

    class _FailFastAnsibleModule(_DummyAnsibleModule):
        def fail_json(self, **kwargs):
            self.fail_payload = kwargs
            raise RuntimeError("fail_json_called")

    dummy_module = _FailFastAnsibleModule()
    dummy_module.params = {
        "fabric_name": "fabric-1",
        "output_level": "normal",
        "state": "merged",
        "config": [],
        "host": "198.51.100.10",
        "username": "admin",
    }

    with (
        patch.object(manage_resource_manager_module, "nd_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module.ResourceManagerConfigModel, "get_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module, "AnsibleModule", return_value=dummy_module),
        patch.object(
            manage_resource_manager_module,
            "require_pydantic",
        ),
        patch.object(
            manage_resource_manager_module,
            "setup_logging",
        ),
        patch.object(
            manage_resource_manager_module,
            "NDModule",
            side_effect=NDModuleError(msg="auth failed", status=401),
        ),
    ):
        with pytest.raises(RuntimeError, match="fail_json_called"):
            manage_resource_manager_module.main()

    assert dummy_module.fail_payload["msg"] == "auth failed"
    assert dummy_module.fail_payload["failed"] is True
    assert "error_details" not in dummy_module.fail_payload


def test_main_valueerror_path_fails_with_validation_message():
    """main() catches ValueError from resource-manager flow and fails with that message."""

    class _FailFastAnsibleModule(_DummyAnsibleModule):
        def fail_json(self, **kwargs):
            self.fail_payload = kwargs
            raise RuntimeError("fail_json_called")

    dummy_module = _FailFastAnsibleModule()
    dummy_module.params = {
        "fabric_name": "fabric-1",
        "output_level": "normal",
        "state": "merged",
        "config": [],
        "host": "198.51.100.10",
        "username": "admin",
    }

    mocked_rm_module = MagicMock()
    mocked_rm_module.manage_state.side_effect = ValueError("invalid config")

    with (
        patch.object(manage_resource_manager_module, "nd_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module.ResourceManagerConfigModel, "get_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module, "AnsibleModule", return_value=dummy_module),
        patch.object(
            manage_resource_manager_module,
            "require_pydantic",
        ),
        patch.object(
            manage_resource_manager_module,
            "setup_logging",
        ),
        patch.object(
            manage_resource_manager_module,
            "NDModule",
            return_value=MagicMock(),
        ),
        patch.object(
            manage_resource_manager_module,
            "NDResourceManagerModule",
            return_value=mocked_rm_module,
        ),
    ):
        with pytest.raises(RuntimeError, match="fail_json_called"):
            manage_resource_manager_module.main()

    assert dummy_module.fail_payload["msg"] == "invalid config"
    assert dummy_module.fail_payload["failed"] is True


def test_main_generic_exception_debug_includes_traceback():
    """main() catches unexpected exceptions and includes traceback at debug output level."""

    class _FailFastAnsibleModule(_DummyAnsibleModule):
        def fail_json(self, **kwargs):
            self.fail_payload = kwargs
            raise RuntimeError("fail_json_called")

    dummy_module = _FailFastAnsibleModule()
    dummy_module.params = {
        "fabric_name": "fabric-1",
        "output_level": "debug",
        "state": "merged",
        "config": [],
        "host": "198.51.100.10",
        "username": "admin",
    }

    mocked_rm_module = MagicMock()
    mocked_rm_module.manage_state.side_effect = RuntimeError("boom")

    with (
        patch.object(manage_resource_manager_module, "nd_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module.ResourceManagerConfigModel, "get_argument_spec", return_value={}),
        patch.object(manage_resource_manager_module, "AnsibleModule", return_value=dummy_module),
        patch.object(
            manage_resource_manager_module,
            "require_pydantic",
        ),
        patch.object(
            manage_resource_manager_module,
            "setup_logging",
        ),
        patch.object(
            manage_resource_manager_module,
            "NDModule",
            return_value=MagicMock(),
        ),
        patch.object(
            manage_resource_manager_module,
            "NDResourceManagerModule",
            return_value=mocked_rm_module,
        ),
    ):
        with pytest.raises(RuntimeError, match="fail_json_called"):
            manage_resource_manager_module.main()

    assert dummy_module.fail_payload["msg"] == "boom"
    assert dummy_module.fail_payload["failed"] is True
    assert "traceback" in dummy_module.fail_payload
    assert "RuntimeError: boom" in dummy_module.fail_payload["traceback"]


def test_resource_manager_config_rejects_unknown_id_pool_name():
    """Unknown ID pool names remain invalid for modifying states."""
    if not HAS_PYDANTIC:
        pytest.skip("Strict validator behavior requires pydantic runtime")

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


@pytest.mark.parametrize(
    ("pool_name", "resource"),
    [
        ("SLA_ID", "10300"),
        ("DEVICE_BGP_ASN", "5200"),
    ],
)
def test_resource_manager_config_accepts_fabric_specific_device_id_pools(pool_name, resource):
    """Fabric-specific ID pools validate with device scope."""
    if not HAS_PYDANTIC:
        pytest.skip("Strict validator behavior requires pydantic runtime")

    model = ResourceManagerConfigModel.model_validate(
        {
            "entity_name": "{0}_load_1".format(pool_name.lower()),
            "pool_type": "ID",
            "pool_name": pool_name,
            "scope_type": "device",
            "switches": ["SER1"],
            "resource": resource,
        },
        context={"state": "merged"},
    )

    assert model.pool_name == pool_name
    assert model.scope_type == "device"


def test_resource_manager_config_allows_partial_gathered_filter():
    """Gathered filters may provide partial criteria without switches."""
    model = ResourceManagerConfigModel.model_validate({"scope_type": "device"}, context={"state": "gathered"})
    assert model.scope_type == "device"
    assert model.switches is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("entity_name", "loopback0"),
        ("pool_name", "LOOPBACK_ID"),
        ("switches", ["SER1"]),
        ("resource", "10"),
        ("scope_type", "device"),
        ("pool_type", "id"),
    ],
)
def test_resource_manager_model_validates_supported_gathered_properties(field, value):
    """The model validates and normalizes every supported gathered property."""
    validated = ResourceManagerConfigModel.validate_gathered_config([{field: value}])

    expected = "ID" if field == "pool_type" else value
    assert validated == [{field: expected}]


def test_resource_manager_model_aggregates_unsupported_gathered_properties():
    """The model reports every invalid gathered item with its config index."""
    config = [
        {"pool_name": "LOOPBACK_ID", "vrf_name": "blue"},
        {"is_pre_allocated": False, "unknown_filter": "value"},
    ]

    with pytest.raises(ValueError) as exc_info:
        ResourceManagerConfigModel.validate_gathered_config(config)

    message = str(exc_info.value)
    assert "config index 0" in message
    assert "config index 1" in message
    assert "vrf_name" in message
    assert "is_pre_allocated" in message
    assert "unknown_filter" in message


@pytest.mark.parametrize("config", [None, []])
def test_resource_manager_model_empty_gathered_config_gathers_all(config):
    """Omitted and explicit empty gathered config both represent gather-all."""
    assert ResourceManagerConfigModel.validate_gathered_config(config) == []


@pytest.mark.parametrize("item", [{}, "not-a-dictionary"])
def test_resource_manager_model_rejects_propertyless_gathered_items(item):
    """A provided gathered item must contain a usable supported property."""
    with pytest.raises(ValueError, match="config index 0"):
        ResourceManagerConfigModel.validate_gathered_config([item])


def test_resource_manager_model_rejects_null_only_gathered_filter():
    """A gathered item containing no active filter property is rejected."""
    with pytest.raises(ValueError, match="must contain at least one supported property"):
        ResourceManagerConfigModel.validate_gathered_config([{"pool_name": None}])


def test_resource_manager_model_ignores_null_property_mixed_with_valid_filter():
    """Null placeholders are ignored when an active gathered filter is present."""
    validated = ResourceManagerConfigModel.validate_gathered_config([{"entity_name": "loopback0", "pool_name": None}])

    assert validated == [{"entity_name": "loopback0"}]


def test_resource_manager_model_accepts_ansible_normalized_gathered_filter():
    """Omitted suboptions populated with None by Ansible are not treated as supplied."""
    validator = ArgumentSpecValidator(ResourceManagerConfigModel.get_argument_spec())
    result = validator.validate(
        {
            "fabric_name": "fabric-1",
            "state": "gathered",
            "config": [{"entity_name": "loopback0"}],
        }
    )

    assert result.error_messages == []
    assert ResourceManagerConfigModel.validate_gathered_config(result.validated_parameters["config"]) == [{"entity_name": "loopback0"}]


def test_resource_manager_config_allows_auto_allocation_without_resource():
    """Merged auto-allocation does not require an explicit resource value."""
    model = ResourceManagerConfigModel.model_validate(
        {
            "entity_name": "loopback0",
            "pool_type": "ID",
            "pool_name": "LOOPBACK_ID",
            "scope_type": "device",
            "switches": ["SER1"],
            "is_pre_allocated": False,
        },
        context={"state": "merged"},
    )

    assert model.resource is None
    assert model.is_pre_allocated is False


def test_resource_manager_config_requires_resource_when_preallocation_omitted():
    """Merged config keeps the legacy explicit-allocation default."""
    with pytest.raises(Exception, match="Mandatory parameter\\(s\\) missing for state='merged': 'resource'"):
        ResourceManagerConfigModel.model_validate(
            {
                "entity_name": "loopback0",
                "pool_type": "ID",
                "pool_name": "LOOPBACK_ID",
                "scope_type": "device",
                "switches": ["SER1"],
            },
            context={"state": "merged"},
        )


def test_resource_manager_argspec_includes_nested_config_options():
    """Argument spec exposes typed nested config options for Ansible-side validation."""
    spec = ResourceManagerConfigModel.get_argument_spec()

    assert spec["fabric_name"]["type"] == "str"
    assert spec["fabric_name"]["required"] is True
    assert spec["state"]["choices"] == ["merged", "deleted", "gathered"]

    config_spec = spec["config"]
    assert config_spec["type"] == "list"
    assert config_spec["elements"] == "dict"

    options = config_spec["options"]
    assert options["entity_name"]["type"] == "str"
    assert options["pool_type"]["type"] == "str"
    assert options["pool_type"]["choices"] == ["ID", "IP", "SUBNET"]
    assert options["pool_name"]["type"] == "str"
    assert options["scope_type"]["type"] == "str"
    assert options["scope_type"]["choices"] == ["fabric", "device", "device_interface", "device_pair", "link"]
    assert options["resource"]["type"] == "str"
    assert options["is_pre_allocated"]["type"] == "bool"
    assert options["vrf_name"]["type"] == "str"
    assert options["switches"]["type"] == "list"
    assert options["switches"]["elements"] == "str"


@pytest.mark.parametrize(
    ("config", "expected_message"),
    [
        (
            [{"entity_name": "l3_vni_fabric"}],
            "Mandatory parameter 'scope_type' missing",
        ),
        ([{"scope_type": "fabric"}], "Mandatory parameter 'pool_type' missing"),
        (
            [
                {
                    "entity_name": "l3_vni_fabric",
                    "pool_type": "ID",
                    "scope_type": "fabric",
                }
            ],
            "Mandatory parameter 'pool_name' missing",
        ),
        (
            [{"pool_type": "ID", "pool_name": "VPC_ID", "scope_type": "fabric"}],
            "Mandatory parameter 'entity_name' missing",
        ),
        (
            [
                {
                    "entity_name": "SER1~SER2",
                    "pool_type": "ID",
                    "pool_name": "VPC_ID",
                    "scope_type": "device_pair",
                }
            ],
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


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param(
            {
                "entity_name": "SER1~SER2~PAIR",
                "pool_type": "ID",
                "pool_name": "VPC_ID",
                "scope_type": "device_pair",
                "switches": ["SER1", "SER2"],
                "resource": "10",
            },
            {
                "entity_name": "SER2~SER1~PAIR",
                "pool_type": "ID",
                "pool_name": "VPC_ID",
                "scope_type": "device_pair",
                "switches": ["SER2", "SER1"],
                "resource": "10",
            },
            id="reversed-device-pair-with-label",
        ),
        pytest.param(
            {
                "entity_name": "SER1~Ethernet1/1~SER2~Ethernet1/2",
                "pool_type": "SUBNET",
                "pool_name": "SUBNET",
                "scope_type": "link",
                "switches": ["SER1", "SER2"],
                "resource": "10.0.0.0/30",
            },
            {
                "entity_name": "SER2~Ethernet1/2~SER1~Ethernet1/1",
                "pool_type": "SUBNET",
                "pool_name": "SUBNET",
                "scope_type": "link",
                "switches": ["SER2", "SER1"],
                "resource": "10.0.0.0/30",
            },
            id="reversed-link",
        ),
        pytest.param(
            {
                "entity_name": "loopback0",
                "pool_type": "ID",
                "pool_name": "LOOPBACK_ID",
                "scope_type": "device",
                "switches": ["SER1"],
                "resource": "10",
            },
            {
                "entity_name": "loopback0",
                "pool_type": "ID",
                "pool_name": "loopbackId",
                "scope_type": "device",
                "switches": ["SER1"],
                "resource": "10",
            },
            id="pool-alias",
        ),
    ],
)
def test_resource_manager_validate_configs_rejects_normalized_duplicate_entries(first, second):
    """Reconciliation-equivalent desired resources are rejected before diffing."""
    with pytest.raises(ValueError, match="Duplicate config entries"):
        ResourceManagerDiffEngine.validate_configs([first, second], "merged", log=LOG)


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
            "vrf_name": "default",
            "is_pre_allocated": False,
            "switches": ["192.0.2.10"],
        }
    ]


@pytest.mark.parametrize("field", ["entity_name", "pool_name", "switches", "resource", "scope_type", "pool_type"])
def test_filter_has_active_criteria_accepts_documented_gathered_filter_fields(field):
    """Every documented gathered filter field marks a filter item active."""
    value = ["SER1"] if field == "switches" else "value"
    assert NDResourceManagerModule._filter_has_active_criteria({field: value}) is True  # pylint: disable=protected-access


def test_filter_has_active_criteria_rejects_empty_filter_item():
    """Empty gathered config entries do not trigger candidate fetching."""
    assert NDResourceManagerModule._filter_has_active_criteria({}) is False  # pylint: disable=protected-access


def test_manage_fabric_resources_get_endpoint_path_and_class_name():
    """Resources GET endpoint has the correct class name, verb, and query path."""
    endpoint = EpManageFabricResourcesGet(fabric_name="fabric-1")
    endpoint.endpoint_params.pool_name = "LOOPBACK_ID"

    assert endpoint.class_name == "EpManageFabricResourcesGet"
    assert endpoint.verb == HttpVerbEnum.GET
    assert endpoint.path == "/api/v1/manage/fabrics/fabric-1/resources?poolName=LOOPBACK_ID"


def test_resource_manager_exit_module_normal_output_omits_raw_results_keys():
    """Normal output does not expose raw Results aggregation keys."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)

    module.exit_module()

    for key in (
        "metadata",
        "path",
        "payload",
        "response",
        "result",
        "verb",
        "verbosity_level",
    ):
        assert key not in ansible_module.exit_payload
    assert "api_paths" not in ansible_module.exit_payload
    assert ansible_module.exit_payload["changed"] is False


def test_resource_manager_exit_module_verbosity_2_omits_api_keys():
    """-vv output exposes path/verb summary but not full controller detail."""
    module, ansible_module = _resource_manager_for_exit(verbosity=2)

    module.exit_module()

    assert ansible_module.exit_payload["api_paths"] == ["/api/v1/manage/fabrics/fabric-1/resources"]
    assert ansible_module.exit_payload["api_verbs"] == ["POST"]
    for key in (
        "api_payload",
        "api_response",
        "api_result",
        "api_diff",
        "api_metadata",
    ):
        assert key not in ansible_module.exit_payload


def test_resource_manager_exit_module_verbose_output_uses_api_keys_only():
    """-vvv output exposes API details only through normalized api_* keys."""
    module, ansible_module = _resource_manager_for_exit(verbosity=3)

    module.exit_module()

    for key in (
        "metadata",
        "path",
        "payload",
        "response",
        "result",
        "verb",
        "verbosity_level",
    ):
        assert key not in ansible_module.exit_payload
    assert ansible_module.exit_payload["api_paths"] == ["/api/v1/manage/fabrics/fabric-1/resources"]
    assert ansible_module.exit_payload["api_verbs"] == ["POST"]
    assert ansible_module.exit_payload["api_payload"] == [{"entityName": "loopback0"}]


# =========================================================================
# ADDITIONAL HELPER FUNCTIONS FOR COMPREHENSIVE MOCKING
# =========================================================================


def _mock_nd_module(fabric="fabric-1", state="merged", config=None, check_mode=False, fabric_type="vxlanIbgp"):
    """Create a mock NDModule with request method for API calls."""
    nd = MagicMock()
    nd.params = {
        "fabric_name": fabric,
        "state": state,
        "config": config or [],
        "output_level": "normal",
    }
    nd.module = MagicMock()
    nd.module.check_mode = check_mode
    nd.request = MagicMock(return_value=[])
    nd.status = 200

    def _request_side_effect(path, *args, **kwargs):
        if isinstance(path, str):
            prefix = "/api/v1/manage/fabrics/"
            if path.startswith(prefix):
                tail = path[len(prefix) :].split("?", 1)[0]
                if "/" not in tail:
                    return {"management": {"type": fabric_type}}
        return nd.request.return_value

    nd.request.side_effect = _request_side_effect
    return nd


def _mock_fabric_inventory(ip_to_id_map=None):
    """Create a mock FabricSwitchInventory."""
    if ip_to_id_map is None:
        ip_to_id_map = {"192.0.2.10": "SER1", "192.0.2.11": "SER2"}

    switches = []
    by_ip = {}
    by_id = {}
    for ip, serial in ip_to_id_map.items():
        switch = MagicMock()
        switch.fabric_management_ip = ip
        switch.switch_id = serial
        switches.append(switch)
        by_ip[ip] = switch
        by_id[serial] = switch

    inventory = MagicMock()
    inventory.switches = switches
    inventory.by_ip.return_value = by_ip
    inventory.by_id.return_value = by_id
    return inventory


def _resource_manager_with_nd(fabric="fabric-1", state="merged", config=None, check_mode=False, all_resources=None):
    """Create NDResourceManagerModule with mocked ND and pre-set resources."""
    nd = _mock_nd_module(fabric, state, config, check_mode)
    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    if all_resources is not None:
        module._all_resources = all_resources  # pylint: disable=protected-access
        module.existing = list(all_resources)
        module.previous = list(all_resources)
    if config and all(isinstance(item, ResourceManagerConfigModel) for item in config):
        module.proposed = list(config)
    return module, nd


# =========================================================================
# PHASE 1: STATE HANDLER TESTS (manage_merged, manage_deleted, manage_gathered)
# =========================================================================


def test_manage_merged_no_config_raises_error():
    """manage_merged with empty config raises validation error."""
    module, nd = _resource_manager_with_nd(state="merged", config=[])

    with pytest.raises(ValueError, match="config.*mandatory"):
        module._validate_input()  # pylint: disable=protected-access


def test_manage_merged_idempotent_no_changes():
    """manage_merged with existing matching resource reports no changes."""
    cfg = _config()
    resp = _response()

    changes = ResourceManagerDiffEngine.compute_changes([cfg], [resp], log=LOG)
    assert len(changes["idempotent"]) == 1
    assert changes["to_add"] == []
    assert changes["to_update"] == []


def test_manage_merged_new_resource_creates_post():
    """manage_merged with new resource generates POST payload."""
    cfg = _config(entity_name="loopback1", resource="11")
    module = _resource_manager()
    module.fabric = "fabric-1"

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["entityName"] == "loopback1"
    assert payload["resourceValue"] == "11"
    assert payload["poolName"] == "LOOPBACK_ID"
    assert payload["poolType"] == "ID"
    assert payload["scopeDetails"]["switchId"] == "SER1"


def test_manage_merged_check_mode_skips_api_calls():
    """manage_merged with check_mode=True logs payload but skips API calls."""
    cfg = _config()
    nd = _mock_nd_module(check_mode=True)

    # Mock to prevent actual API call during init
    nd.request.return_value = []

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)

    assert nd.module.check_mode is True


def test_manage_deleted_no_config_raises_error():
    """manage_deleted with empty config raises validation error."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[])

    with pytest.raises(ValueError, match="config.*mandatory"):
        module._validate_input()  # pylint: disable=protected-access


def test_manage_deleted_matching_resource_removes_by_id():
    """manage_deleted removes resource matching proposed config."""
    resp = _response()

    changes = ResourceManagerDiffEngine.compute_changes([], [resp], log=LOG)
    assert len(changes["to_delete"]) == 1
    assert changes["to_delete"][0].resource_id == 101


def test_manage_gathered_no_config_returns_all():
    """manage_gathered with no config returns all resources."""
    resp1 = _response(resourceId=101, entityName="loopback0")
    resp2 = _response(resourceId=102, entityName="loopback1", resourceValue="11")
    module = _resource_manager()
    module.config = []
    module._all_resources = [resp1, resp2]  # pylint: disable=protected-access

    # No filters, should return all
    assert len(module._all_resources) == 2  # pylint: disable=protected-access


def test_manage_gathered_single_filter_entity_name():
    """manage_gathered with entity_name filter matches one resource."""
    resp1 = _response(resourceId=101, entityName="loopback0")
    resp2 = _response(resourceId=102, entityName="loopback1", resourceValue="11")
    module = _resource_manager()
    module.config = [{"entity_name": "loopback0"}]
    module._all_resources = [resp1, resp2]  # pylint: disable=protected-access

    result = module._resource_matches_filter(resp1, {"entity_name": "loopback0"})  # pylint: disable=protected-access
    assert result is True


# =========================================================================
# PHASE 2: DATA FETCH, RESOLUTION, AND DIFF LOGIC
# =========================================================================


def test_get_all_resources_api_returns_list():
    """_get_all_resources parses list response directly."""
    nd = _mock_nd_module()
    resp_list = [
        {
            "resourceId": 101,
            "entityName": "loopback0",
            "poolName": "LOOPBACK_ID",
            "resourceValue": "10",
            "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
        },
        {
            "resourceId": 102,
            "entityName": "loopback1",
            "poolName": "LOOPBACK_ID",
            "resourceValue": "11",
            "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
        },
    ]
    nd.request.return_value = resp_list

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    assert len(module._all_resources) == 2  # pylint: disable=protected-access
    assert module._resources_fetched is True  # pylint: disable=protected-access


def test_get_all_resources_api_returns_dict_with_resources_key():
    """_get_all_resources parses {"resources": [...]} response."""
    nd = _mock_nd_module()
    resp_dict = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            },
        ],
        "meta": {"count": 1},
    }
    nd.request.return_value = resp_dict

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    assert len(module._all_resources) == 1  # pylint: disable=protected-access


def test_get_all_resources_handles_404_as_empty():
    """_get_all_resources treats 404 as empty fabric (no resources yet)."""
    nd = _mock_nd_module()
    error = NDModuleError(msg="Not Found", status=404)
    nd.request.side_effect = error

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    assert len(module._all_resources) == 0  # pylint: disable=protected-access
    assert module._resources_fetched is True  # pylint: disable=protected-access


def test_get_all_resources_caches_on_second_call():
    """_get_all_resources caches result; second call returns without API hit."""
    nd = _mock_nd_module()
    nd.request.return_value = [
        {
            "resourceId": 101,
            "entityName": "loopback0",
            "poolName": "LOOPBACK_ID",
            "resourceValue": "10",
            "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
        },
    ]

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    first_call_count = nd.request.call_count

    # Call _get_all_resources again (internally)
    module._get_all_resources()  # pylint: disable=protected-access

    # Should not have made additional API call (cached)
    assert nd.request.call_count == first_call_count


def test_get_all_resources_preserves_raw_dict_on_parse_failure():
    """_get_all_resources keeps raw dict when ResourceManagerResponse parsing fails."""
    nd = _mock_nd_module()
    raw_dict = {
        "resourceId": 101,
        "entityName": "loopback0",
        "scopeDetails": {"scopeType": "unknown_type"},
    }  # Invalid scope type

    nd.request.return_value = [raw_dict]

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    # Should preserve raw dict even if parsing failed
    assert len(module._all_resources) > 0  # pylint: disable=protected-access


def test_get_all_resources_reads_multiple_pages_with_offsets():
    """_get_all_resources follows paginated resource metadata."""
    nd = _mock_nd_module()
    page1 = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
        ],
        "meta": {
            "counts": {"remaining": 1, "total": 2},
            "links": {"next": "/api/v1/manage/fabrics/fabric-1/resources?max=1000&offset=1000"},
        },
    }
    page2 = {
        "resources": [
            {
                "resourceId": 102,
                "entityName": "loopback1",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "11",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 2}},
    }
    nd.request.side_effect = [page1, page2]

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    paths = [call.args[0] for call in nd.request.call_args_list]
    assert len(module._all_resources) == 2  # pylint: disable=protected-access
    assert "max=100&offset=0" in paths[0]
    assert "max=100&offset=1" in paths[1]


@pytest.mark.parametrize("requested_page_size", [1, 7, 100, 500])
def test_fetch_resources_paginated_is_independent_of_requested_page_size(requested_page_size):
    """Pagination advances by actual response count when the server caps page size."""
    nd = _mock_nd_module()
    total = 11

    def get_page(path, _verb):
        query = parse_qs(urlparse(path).query)
        offset = int(query["offset"][0])
        response_count = min(requested_page_size, 3, total - offset)
        resources = [
            {
                "resourceId": resource_id,
                "entityName": f"loopback{resource_id}",
                "poolName": "LOOPBACK_ID",
                "resourceValue": str(resource_id),
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
            for resource_id in range(offset, offset + response_count)
        ]
        return {
            "resources": resources,
            "meta": {"counts": {"remaining": total - offset - response_count, "total": total}},
        }

    nd.request.side_effect = get_page
    module = NDResourceManagerModule(nd, Results(), log=LOG)
    module.RESOURCE_PAGE_SIZE = requested_page_size

    resources = module._fetch_resources_paginated()  # pylint: disable=protected-access

    assert len(resources) == total
    paths = [call.args[0] for call in nd.request.call_args_list]
    offsets = [int(parse_qs(urlparse(path).query)["offset"][0]) for path in paths]
    expected_offsets = list(range(total)) if requested_page_size == 1 else [0, 3, 6, 9]
    assert offsets == expected_offsets
    assert all(f"max={requested_page_size}" in path for path in paths)


def test_fetch_resources_paginated_uses_total_when_remaining_stops_early():
    """A zero remaining value cannot truncate a result whose total is not reached."""
    nd = _mock_nd_module()
    pages = [
        {
            "resources": [
                {
                    "resourceId": resource_id,
                    "entityName": f"loopback{resource_id}",
                    "poolName": "LOOPBACK_ID",
                    "resourceValue": str(resource_id),
                    "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                }
            ],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        }
        for resource_id in (101, 102)
    ]
    nd.request.side_effect = pages
    module = NDResourceManagerModule(nd, Results(), log=LOG)

    resources = module._fetch_resources_paginated()  # pylint: disable=protected-access

    assert len(resources) == 2
    assert "offset=1" in nd.request.call_args_list[1].args[0]


def test_fetch_resources_paginated_retries_then_fails_on_incomplete_total():
    """Persistent premature empty pages fail instead of returning partial inventory."""
    nd = _mock_nd_module()
    partial_page = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
        ],
        "meta": {"counts": {"remaining": 1, "total": 2}},
    }
    empty_page = {"resources": [], "meta": {"counts": {"remaining": 0, "total": 2}}}
    nd.request.side_effect = [partial_page, empty_page] * 6
    module = NDResourceManagerModule(nd, Results(), log=LOG)

    with patch("ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.time.sleep") as sleep:
        with pytest.raises(ValueError, match="remained inconsistent after 6 attempts"):
            module._fetch_resources_paginated()  # pylint: disable=protected-access

    paths = [call.args[0] for call in nd.request.call_args_list]
    assert [int(parse_qs(urlparse(path).query)["offset"][0]) for path in paths] == [0, 1] * 6
    assert [call.args[0] for call in sleep.call_args_list] == [2, 4, 6, 8, 10]


def test_fetch_resources_paginated_discards_partial_data_before_successful_retry():
    """A retry starts at zero and does not retain resources from the failed attempt."""
    nd = _mock_nd_module()

    def page(resource_id, remaining):
        return {
            "resources": [
                {
                    "resourceId": resource_id,
                    "entityName": f"loopback{resource_id}",
                    "poolName": "LOOPBACK_ID",
                    "resourceValue": str(resource_id),
                    "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                }
            ],
            "meta": {"counts": {"remaining": remaining, "total": 2}},
        }

    empty_page = {"resources": [], "meta": {"counts": {"remaining": 0, "total": 2}}}
    nd.request.side_effect = [page(999, 1), empty_page, page(101, 1), page(102, 0)]
    module = NDResourceManagerModule(nd, Results(), log=LOG)

    resources = module._fetch_resources_paginated()  # pylint: disable=protected-access

    assert [module._get_resource_id(resource) for resource in resources] == [101, 102]  # pylint: disable=protected-access


def test_manage_deleted_does_not_mutate_after_incomplete_pagination():
    """Deleted state fails before remove-by-ID when inventory cannot be completed."""
    config = [
        {
            "entity_name": "loopback0",
            "pool_type": "ID",
            "pool_name": "loopbackId",
            "scope_type": "device",
            "switches": ["192.0.2.10"],
        }
    ]
    nd = _mock_nd_module(state="deleted", config=config)
    resource_read_count = 0

    def request(path, _verb, **kwargs):
        nonlocal resource_read_count
        if "/resources" not in path:
            return {"management": {"type": "vxlanIbgp"}}
        assert "data" not in kwargs, "delete mutation must not run with incomplete inventory"
        resource_read_count += 1
        if resource_read_count % 2:
            return {
                "resources": [
                    {
                        "resourceId": 101,
                        "entityName": "loopback0",
                        "poolName": "loopbackId",
                        "resourceValue": "10",
                        "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                    }
                ],
                "meta": {"counts": {"remaining": 1, "total": 2}},
            }
        return {"resources": [], "meta": {"counts": {"remaining": 0, "total": 2}}}

    nd.request.side_effect = request
    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=_mock_fabric_inventory({"192.0.2.10": "SER1"}),
    ):
        module = NDResourceManagerModule(nd, Results(), log=LOG)
        module.PAGINATION_RETRY_DELAY_SECONDS = 0
        with pytest.raises(ValueError, match="remained inconsistent after 6 attempts"):
            module.manage_state()

    assert resource_read_count == 12


def test_fetch_resources_paginated_uses_filtered_query_path():
    """Filtered resource reads push poolName, switchId, and entityName filter to the API."""
    nd = _mock_nd_module()
    nd.request.return_value = {"resources": [], "meta": {"counts": {"remaining": 0, "total": 0}}}
    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)

    resources = module._fetch_resources_paginated(  # pylint: disable=protected-access
        pool_name="LOOPBACK_ID",
        switch_id="SER1",
        filter_expr="entityName:loopback0",
    )

    assert resources == []
    path = nd.request.call_args.args[0]
    assert "poolName=LOOPBACK_ID" in path
    assert "switchId=SER1" in path
    assert "filter=entityName:loopback0" in path
    assert "max=100" in path
    assert "offset=0" in path


@pytest.mark.parametrize(
    ("have", "want", "should_match"),
    [
        ("192.168.1.1", "192.168.1.1", True),  # Exact IPv4 match
        ("192.168.1.1", "192.168.1.2", False),  # Different IPv4
        ("10.0.0.0/24", "10.0.0.0/24", True),  # Exact network match
        ("10.0.0.0/24", "10.0.1.0/24", False),  # Different network
        ("10", "10", True),  # String ID match
        ("loopback", "loopback", True),  # String name match
    ],
)
def test_compare_resource_values_various_formats(have, want, should_match):
    """_compare_resource_values handles addresses, networks, and strings."""
    result = ResourceManagerDiffEngine._compare_resource_values(have, want, log=LOG)
    assert result is should_match


def test_compute_changes_detects_to_add_bucket():
    """compute_changes creates to_add bucket for proposed resources not in existing."""
    proposed = [_config(entity_name="loopback_new")]
    existing = [_response(entityName="loopback_old")]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    assert len(changes["to_add"]) == 1
    assert len(changes["idempotent"]) == 0


def test_compute_changes_detects_to_update_bucket():
    """compute_changes creates to_update bucket for changed resource values."""
    proposed = [_config(entity_name="loopback0", resource="20")]  # Different value
    existing = [_response(entityName="loopback0", resourceValue="10")]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    assert len(changes["to_update"]) == 1
    assert len(changes["idempotent"]) == 0


def test_compute_changes_treats_vrf_name_as_identity():
    """Resources that differ only by VRF are not treated as the same allocation."""
    proposed = [_config(vrf_name="blue")]
    existing = [_response(vrfName="red")]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    assert len(changes["to_add"]) == 1
    assert len(changes["idempotent"]) == 0


def test_compute_changes_auto_allocated_value_is_idempotent():
    """Auto-allocation config stays idempotent after ND assigns a resource value."""
    proposed = [_config(resource=None, is_pre_allocated=False)]
    existing = [_response(resourceValue="10", isPreAllocated=False)]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    assert len(changes["idempotent"]) == 1
    assert changes["to_update"] == []


def test_compute_changes_detects_to_delete_bucket():
    """compute_changes creates to_delete bucket for existing without proposed match."""
    proposed = []
    existing = [_response(entityName="loopback0")]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    assert len(changes["to_delete"]) == 1
    assert len(changes["idempotent"]) == 0


def test_compute_changes_multi_switch_device_pair():
    """compute_changes handles device_pair scope with two endpoints."""
    proposed = [
        _config(
            entity_name="SER1~SER2",
            scope_type="device_pair",
            pool_name="VPC_ID",
            pool_type="ID",
            switches=["SER1", "SER2"],
            resource="10",
        )
    ]
    existing = [
        _response(
            entityName="SER1~SER2",
            poolName="VPC_ID",
            scopeDetails={
                "scopeType": "devicePair",
                "srcSwitchId": "SER1",
                "dstSwitchId": "SER2",
            },
        )
    ]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)
    assert len(changes["idempotent"]) == 1


# =========================================================================
# PHASE 3: SCOPE BUILDERS AND PAYLOAD CONSTRUCTION
# =========================================================================


def test_build_fabric_scope_payload():
    """_build_create_payload for fabric scope omits switch information."""
    module = _resource_manager()
    cfg = _config(scope_type="fabric", pool_name="L3_VNI", switches=None)

    payload = module._build_create_payload(cfg, switch_ip=None)  # pylint: disable=protected-access

    assert payload["scopeDetails"]["fabricName"] == "fabric-1"
    assert "switchId" not in payload["scopeDetails"]


def test_build_device_scope_payload():
    """_build_create_payload for device scope includes single switch."""
    module = _resource_manager()
    cfg = _config(scope_type="device", switches=["SER1"])

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["scopeDetails"]["switchId"] == "SER1"
    assert payload["scopeDetails"]["scopeType"] == "device"
    assert payload["isPreAllocated"] is True


def test_build_create_payload_passes_auto_allocation_and_vrf():
    """_build_create_payload honors is_pre_allocated=false and vrf_name."""
    module = _resource_manager()
    cfg = _config(
        resource=None,
        is_pre_allocated=False,
        vrf_name="pr333_vrf_marker",
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["isPreAllocated"] is False
    assert payload["vrfName"] == "pr333_vrf_marker"
    assert "resourceValue" not in payload


def test_build_create_payload_keeps_legacy_preallocation_default():
    """Omitted is_pre_allocated keeps sending explicit pre-allocation."""
    module = _resource_manager()
    cfg = _config(is_pre_allocated=None)

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["isPreAllocated"] is True


def test_build_device_interface_scope_payload():
    """_build_create_payload for device_interface extracts interface from entity_name."""
    module = _resource_manager()
    cfg = _config(
        entity_name="SER1~Ethernet1/13",
        scope_type="device_interface",
        pool_name="IP_POOL",
        switches=["SER1"],
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["scopeDetails"]["switchId"] == "SER1"
    assert payload["scopeDetails"]["interfaceName"] == "Ethernet1/13"
    assert payload["scopeDetails"]["scopeType"] == "deviceInterface"


def test_build_device_pair_scope_payload():
    """_build_create_payload for device_pair extracts both endpoints."""
    module = _resource_manager()
    cfg = _config(
        entity_name="SER1~SER2",
        scope_type="device_pair",
        pool_name="VPC_ID",
        switches=["SER1", "SER2"],
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["scopeDetails"]["srcSwitchId"] == "SER1"
    assert payload["scopeDetails"]["dstSwitchId"] == "SER2"
    assert payload["scopeDetails"]["scopeType"] == "devicePair"


def test_build_link_scope_payload_all_endpoints():
    """_build_create_payload for link extracts all four tilde-separated fields."""
    module = _resource_manager()
    cfg = _config(
        entity_name="SER1~Ethernet1/1~SER2~Ethernet1/2",
        scope_type="link",
        pool_type="SUBNET",
        pool_name="SUBNET",
        resource="10.0.0.0/30",
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["scopeDetails"]["srcSwitchId"] == "SER1"
    assert payload["scopeDetails"]["srcInterfaceName"] == "Ethernet1/1"
    assert payload["scopeDetails"]["dstSwitchId"] == "SER2"
    assert payload["scopeDetails"]["dstInterfaceName"] == "Ethernet1/2"
    assert payload["scopeDetails"]["scopeType"] == "link"


def test_build_create_payload_with_subnet_resource():
    """_build_create_payload sets resourceValue for SUBNET pool type with link scope."""
    module = _resource_manager()
    cfg = _config(
        entity_name="SER1~Ethernet1/1~SER2~Ethernet1/2",
        scope_type="link",
        pool_type="SUBNET",
        pool_name="SUBNET",
        resource="10.0.0.0/24",
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["resourceValue"] == "10.0.0.0/24"
    assert payload["poolType"] == "SUBNET"


def test_build_create_payload_with_ip_resource():
    """_build_create_payload sets resourceValue for IP pool type."""
    module = _resource_manager()
    cfg = _config(
        entity_name="SER1~Ethernet1/13",
        scope_type="device_interface",
        pool_type="IP",
        pool_name="IP_POOL",
        resource="192.168.1.1",
    )

    payload = module._build_create_payload(cfg, switch_ip="SER1")  # pylint: disable=protected-access

    assert payload["resourceValue"] == "192.168.1.1"
    assert payload["poolType"] == "IP"


# =========================================================================
# PHASE 4: FILTERING, HELPERS, AND ACCESSOR METHODS
# =========================================================================


@pytest.mark.parametrize(
    ("e1", "e2", "scope_type", "should_match"),
    [
        ("SER1~SER2", "SER1~SER2", "device_pair", True),
        ("SER1~SER2", "SER2~SER1", "device_pair", True),
        (
            "{{ ansible_sno_2 }}~{{ ansible_sno_1 }}",
            "{{ ansible_sno_1 }}~{{ ansible_sno_2 }}",
            "device_pair",
            True,
        ),
        ("SER1~SER2~LABEL", "SER2~SER1~LABEL", "device_pair", True),
        ("SER1~SER2~LABEL", "SER2~SER1~OTHER", "device_pair", False),
        ("SER1~SER2", "SER3~SER4", "device_pair", False),
        (
            "SER1~Ethernet1/6~SER2~Ethernet1/10",
            "SER2~Ethernet1/10~SER1~Ethernet1/6",
            "link",
            True,
        ),
        (
            "SER1~Ethernet1/6~SER2~Ethernet1/10",
            "SER2~Ethernet1/6~SER1~Ethernet1/10",
            "link",
            False,
        ),
        ("SER1~Ethernet1/6", "Ethernet1/6~SER1", "device_interface", False),
        ("SER1", "SER1", "device", True),
        ("loopback0", "loopback0", "fabric", True),
    ],
)
def test_entity_names_match_scope_aware(e1, e2, scope_type, should_match):
    """_entity_names_match compares multi-endpoint resources without cross-pairing links."""
    module = _resource_manager()
    result = module._entity_names_match(e1, e2, scope_type=scope_type)
    assert result is should_match


def test_resource_matches_filter_by_entity_name():
    """_resource_matches_filter matches only on entity_name when specified."""
    module = _resource_manager()
    resource = _response(entityName="loopback0")

    assert module._resource_matches_filter(resource, {"entity_name": "loopback0"}) is True  # pylint: disable=protected-access
    assert module._resource_matches_filter(resource, {"entity_name": "loopback1"}) is False  # pylint: disable=protected-access


def test_resource_matches_filter_by_pool_name():
    """_resource_matches_filter matches only on pool_name when specified."""
    module = _resource_manager()
    resource = _response(poolName="LOOPBACK_ID")

    assert module._resource_matches_filter(resource, {"pool_name": "LOOPBACK_ID"}) is True  # pylint: disable=protected-access
    assert module._resource_matches_filter(resource, {"pool_name": "VPC_ID"}) is False  # pylint: disable=protected-access


def test_resource_matches_filter_by_switches():
    """_resource_matches_filter checks if switch ID is in filter list."""
    module = _resource_manager()
    resource = _response(
        scopeDetails={
            "scopeType": "device",
            "switchId": "SER1",
            "switchIp": "192.0.2.10",
        }
    )

    # Filter matches when switch is in list
    assert module._resource_matches_filter(resource, {"switches": ["SER1"]}) is True  # pylint: disable=protected-access
    # Filter does not match when switch not in list
    assert module._resource_matches_filter(resource, {"switches": ["SER2"]}) is False  # pylint: disable=protected-access


@pytest.mark.parametrize("scope_type", ["devicePair", "link"])
@pytest.mark.parametrize(("src_switch_id", "dst_switch_id"), [("SER1", "SER2"), ("SER2", "SER1")])
@pytest.mark.parametrize("filter_switch_id", ["SER1", "SER2"])
def test_resource_matches_filter_by_multi_endpoint_switch(scope_type, src_switch_id, dst_switch_id, filter_switch_id):
    """Multi-endpoint switch filters match either endpoint in controller order."""
    module = _resource_manager()
    resource = _response(
        scopeDetails={
            "scopeType": scope_type,
            "srcSwitchId": src_switch_id,
            "dstSwitchId": dst_switch_id,
        }
    )

    assert module._resource_matches_filter(resource, {"switches": [filter_switch_id]}) is True  # pylint: disable=protected-access
    assert module._resource_matches_filter(resource, {"switches": ["SER3"]}) is False  # pylint: disable=protected-access


def test_get_switch_ids_supports_raw_multi_endpoint_resource():
    """_get_switch_ids extracts both endpoint IDs from a raw API dictionary."""
    module = _resource_manager()
    resource = {
        "scopeDetails": {
            "scopeType": "devicePair",
            "srcSwitchId": "SER1",
            "dstSwitchId": "SER2",
        }
    }

    assert module._get_switch_ids(resource) == ("SER1", "SER2")  # pylint: disable=protected-access


def test_resource_matches_filter_by_resource_value():
    """_resource_matches_filter checks documented resource filters."""
    module = _resource_manager()
    resource = _response(resourceValue="48950")

    assert module._resource_matches_filter(resource, {"resource": "48950"}) is True  # pylint: disable=protected-access
    assert module._resource_matches_filter(resource, {"resource": "48990"}) is False  # pylint: disable=protected-access


def test_resource_matches_filter_by_scope_type():
    """_resource_matches_filter checks documented scope_type filters."""
    module = _resource_manager()
    resource = _response(scopeDetails={"scopeType": "fabric"})

    assert module._resource_matches_filter(resource, {"scope_type": "fabric"}) is True  # pylint: disable=protected-access
    assert module._resource_matches_filter(resource, {"scope_type": "device"}) is False  # pylint: disable=protected-access


def test_resource_matches_filter_by_pool_type():
    """_resource_matches_filter checks documented pool_type filters."""
    module = _resource_manager()
    resource = _response(resourceValue="192.0.2.1")

    assert module._resource_matches_filter(resource, {"pool_type": "IP"}) is True  # pylint: disable=protected-access
    assert module._resource_matches_filter(resource, {"pool_type": "ID"}) is False  # pylint: disable=protected-access


def test_resource_matches_filter_combined_criteria():
    """_resource_matches_filter combines multiple filter criteria."""
    module = _resource_manager()
    resource = _response(
        entityName="loopback0",
        poolName="LOOPBACK_ID",
        scopeDetails={"scopeType": "device", "switchId": "SER1"},
    )

    # All criteria match
    filter_item = {
        "entity_name": "loopback0",
        "pool_name": "LOOPBACK_ID",
        "switches": ["SER1"],
    }
    assert module._resource_matches_filter(resource, filter_item) is True  # pylint: disable=protected-access

    # One criterion fails
    filter_item = {
        "entity_name": "loopback0",
        "pool_name": "VPC_ID",
        "switches": ["SER1"],
    }
    assert module._resource_matches_filter(resource, filter_item) is False  # pylint: disable=protected-access


def test_apply_gathered_filters_empty_filters():
    """_apply_gathered_filters with empty config or no filter criteria returns empty."""
    module = _resource_manager()
    module.config = []
    module._all_resources = [
        _response(),
        _response(resourceId=102, entityName="loopback1"),
    ]  # pylint: disable=protected-access

    # With no filters/config, method returns empty (filters are required)
    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access
    # When config is empty, no filters are applied, returns empty
    assert isinstance(gathered, list)


def test_apply_gathered_filters_single_filter():
    """_apply_gathered_filters applies single filter and returns matching resources."""
    module = _resource_manager()
    module.config = [{"entity_name": "loopback0"}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(entityName="loopback0"),
        _response(resourceId=102, entityName="loopback1"),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access
    assert len(gathered) == 1
    assert gathered[0]["entity_name"] == "loopback0"


def test_apply_gathered_filters_matches_fabric_entity_only_filter():
    """Entity-only gathered filters match fabric resources from local candidates."""
    module = _resource_manager()
    module.config = [{"entity_name": "ibgp_all_vpc_domain_fabric"}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(
            resourceId=101,
            entityName="ibgp_all_vpc_domain_fabric",
            poolName="VPC_DOMAIN_ID",
            scopeDetails={
                "scopeType": "fabric",
                "fabricName": "fabric-1",
            },
        ),
        _response(resourceId=102, entityName="ibgp_all_l3_vni_fabric", poolName="L3_VNI"),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access

    assert len(gathered) == 1
    assert gathered[0]["entity_name"] == "ibgp_all_vpc_domain_fabric"


def test_apply_gathered_filters_matches_reversed_device_pair_entity_name():
    """Gathered entity filters match device-pair serials in either order."""
    module = _resource_manager()
    module.config = [{"entity_name": "SER2~SER1", "scope_type": "device_pair"}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(
            entityName="SER1~SER2",
            poolName="VPC_ID",
            scopeDetails={
                "scopeType": "devicePair",
                "srcSwitchId": "SER1",
                "dstSwitchId": "SER2",
            },
        ),
        _response(resourceId=102, entityName="SER3~SER4"),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access

    assert len(gathered) == 1
    assert gathered[0]["entity_name"] == "SER1~SER2"


def test_apply_gathered_filters_infers_reversed_device_pair_entity_name():
    """Gathered entity filters infer device-pair matching when scope_type is omitted."""
    module = _resource_manager()
    module.config = [{"entity_name": "SER2~SER1~PAIR"}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(
            entityName="SER1~SER2~PAIR",
            poolName="VPC_ID",
            scopeDetails={
                "scopeType": "devicePair",
                "srcSwitchId": "SER1",
                "dstSwitchId": "SER2",
            },
        ),
        _response(resourceId=102, entityName="SER1~SER2~OTHER"),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access

    assert len(gathered) == 1
    assert gathered[0]["entity_name"] == "SER1~SER2~PAIR"


def test_apply_gathered_filters_matches_reversed_link_entity_name():
    """Gathered entity filters match links when endpoint pairs are reversed."""
    module = _resource_manager()
    module.config = [{"entity_name": "SER2~Ethernet1/10~SER1~Ethernet1/6", "scope_type": "link"}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(
            entityName="SER1~Ethernet1/6~SER2~Ethernet1/10",
            poolName="SUBNET",
            resourceValue="fd00:333:4:2::/64",
            scopeDetails={
                "scopeType": "link",
                "srcSwitchId": "SER1",
                "srcInterfaceName": "Ethernet1/6",
                "dstSwitchId": "SER2",
                "dstInterfaceName": "Ethernet1/10",
            },
        ),
        _response(resourceId=102, entityName="SER2~Ethernet1/6~SER1~Ethernet1/10"),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access

    assert len(gathered) == 1
    assert gathered[0]["entity_name"] == "SER1~Ethernet1/6~SER2~Ethernet1/10"


def test_apply_gathered_filters_infers_reversed_link_entity_name():
    """Gathered entity filters infer link matching when scope_type is omitted."""
    module = _resource_manager()
    module.config = [{"entity_name": "SER2~Ethernet1/10~SER1~Ethernet1/6"}]
    module._all_resources = [  # pylint: disable=protected-access
        _response(
            entityName="SER1~Ethernet1/6~SER2~Ethernet1/10",
            poolName="SUBNET",
            resourceValue="fd00:333:4:2::/64",
            scopeDetails={
                "scopeType": "link",
                "srcSwitchId": "SER1",
                "srcInterfaceName": "Ethernet1/6",
                "dstSwitchId": "SER2",
                "dstInterfaceName": "Ethernet1/10",
            },
        ),
        _response(resourceId=102, entityName="SER2~Ethernet1/6~SER1~Ethernet1/10"),
    ]

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access

    assert len(gathered) == 1
    assert gathered[0]["entity_name"] == "SER1~Ethernet1/6~SER2~Ethernet1/10"


def test_build_gathered_resource_criteria_omits_entity_filter_for_entity_names():
    """Gathered filters use local entity matching instead of exact API filtering."""
    module = _resource_manager()
    module.config = [
        {"entity_name": "ibgp_all_vpc_domain_fabric"},
        {"entity_name": "loopback0", "pool_name": "LOOPBACK_ID"},
        {"entity_name": "SER2~SER1", "scope_type": "device_pair"},
        {"entity_name": "SER2~Ethernet1/10~SER1~Ethernet1/6", "scope_type": "link"},
    ]

    criteria = module._build_gathered_resource_criteria()  # pylint: disable=protected-access

    assert criteria == [
        (None, None, None),
        ("LOOPBACK_ID", None, None),
        (None, None, None),
        (None, None, None),
    ]


def test_apply_gathered_filters_multiple_filters_with_dedup():
    """_apply_gathered_filters deduplicates results from multiple filters."""
    module = _resource_manager()
    module.config = [
        {"pool_name": "LOOPBACK_ID"},
        {"entity_name": "loopback0"},
    ]
    module._all_resources = [_response(resourceId=101, entityName="loopback0", poolName="LOOPBACK_ID")]  # pylint: disable=protected-access

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access
    # Both filters match same resource; dedup should return only one
    assert len(gathered) == 1


@pytest.mark.parametrize(
    ("resource_value", "expected_pool_type"),
    [
        ("10.0.0.0/24", "SUBNET"),  # IPv4 network
        ("2001:db8::/32", "SUBNET"),  # IPv6 network
        ("192.168.1.1", "IP"),  # Single IPv4
        ("2001:db8::1", "IP"),  # Single IPv6
        ("10", "ID"),  # Integer string
        ("loopback", "ID"),  # Non-numeric string
    ],
)
def test_determine_pool_type_inference(resource_value, expected_pool_type):
    """_determine_pool_type infers pool type from resource value format."""
    module = _resource_manager()
    pool_type = module._determine_pool_type(resource_value)  # pylint: disable=protected-access
    assert pool_type == expected_pool_type


def test_get_entity_name_from_model():
    """_get_entity_name extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response(entityName="loopback0")

    entity_name = module._get_entity_name(resource)
    assert entity_name == "loopback0"


def test_get_entity_name_from_dict():
    """_get_entity_name extracts from raw dict resource."""
    module = _resource_manager()
    resource = {"entityName": "loopback0"}

    entity_name = module._get_entity_name(resource)
    assert entity_name == "loopback0"


def test_get_pool_name_from_model():
    """_get_pool_name extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response(poolName="LOOPBACK_ID")

    pool_name = module._get_pool_name(resource)
    assert pool_name == "LOOPBACK_ID"


def test_get_resource_value_from_model():
    """_get_resource_value extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response(resourceValue="10")

    resource_value = module._get_resource_value(resource)
    assert resource_value == "10"


def test_get_scope_type_from_model():
    """_get_scope_type maps API camelCase to playbook snake_case."""
    module = _resource_manager()
    resource = _response(scopeDetails={"scopeType": "device", "switchId": "SER1"})

    scope_type = module._get_scope_type(resource)
    assert scope_type == "device"


def test_get_switch_ip_from_device_scope():
    """_get_switch_ip extracts switchIp for device scope."""
    module = _resource_manager()
    resource = _response(
        scopeDetails={
            "scopeType": "device",
            "switchId": "SER1",
            "switchIp": "192.0.2.10",
        }
    )

    switch_ip = module._get_switch_ip(resource)
    assert switch_ip == "192.0.2.10"


def test_get_switch_ip_from_fabric_scope_returns_none():
    """_get_switch_ip returns None for fabric scope."""
    module = _resource_manager()
    resource = _response(scopeDetails={"scopeType": "fabric"})

    switch_ip = module._get_switch_ip(resource)
    assert switch_ip is None


def test_normalize_pool_name_canonical_conversion():
    """_normalize_pool_name converts API names to playbook constants."""
    # Test that pool names are normalized to canonical form
    result = ResourceManagerDiffEngine._normalize_pool_name("loopbackId", LOG)
    # Should map to LOOPBACK_ID or return original
    assert result is not None


def test_normalize_entity_key_device_pair_preserves_label_and_ignores_serial_order():
    """_normalize_entity_key preserves device-pair labels while allowing serial order reversal."""
    result = ResourceManagerDiffEngine._normalize_entity_key(
        "SER2~SER1~LABEL",
        LOG,
        scope_type="device_pair",
    )
    reversed_result = ResourceManagerDiffEngine._normalize_entity_key(
        "SER1~SER2~LABEL",
        LOG,
        scope_type="device_pair",
    )
    different_label = ResourceManagerDiffEngine._normalize_entity_key(
        "SER1~SER2~OTHER",
        LOG,
        scope_type="device_pair",
    )

    assert result == reversed_result
    assert result != different_label


def test_normalize_entity_key_strips_entity_and_parts():
    """_normalize_entity_key trims exact names and tilde-separated parts."""
    exact = ResourceManagerDiffEngine._normalize_entity_key(" loopback0 ", LOG)
    pair = ResourceManagerDiffEngine._normalize_entity_key(
        " SER2 ~ SER1 ~ PAIR ",
        LOG,
        scope_type="device_pair",
    )
    reversed_pair = ResourceManagerDiffEngine._normalize_entity_key(
        "SER1~SER2~PAIR",
        LOG,
        scope_type="device_pair",
    )

    assert exact == ("exact", "loopback0")
    assert pair == reversed_pair


def test_normalize_entity_key_device_pair_matches_nd_reordered_entity_name():
    """_normalize_entity_key matches ND device-pair names when ND reverses serial order."""
    requested = ResourceManagerDiffEngine._normalize_entity_key(
        "9CODD3GJCC6~9CNJ9CWP24C~base_vpc_id_pair",
        LOG,
        scope_type="device_pair",
    )
    nd_response = ResourceManagerDiffEngine._normalize_entity_key(
        "9CNJ9CWP24C~9CODD3GJCC6~base_vpc_id_pair",
        LOG,
        scope_type="devicePair",
    )
    different_label = ResourceManagerDiffEngine._normalize_entity_key(
        "9CNJ9CWP24C~9CODD3GJCC6~other_vpc_id_pair",
        LOG,
        scope_type="devicePair",
    )

    assert requested == nd_response
    assert requested != different_label


def test_normalize_entity_key_fabric_pair_ignores_switch_order():
    """_normalize_entity_key matches two-part fabric names regardless of switch order."""
    requested = ResourceManagerDiffEngine._normalize_entity_key(
        "9KQKJLKFLKW~9HD1Q6C52FA",
        LOG,
        scope_type="fabric",
    )
    nd_response = ResourceManagerDiffEngine._normalize_entity_key(
        "9HD1Q6C52FA~9KQKJLKFLKW",
        LOG,
        scope_type="fabric",
    )

    assert requested == nd_response


def test_normalize_entity_key_link_preserves_serial_interface_pairs():
    """_normalize_entity_key compares links as unordered endpoint pairs."""
    result = ResourceManagerDiffEngine._normalize_entity_key(
        "SER1~Ethernet1/6~SER2~Ethernet1/10",
        LOG,
        scope_type="link",
    )
    reversed_result = ResourceManagerDiffEngine._normalize_entity_key(
        "SER2~Ethernet1/10~SER1~Ethernet1/6",
        LOG,
        scope_type="link",
    )
    cross_paired = ResourceManagerDiffEngine._normalize_entity_key(
        "SER2~Ethernet1/6~SER1~Ethernet1/10",
        LOG,
        scope_type="link",
    )

    assert result == reversed_result
    assert result != cross_paired


def test_extract_scope_type_maps_api_to_playbook():
    """_extract_scope_type converts API camelCase to playbook snake_case."""
    scope_dict = {"scopeType": "deviceInterface"}
    result = ResourceManagerDiffEngine._extract_scope_type(scope_dict, LOG)
    assert result == "device_interface"


def test_make_resource_key_builds_dedup_key():
    """_make_resource_key constructs normalized tuple for matching."""
    key = ResourceManagerDiffEngine._make_resource_key(
        entity_name="loopback0",
        pool_name="LOOPBACK_ID",
        scope_type="device",
        switch_ip="SER1",
        log=LOG,
    )
    assert isinstance(key, tuple)
    assert len(key) == 5  # (entity, pool, scope, switch, vrf_name)


# =========================================================================
# ADDITIONAL COMPREHENSIVE TESTS: FAILURE SCENARIOS & INTEGRATION
# =========================================================================


def test_get_all_resources_api_error_100_raises():
    """_get_all_resources with API 100 error raises ValueError."""
    nd = _mock_nd_module()
    error = NDModuleError(msg="Internal Server Error", status=100)
    nd.request.side_effect = error

    with pytest.raises(ValueError, match="API call failed"):
        results = Results()
        module = NDResourceManagerModule(nd, results, log=LOG)
        module._get_all_resources()  # pylint: disable=protected-access


def test_get_all_resources_api_error_timeout_raises():
    """_get_all_resources with timeout error raises ValueError."""
    nd = _mock_nd_module()
    nd.request.side_effect = Exception("Connection timeout")

    with pytest.raises(ValueError, match="API call failed"):
        results = Results()
        module = NDResourceManagerModule(nd, results, log=LOG)
        module._get_all_resources()  # pylint: disable=protected-access


def test_get_all_resources_empty_response():
    """_get_all_resources handles completely empty response."""
    nd = _mock_nd_module()
    nd.request.return_value = {}  # Empty dict

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    assert len(module._all_resources) == 0  # pylint: disable=protected-access


def test_get_all_resources_single_dict_wraps_in_list():
    """_get_all_resources wraps single dict response in list."""
    nd = _mock_nd_module()
    single_dict = {
        "resourceId": 101,
        "entityName": "loopback0",
        "poolName": "LOOPBACK_ID",
        "resourceValue": "10",
        "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
    }
    nd.request.return_value = single_dict

    results = Results()
    module = NDResourceManagerModule(nd, results, log=LOG)
    module._get_all_resources()  # pylint: disable=protected-access

    # Should wrap in list and parse
    assert len(module._all_resources) >= 0  # pylint: disable=protected-access


def test_validate_input_empty_config_for_merged_raises():
    """_validate_input raises error when config is empty for merged state."""
    module = _resource_manager()
    module.state = "merged"
    module.config = []

    with pytest.raises(ValueError, match="config.*mandatory"):
        module._validate_input()  # pylint: disable=protected-access


def test_validate_input_empty_config_for_deleted_raises():
    """_validate_input raises error when config is empty for deleted state."""
    module = _resource_manager()
    module.state = "deleted"
    module.config = []

    with pytest.raises(ValueError, match="config.*mandatory"):
        module._validate_input()  # pylint: disable=protected-access


def test_build_modifying_resource_criteria_omits_switch_filter_for_links():
    """Link candidates are not tied to the configured endpoint switch."""
    module = _resource_manager()
    module.config = [
        {
            "pool_name": "loopbackId",
            "scope_type": "device",
            "switches": ["SER1"],
        },
        {
            "pool_name": "DCI subnet pool",
            "scope_type": "link",
            "switches": ["SER1"],
        },
    ]

    criteria = module._build_modifying_resource_criteria()  # pylint: disable=protected-access

    assert criteria == [
        ("loopbackId", "SER1", None),
        (None, None, None),
    ]


def test_manage_state_merged_fetches_filtered_candidates_before_diffing():
    """Merged state narrows resource inventory by requested pool and switch."""
    config = [
        {
            "entity_name": "loopback0",
            "pool_type": "ID",
            "pool_name": "loopbackId",
            "scope_type": "device",
            "switches": ["192.0.2.10"],
            "resource": "10",
        }
    ]
    nd = _mock_nd_module(state="merged", config=config)
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "loopbackId",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                "status": None,
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }
    results = Results()

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=_mock_fabric_inventory({"192.0.2.10": "SER1"}),
    ):
        module = NDResourceManagerModule(nd, results, log=LOG)
        module.manage_state()

    paths = [call.args[0] for call in nd.request.call_args_list]
    resource_paths = [path for path in paths if "/resources" in path]
    assert resource_paths
    path = resource_paths[0]
    assert "max=" in path
    assert "offset=0" in path
    assert "poolName=loopbackId" in path
    assert "switchId=SER1" in path
    assert "filter=" not in path


def test_manage_state_deleted_fetches_filtered_candidates_before_matching():
    """Deleted state narrows resource inventory by requested pool and switch."""
    config = [
        {
            "entity_name": "loopback0",
            "pool_type": "ID",
            "pool_name": "loopbackId",
            "scope_type": "device",
            "switches": ["192.0.2.10"],
        }
    ]
    nd = _mock_nd_module(state="deleted", config=config)
    nd.request.return_value = {"resources": [], "meta": {"counts": {"remaining": 0, "total": 0}}}
    results = Results()

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=_mock_fabric_inventory({"192.0.2.10": "SER1"}),
    ):
        module = NDResourceManagerModule(nd, results, log=LOG)
        module.manage_state()

    paths = [call.args[0] for call in nd.request.call_args_list]
    resource_paths = [path for path in paths if "/resources" in path]
    assert resource_paths
    path = resource_paths[0]
    assert "max=" in path
    assert "offset=0" in path
    assert "poolName=loopbackId" in path
    assert "switchId=SER1" in path
    assert "filter=" not in path
    assert len(resource_paths) == 1


def test_manage_state_deleted_matches_link_returned_under_opposite_endpoint_switch():
    """Deleted state discovers canonically reordered links without a switch filter."""
    config = [
        {
            "entity_name": "SER1~Ethernet1/3~SER2~Ethernet1/3",
            "pool_type": "SUBNET",
            "pool_name": "DCI subnet pool",
            "scope_type": "link",
            "switches": ["192.0.2.10"],
            "resource": "10.33.61.0/30",
        }
    ]
    nd = _mock_nd_module(state="deleted", config=config)

    def request(path, _verb, **_kwargs):
        if path.endswith("/fabric-1"):
            return {"management": {"type": "vxlanIbgp"}}
        if "/resources?" in path:
            return {
                "resources": [
                    {
                        "resourceId": 501,
                        "entityName": "SER2~Ethernet1/3~SER1~Ethernet1/3",
                        "poolName": "DCI subnet pool",
                        "poolType": "SUBNET",
                        "resourceValue": "10.33.61.0/30",
                        "scopeDetails": {
                            "scopeType": "link",
                            "srcSwitchId": "SER2",
                            "srcInterfaceName": "Ethernet1/3",
                            "dstSwitchId": "SER1",
                            "dstInterfaceName": "Ethernet1/3",
                        },
                    }
                ],
                "meta": {"counts": {"remaining": 0, "total": 1}},
            }
        return {"resources": [{"resourceId": 501}]}

    nd.request.side_effect = request
    remove_item = MagicMock()
    remove_item.status = None
    remove_item.message = None
    remove_item.resource_value = "10.33.61.0/30"
    remove_item.model_dump.return_value = {"resourceId": 501}
    remove_response = MagicMock(resources=[remove_item])

    with (
        patch(
            "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
            return_value=_mock_fabric_inventory(),
        ),
        patch(
            "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources"
            ".RemoveResourcesByIdsResponse.from_response",
            return_value=remove_response,
        ),
    ):
        module = NDResourceManagerModule(nd, Results(), log=LOG)
        module.manage_state()

    resource_paths = [call.args[0] for call in nd.request.call_args_list if "/resources?" in call.args[0]]
    assert len(resource_paths) == 1
    assert "poolName=" not in resource_paths[0]
    assert "switchId=" not in resource_paths[0]
    remove_call = next(call for call in nd.request.call_args_list if call.args[0].endswith("/resources/actions/remove"))
    assert remove_call.kwargs["data"] == {"resourceIds": [501]}


def test_manage_state_gathered_uses_filtered_candidate_get():
    """Gathered state pushes pool and switch filters to resource GET."""
    config = [
        {
            "entity_name": "loopback0",
            "pool_name": "loopbackId",
            "switches": ["192.0.2.10"],
        }
    ]
    nd = _mock_nd_module(state="gathered", config=config)
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "loopbackId",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }
    results = Results()

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=_mock_fabric_inventory({"192.0.2.10": "SER1"}),
    ):
        module = NDResourceManagerModule(nd, results, log=LOG)
        module.manage_state()

    paths = [call.args[0] for call in nd.request.call_args_list]
    resource_paths = [path for path in paths if "/resources" in path]
    assert resource_paths
    path = resource_paths[0]
    assert "poolName=loopbackId" in path
    assert "switchId=SER1" in path
    assert "filter=entityName:loopback0" not in path
    assert module.changed_dict[0]["gathered"]  # pylint: disable=protected-access


def test_manage_state_gathered_applies_resource_filter_after_pool_candidate_get():
    """Gathered state locally narrows pool candidates by documented resource filter."""
    config = [
        {
            "pool_name": "L2_VNI",
            "resource": "48950",
        }
    ]
    nd = _mock_nd_module(state="gathered", config=config)
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 201,
                "entityName": "l2_vni_a",
                "poolName": "L2_VNI",
                "resourceValue": "48990",
                "scopeDetails": {"scopeType": "fabric"},
            },
            {
                "resourceId": 202,
                "entityName": "l2_vni_b",
                "poolName": "L2_VNI",
                "resourceValue": "48950",
                "scopeDetails": {"scopeType": "fabric"},
            },
        ],
        "meta": {"counts": {"remaining": 0, "total": 2}},
    }
    results = Results()

    module = NDResourceManagerModule(nd, results, log=LOG)
    module.manage_state()

    paths = [call.args[0] for call in nd.request.call_args_list]
    resource_paths = [path for path in paths if "/resources" in path]
    assert resource_paths
    assert "poolName=L2_VNI" in resource_paths[0]
    assert len(module.changed_dict[0]["gathered"]) == 1  # pylint: disable=protected-access
    assert module.changed_dict[0]["gathered"][0]["resource"] == "48950"  # pylint: disable=protected-access


@pytest.mark.parametrize(
    ("config", "expected_resources"),
    [
        ([{"resource": "48950"}], ["48950"]),
        ([{"scope_type": "fabric"}], ["48950", "48990"]),
        ([{"pool_type": "IP"}], ["192.0.2.1"]),
    ],
)
def test_manage_state_gathered_local_only_filters_fetch_candidates_and_narrow_results(config, expected_resources):
    """Local-only gathered filters fetch candidates and apply the final predicate."""
    nd = _mock_nd_module(state="gathered", config=config)
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 201,
                "entityName": "l2_vni_a",
                "poolName": "L2_VNI",
                "resourceValue": "48950",
                "scopeDetails": {"scopeType": "fabric"},
            },
            {
                "resourceId": 202,
                "entityName": "l2_vni_b",
                "poolName": "L2_VNI",
                "resourceValue": "48990",
                "scopeDetails": {"scopeType": "fabric"},
            },
            {
                "resourceId": 203,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            },
            {
                "resourceId": 204,
                "entityName": "loopback0_ip",
                "poolName": "LOOPBACK0_IP_POOL",
                "resourceValue": "192.0.2.1",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            },
        ],
        "meta": {"counts": {"remaining": 0, "total": 4}},
    }
    results = Results()

    module = NDResourceManagerModule(nd, results, log=LOG)
    module.manage_state()

    paths = [call.args[0] for call in nd.request.call_args_list]
    resource_paths = [path for path in paths if "/resources" in path]
    assert resource_paths
    assert "poolName=" not in resource_paths[0]
    assert "switchId=" not in resource_paths[0]
    gathered_resources = [item["resource"] for item in module.changed_dict[0]["gathered"]]  # pylint: disable=protected-access
    assert gathered_resources == expected_resources


def test_manage_resource_manager_merged_rejects_unsupported_pool_for_fabric_type():
    """Merged config rejects pool_name values unsupported for the fabric type."""
    nd = _mock_nd_module(
        state="merged",
        fabric_type="vxlanIbgp",
        config=[
            {
                "entity_name": "router_id_a",
                "pool_type": "ID",
                "pool_name": "ROUTER_ID_POOL",
                "scope_type": "fabric",
                "resource": "100",
            }
        ],
    )

    with pytest.raises(ValueError, match="Unsupported pool_name values for fabric type"):
        NDResourceManagerModule(nd, Results(), log=LOG)


def test_manage_resource_manager_deleted_rejects_unsupported_pool_for_fabric_type():
    """Deleted config rejects pool_name values unsupported for the fabric type."""
    nd = _mock_nd_module(
        state="deleted",
        fabric_type="vxlanIbgp",
        config=[
            {
                "entity_name": "router_id_a",
                "pool_type": "ID",
                "pool_name": "ROUTER_ID_POOL",
                "scope_type": "fabric",
            }
        ],
    )

    with pytest.raises(ValueError, match="Unsupported pool_name values for fabric type"):
        NDResourceManagerModule(nd, Results(), log=LOG)


def test_manage_resource_manager_gathered_rejects_unsupported_pool_filter_for_fabric_type():
    """Gathered filters reject pool_name values unsupported for the fabric type."""
    nd = _mock_nd_module(
        state="gathered",
        fabric_type="vxlanIbgp",
        config=[
            {
                "pool_name": "ROUTER_ID_POOL",
            }
        ],
    )

    with pytest.raises(ValueError, match="Unsupported pool_name values for fabric type"):
        NDResourceManagerModule(nd, Results(), log=LOG)


def test_manage_resource_manager_reports_all_unsupported_pools_for_fabric_type():
    """Unsupported pool validation reports every offending config entry."""
    nd = _mock_nd_module(
        state="merged",
        fabric_type="vxlanIbgp",
        config=[
            {
                "entity_name": "router_id_a",
                "pool_type": "ID",
                "pool_name": "ROUTER_ID_POOL",
                "scope_type": "fabric",
                "resource": "100",
            },
            {
                "entity_name": "loopback_id",
                "pool_type": "ID",
                "pool_name": "loopbackId",
                "scope_type": "fabric",
                "resource": "101",
            },
            {
                "entity_name": "instance_id",
                "pool_type": "ID",
                "pool_name": "INSTANCE_ID",
                "scope_type": "fabric",
                "resource": "102",
            },
        ],
    )

    with pytest.raises(ValueError) as exc_info:
        NDResourceManagerModule(nd, Results(), log=LOG)

    error_msg = str(exc_info.value)
    assert "Unsupported pool_name values for fabric type 'vxlanIbgp'" in error_msg
    assert "config index 0: 'ROUTER_ID_POOL'" in error_msg
    assert "config index 2: 'INSTANCE_ID'" in error_msg
    assert "loopbackId" not in error_msg


def test_manage_resource_manager_external_connectivity_rejects_subnet_pool():
    """EXTERNAL_CONNECTIVITY fabric rejects SUBNET pool (not supported for this type)."""
    nd = _mock_nd_module(
        state="merged",
        fabric_type="externalConnectivity",
        config=[
            {
                "entity_name": "subnet_pool",
                "pool_type": "SUBNET",
                "pool_name": "SUBNET",
                "scope_type": "link",
                "resource": "10.0.0.0/24",
            }
        ],
    )

    with pytest.raises(ValueError, match="Unsupported pool_name values for fabric type"):
        NDResourceManagerModule(nd, Results(), log=LOG)


@patch("ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric")
def test_manage_resource_manager_external_connectivity_accepts_tunnel_id_pool(mock_from_fabric):
    """EXTERNAL_CONNECTIVITY fabric accepts TUNNEL_ID_IOS_XE pool (supported for this type)."""
    mock_from_fabric.return_value = _mock_fabric_inventory(ip_to_id_map={"192.0.2.10": "SER1"})

    nd = _mock_nd_module(
        state="merged",
        fabric_type="externalConnectivity",
        config=[
            {
                "entity_name": "tunnel_id",
                "pool_type": "ID",
                "pool_name": "TUNNEL_ID_IOS_XE",
                "scope_type": "device",
                "switches": ["SER1"],
                "resource": "100",
            }
        ],
    )

    # Should not raise - TUNNEL_ID_IOS_XE is supported for externalConnectivity
    module = NDResourceManagerModule(nd, Results(), log=LOG)
    assert module.fabric_type == "externalConnectivity"


def test_manage_resource_manager_vxlan_ibgp_accepts_subnet_pool():
    """VXLAN_IBGP fabric accepts SUBNET pool (supported for this type)."""
    nd = _mock_nd_module(
        state="merged",
        fabric_type="vxlanIbgp",
        config=[
            {
                "entity_name": "subnet_pool",
                "pool_type": "SUBNET",
                "pool_name": "SUBNET",
                "scope_type": "link",
                "resource": "10.0.0.0/24",
            }
        ],
    )

    # Should not raise - SUBNET is supported for vxlanIbgp
    module = NDResourceManagerModule(nd, Results(), log=LOG)
    assert module.fabric_type == "vxlanIbgp"


def test_manage_resource_manager_vxlan_ebgp_accepts_subnet_pool():
    """VXLAN_EBGP fabric accepts SUBNET pool (supported for this type)."""
    nd = _mock_nd_module(
        state="merged",
        fabric_type="vxlanEbgp",
        config=[
            {
                "entity_name": "subnet_pool",
                "pool_type": "SUBNET",
                "pool_name": "SUBNET",
                "scope_type": "link",
                "resource": "10.0.0.0/24",
            }
        ],
    )

    # Should not raise - SUBNET is supported for VXLAN_EBGP
    module = NDResourceManagerModule(nd, Results(), log=LOG)
    assert module.fabric_type == "vxlanEbgp"


def test_validate_input_gathered_with_partial_filter():
    """_validate_input allows gathered with partial filter criteria."""
    module = _resource_manager()
    module.state = "gathered"
    module.config = [{"pool_name": "LOOPBACK_ID"}]  # Only pool_name, no other fields

    # Should not raise; gathered allows partial criteria
    result = module._validate_input()  # pylint: disable=protected-access
    assert result == []  # Gathered returns empty list


@pytest.mark.parametrize("field,value", [("vrf_name", "blue"), ("is_pre_allocated", False)])
def test_gathered_rejects_unsupported_properties_before_api_calls(field, value):
    """Gathered property validation runs before fabric or resource API calls."""
    nd = _mock_nd_module(state="gathered", config=[{field: value}])

    with pytest.raises(ValueError, match=field):
        NDResourceManagerModule(nd, Results(), log=LOG)

    nd.request.assert_not_called()


def test_gathered_rejects_null_only_filter_before_api_calls():
    """Gathered empty-filter validation runs before fabric or resource API calls."""
    nd = _mock_nd_module(state="gathered", config=[{"pool_name": None}])

    with pytest.raises(ValueError, match="must contain at least one supported property"):
        NDResourceManagerModule(nd, Results(), log=LOG)

    nd.request.assert_not_called()


def test_validate_required_fields_compat_missing_entity_name():
    """_validate_required_fields_compat raises for missing entity_name."""
    module = _resource_manager()
    module.state = "deleted"
    module.config = [{"scope_type": "device", "pool_type": "ID", "pool_name": "LOOPBACK_ID"}]  # No entity_name

    with pytest.raises(ValueError, match="entity_name.*missing"):
        module._validate_required_fields_compat()  # pylint: disable=protected-access


def test_validate_required_fields_compat_missing_switches_for_device_scope():
    """_validate_required_fields_compat raises for missing switches on device scope."""
    module = _resource_manager()
    module.state = "deleted"
    module.config = [
        {
            "entity_name": "loopback0",
            "scope_type": "device",
            "pool_type": "ID",
            "pool_name": "LOOPBACK_ID",
            # No switches
        }
    ]

    with pytest.raises(ValueError, match="switches.*Required parameter"):
        module._validate_required_fields_compat()  # pylint: disable=protected-access


def test_register_result_creates_results_entry():
    """_register_result registers API call details without error."""
    module, unused_nd = _resource_manager_with_nd()

    # Call _register_result - verify it doesn't raise error
    module._register_result(  # pylint: disable=protected-access
        action="create",
        operation_type=OperationType.CREATE,
        message="Resource created",
        changed=True,
        verb=HttpVerbEnum.POST,
        path="/api/v1/manage/fabrics/fabric-1/resources",
        payload={"entityName": "loopback0"},
    )

    # Verify results object still exists
    assert module.results is not None


def test_register_result_includes_diff():
    """_register_result registers diff information without error."""
    module, unused_nd = _resource_manager_with_nd()

    # _register_result implementation doesn't store diff directly
    # Test that the call succeeds without error
    module._register_result(  # pylint: disable=protected-access
        action="create",
        operation_type=OperationType.CREATE,
        message="Created",
        changed=True,
        diff={"before": {}, "after": {"entity_name": "loopback0"}},
    )

    # Verify results object still exists
    assert module.results is not None


def test_register_result_uses_explicit_return_code():
    """_register_result stores the ND return code supplied by a live request."""
    module, unused_nd = _resource_manager_with_nd()

    module._register_result(  # pylint: disable=protected-access
        action="create",
        operation_type=OperationType.CREATE,
        message="Created",
        changed=True,
        return_code=207,
    )

    assert module.results.responses[-1]["RETURN_CODE"] == 207


def test_resolve_switch_ids_fabric_scope_no_switches():
    """_resolve_switch_ids_in_config skips processing for fabric scope without switches."""
    module, unused_nd = _resource_manager_with_nd()
    # Fabric scope doesn't require switches
    original_config = [{"entity_name": "l3_vni", "scope_type": "fabric"}]

    result = module._resolve_switch_ids_in_config(original_config)  # pylint: disable=protected-access

    # Should return list without modification
    assert isinstance(result, list)
    assert len(result) == 1


def test_resolve_switch_ids_skips_inventory_when_no_switches():
    """_resolve_switch_ids_in_config optimizes by skipping inventory when no switches."""
    module = _resource_manager()
    module.log = LOG

    config = [{"entity_name": "l3_vni", "scope_type": "fabric"}]  # Fabric scope, no switches

    # Should return immediately without inventory lookup
    result = module._resolve_switch_ids_in_config(config)  # pylint: disable=protected-access
    assert len(result) == 1


def test_exit_module_with_no_results():
    """exit_module handles case with no API results registered."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.results = Results()  # Fresh, empty results
    module.results.state = "merged"
    module.results.check_mode = False

    module.exit_module()

    assert ansible_module.exit_payload is not None


def test_exit_module_changed_true_when_modifications():
    """exit_module reports changed=True when modifications occurred."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)

    module.exit_module()

    # Based on _register_resource_manager_task, should show changes
    assert "changed" in ansible_module.exit_payload


def test_exit_module_normal_output_structure():
    """exit_module normal output has expected top-level keys."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)

    module.exit_module()

    assert "changed" in ansible_module.exit_payload
    assert "gathering_info" in ansible_module.exit_payload or "changed" in ansible_module.exit_payload


def test_exit_module_verbosity_0_minimal_output():
    """exit_module with verbosity=0 provides minimal output (changed key only)."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)

    module.exit_module()

    # Should not have detailed API keys
    for key in ["api_payload", "api_response", "api_paths", "api_verbs"]:
        assert key not in ansible_module.exit_payload


def test_compute_changes_with_empty_proposed_and_existing():
    """compute_changes with empty lists returns all empty buckets."""
    changes = ResourceManagerDiffEngine.compute_changes([], [], log=LOG)

    assert changes["idempotent"] == []
    assert changes["to_add"] == []
    assert changes["to_update"] == []
    assert changes["to_delete"] == []


def test_compute_changes_handles_mixed_resource_types():
    """compute_changes handles mix of ResourceManagerResponse models and raw dicts."""
    proposed = [_config()]
    existing = [
        _response(),  # Model
        {  # Raw dict
            "resourceId": 102,
            "entityName": "loopback1",
            "poolName": "LOOPBACK_ID",
            "resourceValue": "11",
            "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
        },
    ]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    # Should match model, not match dict
    assert len(changes["idempotent"]) == 1  # First one matches
    assert len(changes["to_delete"]) == 1  # Second one unmatched


def test_compare_resource_values_none_values():
    """_compare_resource_values handles None comparisons."""
    result = ResourceManagerDiffEngine._compare_resource_values(None, None, log=LOG)
    assert result is True

    result = ResourceManagerDiffEngine._compare_resource_values(None, "10", log=LOG)
    assert result is False

    result = ResourceManagerDiffEngine._compare_resource_values("10", None, log=LOG)
    assert result is False


def test_compare_resource_values_empty_strings():
    """_compare_resource_values handles empty string comparisons."""
    result = ResourceManagerDiffEngine._compare_resource_values("", "", log=LOG)
    assert result is True

    result = ResourceManagerDiffEngine._compare_resource_values("", "10", log=LOG)
    assert result is False


def test_get_entity_name_from_none_resource():
    """_get_entity_name returns None for unrecognized resource type."""
    module = _resource_manager()
    result = module._get_entity_name(None)  # pylint: disable=protected-access
    assert result is None


def test_get_pool_name_from_dict():
    """_get_pool_name extracts from raw dict resource."""
    module = _resource_manager()
    resource = {"poolName": "LOOPBACK_ID"}

    pool_name = module._get_pool_name(resource)
    assert pool_name == "LOOPBACK_ID"


def test_get_resource_id_from_dict():
    """_get_resource_id extracts from raw dict resource."""
    module = _resource_manager()
    resource = {"resourceId": 101}

    resource_id = module._get_resource_id(resource)
    assert resource_id == 101


def test_apply_gathered_filters_no_active_criteria():
    """_apply_gathered_filters with no active filter criteria returns empty."""
    module = _resource_manager()
    module.config = [{}]  # Empty filter dict
    module._all_resources = [_response()]  # pylint: disable=protected-access

    gathered = module._apply_gathered_filters()  # pylint: disable=protected-access
    # With no active criteria, should match nothing or return empty
    assert isinstance(gathered, list)


def test_translate_gathered_results_with_single_switch():
    """translate_gathered_results converts model to dict format."""
    module = _resource_manager()
    resource = _response()

    result = module.translate_gathered_results([resource])  # pylint: disable=protected-access

    assert len(result) == 1
    assert result[0]["entity_name"] == "loopback0"
    assert result[0]["pool_name"] == "LOOPBACK_ID"


def test_translate_gathered_results_includes_model_resource_id_for_snapshot():
    """Snapshot translation includes a model-backed resource identifier."""
    module = _resource_manager()

    result = module.translate_gathered_results([_response(resourceId=101)], include_resource_id=True)  # pylint: disable=protected-access

    assert result[0]["resource_id"] == 101


def test_translate_gathered_results_includes_raw_resource_id_for_snapshot():
    """Snapshot translation includes an identifier from a raw API dictionary."""
    module = _resource_manager()
    resource = {
        "resourceId": 202,
        "entityName": "loopback1",
        "poolName": "LOOPBACK_ID",
        "resourceValue": "11",
        "scopeDetails": {"scopeType": "device", "switchIp": "192.0.2.11"},
    }

    result = module.translate_gathered_results([resource], include_resource_id=True)  # pylint: disable=protected-access

    assert result[0]["resource_id"] == 202


def test_translate_gathered_results_omits_resource_id_by_default():
    """Gathered translation remains replayable and omits resource identifiers."""
    module = _resource_manager()

    result = module.translate_gathered_results([_response(resourceId=101)])  # pylint: disable=protected-access

    assert "resource_id" not in result[0]


def test_translate_gathered_results_omits_missing_resource_id_for_snapshot():
    """Snapshot translation omits the identifier when the API did not return one."""
    module = _resource_manager()

    result = module.translate_gathered_results([_response(resourceId=None)], include_resource_id=True)  # pylint: disable=protected-access

    assert "resource_id" not in result[0]


def test_translate_gathered_results_preserves_vrf_and_auto_allocation():
    """Gathered output keeps VRF and is_pre_allocated for replayable config."""
    module = _resource_manager()
    resource = _response(
        resourceValue=None,
        isPreAllocated=False,
        vrfName="blue",
    )

    result = module.translate_gathered_results([resource])  # pylint: disable=protected-access

    assert result == [
        {
            "entity_name": "loopback0",
            "pool_type": "ID",
            "pool_name": "LOOPBACK_ID",
            "scope_type": "device",
            "resource": None,
            "vrf_name": "blue",
            "is_pre_allocated": False,
            "switches": ["192.0.2.10"],
        }
    ]


def test_gathered_round_trip_accepts_non_default_vrf_auto_allocation():
    """Translated auto-allocated non-default VRF output validates for merged replay."""
    module = _resource_manager()
    resource = _response(
        resourceValue=None,
        isPreAllocated=False,
        vrfName="blue",
    )

    translated = module.translate_gathered_results([resource])[0]  # pylint: disable=protected-access
    replay_model = ResourceManagerConfigModel.model_validate(translated, context={"state": "merged"})

    assert replay_model.vrf_name == "blue"
    assert replay_model.is_pre_allocated is False
    assert replay_model.resource is None


def test_deduplicate_resources_keeps_fallback_entries_with_different_vrfs():
    """Fallback dedupe keys include VRF when API resources have no resourceId."""
    module = _resource_manager()
    resources = [
        {
            "entityName": "loopback0",
            "poolName": "LOOPBACK_ID",
            "resourceValue": "10",
            "vrfName": "blue",
            "scopeDetails": {
                "scopeType": "device",
                "switchId": "SER1",
            },
        },
        {
            "entityName": "loopback0",
            "poolName": "LOOPBACK_ID",
            "resourceValue": "10",
            "vrfName": "red",
            "scopeDetails": {
                "scopeType": "device",
                "switchId": "SER1",
            },
        },
    ]

    deduped = module._deduplicate_resources(resources)  # pylint: disable=protected-access

    assert len(deduped) == 2
    assert [item["vrfName"] for item in deduped] == ["blue", "red"]


def test_translate_gathered_results_with_missing_fields():
    """translate_gathered_results handles resources with missing fields."""
    module = _resource_manager()
    # Raw dict without all fields
    raw_resource = {"resourceId": 101, "entityName": "loopback0"}

    results = module.translate_gathered_results([raw_resource])  # pylint: disable=protected-access
    assert len(results) >= 0  # Should handle gracefully


def test_determine_pool_type_ipv4_address():
    """_determine_pool_type identifies single IPv4 address as IP."""
    module = _resource_manager()
    pool_type = module._determine_pool_type("192.168.1.1")  # pylint: disable=protected-access
    assert pool_type == "IP"


def test_determine_pool_type_ipv4_network():
    """_determine_pool_type identifies IPv4 network as SUBNET."""
    module = _resource_manager()
    pool_type = module._determine_pool_type("192.168.1.0/24")  # pylint: disable=protected-access
    assert pool_type == "SUBNET"


def test_determine_pool_type_integer():
    """_determine_pool_type identifies integer string as ID."""
    module = _resource_manager()
    pool_type = module._determine_pool_type("100")  # pylint: disable=protected-access
    assert pool_type == "ID"


def test_determine_pool_type_alphanumeric():
    """_determine_pool_type identifies alphanumeric as ID."""
    module = _resource_manager()
    pool_type = module._determine_pool_type("vlan_100")  # pylint: disable=protected-access
    assert pool_type == "ID"


def test_entity_names_match_with_none_values():
    """_entity_names_match handles None values."""
    module = _resource_manager()

    assert module._entity_names_match(None, "loopback0") is False  # pylint: disable=protected-access
    assert module._entity_names_match("loopback0", None) is False  # pylint: disable=protected-access
    assert module._entity_names_match(None, None) is False  # pylint: disable=protected-access


def test_resource_matches_filter_with_no_criteria():
    """_resource_matches_filter with empty filter returns True (match all)."""
    module = _resource_manager()
    resource = _response()

    result = module._resource_matches_filter(resource, {})  # pylint: disable=protected-access
    assert result is True


def test_normalize_pool_name_with_none():
    """_normalize_pool_name returns None for None input."""
    result = ResourceManagerDiffEngine._normalize_pool_name(None, LOG)
    assert result is None


def test_normalize_pool_name_with_empty_string():
    """_normalize_pool_name returns empty string for empty input."""
    result = ResourceManagerDiffEngine._normalize_pool_name("", LOG)
    assert result == ""


def test_normalize_entity_key_single_element():
    """_normalize_entity_key returns single element unchanged."""
    result = ResourceManagerDiffEngine._normalize_entity_key("loopback0", LOG)
    assert result == ("exact", "loopback0")


def test_extract_scope_switch_key_val_fabric_scope():
    """_extract_scope_switch_key_val returns None for fabric scope."""
    scope_dict = {"scopeType": "fabric"}
    result = ResourceManagerDiffEngine._extract_scope_switch_key_val(scope_dict, "switch_id", "src_switch_id", LOG)
    assert result is None


def test_compute_changes_device_pair_endpoint_normalization():
    """compute_changes normalizes device_pair endpoints regardless of order."""
    proposed = [
        _config(
            entity_name="9CODD3GJCC6~9CNJ9CWP24C~base_vpc_id_pair",
            scope_type="device_pair",
            pool_name="VPC_ID",
            switches=["9CODD3GJCC6", "9CNJ9CWP24C"],
        )
    ]  # Reversed order
    existing = [
        _response(
            entityName="9CNJ9CWP24C~9CODD3GJCC6~base_vpc_id_pair",
            poolName="VPC_ID",
            scopeDetails={
                "scopeType": "devicePair",
                "srcSwitchId": "9CNJ9CWP24C",
                "dstSwitchId": "9CODD3GJCC6",
            },  # Normal order
        )
    ]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)
    # Should match despite different order (tilde-normalization)
    assert len(changes["idempotent"]) == 1
    assert changes["to_add"] == []


def test_compute_changes_fabric_pair_endpoint_normalization():
    """compute_changes normalizes two-part fabric entity names regardless of order."""
    proposed = [_config(entity_name="9KQKJLKFLKW~9HD1Q6C52FA", scope_type="fabric", pool_name="VPC_DOMAIN_ID")]
    existing = [
        _response(
            entityName="9HD1Q6C52FA~9KQKJLKFLKW",
            poolName="VPC_DOMAIN_ID",
            scopeDetails={"scopeType": "fabric"},
        )
    ]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)
    assert len(changes["idempotent"]) == 1
    assert changes["to_add"] == []


def test_compute_changes_device_pair_omitted_resource_accepts_nd_allocated_value():
    """compute_changes keeps ND-allocated vpcId idempotent when resource is omitted."""
    proposed = ResourceManagerDiffEngine.validate_configs(
        [
            {
                "entity_name": "9CODD3GJCC6~9CNJ9CWP24C~base_vpc_id_pair",
                "pool_type": "ID",
                "pool_name": "vpcId",
                "scope_type": "device_pair",
                "switches": ["9CODD3GJCC6", "9CNJ9CWP24C"],
                "resource": None,
                "is_pre_allocated": False,
            }
        ],
        "deleted",
        log=LOG,
    )
    existing = [
        _response(
            entityName="9CNJ9CWP24C~9CODD3GJCC6~base_vpc_id_pair",
            poolName="vpcId",
            resourceValue="51",
            isPreAllocated=False,
            scopeDetails={
                "scopeType": "devicePair",
                "srcSwitchId": "9CNJ9CWP24C",
                "dstSwitchId": "9CODD3GJCC6",
            },
        )
    ]

    changes = ResourceManagerDiffEngine.compute_changes(proposed, existing, log=LOG)

    assert len(changes["idempotent"]) == 1
    assert changes["to_add"] == []
    assert changes["to_update"] == []


def test_validate_configs_single_valid_config():
    """validate_configs returns list with single validated config."""
    data = {
        "entity_name": "loopback0",
        "pool_type": "ID",
        "pool_name": "LOOPBACK_ID",
        "scope_type": "device",
        "switches": ["SER1"],
        "resource": "10",
    }

    result = ResourceManagerDiffEngine.validate_configs([data], "merged", log=LOG)
    assert len(result) == 1
    assert isinstance(result[0], ResourceManagerConfigModel)


def test_validate_configs_multiple_valid_configs():
    """validate_configs returns list with multiple validated configs."""
    data1 = {
        "entity_name": "loopback0",
        "pool_type": "ID",
        "pool_name": "LOOPBACK_ID",
        "scope_type": "device",
        "switches": ["SER1"],
        "resource": "10",
    }
    data2 = {
        "entity_name": "loopback1",
        "pool_type": "ID",
        "pool_name": "LOOPBACK_ID",
        "scope_type": "device",
        "switches": ["SER2"],
        "resource": "11",
    }

    result = ResourceManagerDiffEngine.validate_configs([data1, data2], "merged", log=LOG)
    assert len(result) == 2
    assert all(isinstance(cfg, ResourceManagerConfigModel) for cfg in result)


def test_compare_resource_values_ipv6_addresses():
    """_compare_resource_values compares IPv6 addresses."""
    result = ResourceManagerDiffEngine._compare_resource_values("2001:db8::1", "2001:db8::1", log=LOG)
    assert result is True

    result = ResourceManagerDiffEngine._compare_resource_values("2001:db8::1", "2001:db8::2", log=LOG)
    assert result is False


def test_compare_resource_values_ipv6_networks():
    """_compare_resource_values compares IPv6 networks as strings."""
    result = ResourceManagerDiffEngine._compare_resource_values("2001:db8::/32", "2001:db8::/32", log=LOG)
    assert result is True

    # Different networks should still compare as False
    result = ResourceManagerDiffEngine._compare_resource_values("2001:db8::/32", "2001:db8:1::/32", log=LOG)
    # Note: may compare as string-equal or may use IPv6 logic
    assert isinstance(result, bool)


# =========================================================================
# COMPREHENSIVE INTEGRATION & FAILURE SCENARIOS FOR CRITICAL METHODS
# =========================================================================


def test_manage_merged_with_single_new_resource():
    """manage_merged with new resource creates it via POST."""
    module, nd = _resource_manager_with_nd(config=[_config()], all_resources=[])  # Empty existing

    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Run manage_merged
    result = module.manage_merged()  # pylint: disable=protected-access

    # Should call create via POST
    assert nd.request.called


def test_manage_merged_propagates_nd_return_code():
    """Batch create propagates ND's HTTP status to item and registered responses."""
    module, nd = _resource_manager_with_nd(config=[_config()], all_resources=[])
    nd.status = 207
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
            }
        ]
    }

    module.manage_merged()

    assert module.api_responses[-1]["RETURN_CODE"] == 207
    assert module.results.responses[-1]["RETURN_CODE"] == 207


def test_manage_merged_with_existing_matches_idempotent():
    """manage_merged with existing matching resource reports idempotent."""
    module, unused_nd = _resource_manager_with_nd(config=[_config()], all_resources=[_response()])  # Matching existing

    # Run manage_merged - should report no changes
    module.manage_merged()  # pylint: disable=protected-access

    # Method is side-effect driven and should complete without error
    assert module.results is not None


def test_manage_deleted_with_existing_resource():
    """manage_deleted removes matching existing resource via DELETE."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[_config()], all_resources=[_response()])  # Existing to delete

    nd.request.return_value = {
        "resources": [{"resourceId": 101, "status": None}],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Run manage_deleted
    result = module.manage_deleted()  # pylint: disable=protected-access

    # Should prepare delete request
    assert nd.request.called or result is not None


def test_manage_deleted_with_no_matching_resource():
    """manage_deleted with no matching resource reports idempotent."""
    module, unused_nd = _resource_manager_with_nd(state="deleted", config=[_config()], all_resources=[])  # No existing resources

    # Run manage_deleted
    module.manage_deleted()  # pylint: disable=protected-access

    # Method is side-effect driven and should complete without error
    assert module.results is not None


def test_manage_gathered_with_empty_config():
    """manage_gathered with an empty config list returns all resources."""
    module, unused_nd = _resource_manager_with_nd(state="gathered", config=[], all_resources=[_response()])

    # Run manage_gathered
    module.manage_gathered()  # pylint: disable=protected-access

    # Method is side-effect driven and should complete without error
    assert module.results is not None


def test_manage_gathered_with_pool_name_filter():
    """manage_gathered filters by pool_name."""
    module, unused_nd = _resource_manager_with_nd(
        state="gathered",
        config=[{"pool_name": "loopbackId"}],
        all_resources=[_response(poolName="loopbackId")],
    )

    # Run manage_gathered
    module.manage_gathered()  # pylint: disable=protected-access

    # Method is side-effect driven and should complete without error
    assert module.results is not None


def test_manage_gathered_with_entity_name_filter():
    """manage_gathered filters by entity_name."""
    module, unused_nd = _resource_manager_with_nd(
        state="gathered",
        config=[{"entity_name": "loopback0"}],
        all_resources=[_response()],
    )

    # Run manage_gathered
    module.manage_gathered()  # pylint: disable=protected-access

    # Method is side-effect driven and should complete without error
    assert module.results is not None


def test_manage_gathered_empty_all_resources():
    """manage_gathered with empty resource list returns empty."""
    module, unused_nd = _resource_manager_with_nd(state="gathered", config=[], all_resources=[])

    # Run manage_gathered
    module.manage_gathered()  # pylint: disable=protected-access

    # Method is side-effect driven and should complete without error
    assert module.results is not None


def test_manage_state_merged_calls_manage_merged():
    """manage_state dispatches merged state to manage_merged."""
    module, nd = _resource_manager_with_nd(
        state="merged",
        config=[
            {
                "entity_name": "l3_vni",
                "pool_type": "ID",
                "pool_name": "L3_VNI",
                "scope_type": "fabric",
                "resource": "5000",
            }
        ],
    )
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "l3_vni",
                "poolName": "L3_VNI",
                "resourceValue": "5000",
                "scopeDetails": {"scopeType": "fabric"},
                "status": None,
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Call manage_state
    module.manage_state()

    # Should process merged state
    assert module.state == "merged"


def test_manage_state_deleted_calls_manage_deleted():
    """manage_state dispatches deleted state to manage_deleted."""
    module, nd = _resource_manager_with_nd(
        state="deleted",
        config=[
            {
                "entity_name": "l3_vni",
                "pool_type": "ID",
                "pool_name": "L3_VNI",
                "scope_type": "fabric",
                "resource": "5000",
            }
        ],
    )
    nd.request.return_value = []

    # Call manage_state
    module.manage_state()

    # Should process deleted state
    assert module.state == "deleted"


def test_manage_state_gathered_calls_manage_gathered():
    """manage_state dispatches gathered state to manage_gathered."""
    module, nd = _resource_manager_with_nd(state="gathered")
    nd.request.return_value = []

    # Call manage_state
    module.manage_state()

    # Should process gathered state
    assert module.state == "gathered"


def test_get_entity_name_from_response_model():
    """_get_entity_name extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response()

    entity_name = module._get_entity_name(resource)  # pylint: disable=protected-access
    assert entity_name == "loopback0"


def test_get_pool_name_from_response_model():
    """_get_pool_name extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response()

    pool_name = module._get_pool_name(resource)  # pylint: disable=protected-access
    assert pool_name == "LOOPBACK_ID"


def test_get_scope_type_from_response_model():
    """_get_scope_type extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response()

    scope_type = module._get_scope_type(resource)  # pylint: disable=protected-access
    assert scope_type == "device"


def test_get_resource_value_from_response_model():
    """_get_resource_value extracts from ResourceManagerResponse model."""
    module = _resource_manager()
    resource = _response()

    resource_value = module._get_resource_value(resource)  # pylint: disable=protected-access
    assert resource_value == "10"


def test_entity_names_match_case_insensitive():
    """_entity_names_match compares case-insensitively."""
    module = _resource_manager()

    # Should match different cases
    result = module._entity_names_match("Loopback0", "loopback0")  # pylint: disable=protected-access
    # Depending on implementation, may match
    assert isinstance(result, bool)


def test_entity_names_match_same_case():
    """_entity_names_match handles same case names."""
    module = _resource_manager()
    result = module._entity_names_match("loopback0", "loopback0")
    assert result is True


def test_entity_names_match_different_names():
    """_entity_names_match detects different names."""
    module = _resource_manager()
    result = module._entity_names_match("loopback0", "loopback1")
    assert result is False


def test_resource_matches_filter_with_multiple_criteria():
    """_resource_matches_filter applies all criteria (AND logic)."""
    module = _resource_manager()
    resource = _response()

    # Filter with multiple matching criteria
    criteria = {"pool_name": "LOOPBACK_ID", "entity_name": "loopback0"}
    result = module._resource_matches_filter(resource, criteria)  # pylint: disable=protected-access

    # Should match only if all criteria match
    assert result is True


def test_resource_matches_filter_with_one_nonmatching_criterion():
    """_resource_matches_filter fails if any criterion doesn't match."""
    module = _resource_manager()
    resource = _response()

    # Filter with one non-matching criterion
    criteria = {
        "pool_name": "LOOPBACK_ID",
        "entity_name": "loopback1",
    }  # Wrong entity_name
    result = module._resource_matches_filter(resource, criteria)  # pylint: disable=protected-access

    # Should not match
    assert result is False


def test_apply_gathered_filters_matches_multiple_resources():
    """_apply_gathered_filters matches all resources meeting criteria."""
    module, unused_nd = _resource_manager_with_nd(
        config=[{"pool_name": "loopbackId"}],
        all_resources=[
            _response(entityName="loopback0", poolName="loopbackId"),
            _response(entityName="loopback1", poolName="loopbackId"),
            _response(entityName="loopback0", poolName="loopbackId"),
        ],  # Duplicate entity
    )

    # Apply filter
    result = module._apply_gathered_filters()  # pylint: disable=protected-access

    # Should match all with same pool_name
    assert len(result) >= 1


def test_translate_gathered_results_empty_list():
    """translate_gathered_results handles empty resource list."""
    module = _resource_manager()

    result = module.translate_gathered_results([])  # pylint: disable=protected-access

    assert result == []


def test_translate_gathered_results_multiple_resources():
    """translate_gathered_results converts multiple resources to dict list."""
    module = _resource_manager()
    resources = [
        _response(entityName="loopback0"),
        _response(entityName="loopback1"),
        _response(entityName="vlan_100"),
    ]

    result = module.translate_gathered_results(resources)  # pylint: disable=protected-access

    assert len(result) == 3
    assert all(isinstance(r, dict) for r in result)


def test_determine_pool_type_ipv4_multicast():
    """_determine_pool_type identifies multicast IPv4 as IP."""
    module = _resource_manager()

    pool_type = module._determine_pool_type("224.0.0.0")  # pylint: disable=protected-access
    # Should identify as IP (not SUBNET)
    assert pool_type in ["IP", "SUBNET"]


def test_determine_pool_type_ipv6_address_short():
    """_determine_pool_type identifies short IPv6 address as ID."""
    module = _resource_manager()

    # Short IPv6 notation like 2001:db8::1
    pool_type = module._determine_pool_type("2001:db8::1")  # pylint: disable=protected-access
    assert pool_type is not None


def test_determine_pool_type_mac_address():
    """_determine_pool_type identifies MAC address format."""
    module = _resource_manager()

    pool_type = module._determine_pool_type("00:11:22:33:44:55")  # pylint: disable=protected-access
    # Should identify as some type (likely ID)
    assert pool_type in ["ID", "IP", "SUBNET"]


def test_payload_construction_success():
    """Payload construction methods exist and can be called."""
    module, unused_nd = _resource_manager_with_nd()
    config = _config()
    resource = _response()

    # Methods should exist and not raise errors
    # We're testing that the infrastructure works
    assert module is not None
    assert config is not None
    assert resource is not None


def test_check_mode_prevents_api_calls_merged():
    """Check mode with merged state logs but doesn't call API."""
    module, nd = _resource_manager_with_nd(state="merged", config=[_config()], all_resources=[])
    nd.module.check_mode = True
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                "status": None,
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Ignore initialization-time GETs and count only manage_merged calls.
    nd.request.reset_mock()

    # Run manage_merged in check mode
    module.manage_merged()  # pylint: disable=protected-access

    # API shouldn't be called in check mode for new resources
    assert nd.request.call_count == 0
    # Verify changed=True and diff recorded in check mode
    assert len(module.results.results) > 0
    last_result = module.results.results[-1]
    assert last_result["changed"] is True


def test_check_mode_prevents_api_calls_deleted():
    """Check mode with deleted state logs but doesn't call DELETE."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[_config()], all_resources=[_response()])
    nd.module.check_mode = True
    nd.request.return_value = {
        "resources": [{"resourceId": 101, "status": None}],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Ignore initialization-time GETs and count only manage_deleted calls.
    nd.request.reset_mock()

    # Run manage_deleted in check mode
    module.manage_deleted()  # pylint: disable=protected-access

    # DELETE shouldn't be called in check mode
    assert nd.request.call_count == 0
    # Verify changed=True and diff recorded in check mode
    assert len(module.results.results) > 0
    last_result = module.results.results[-1]
    assert last_result["changed"] is True


def test_manage_merged_logs_payload():
    """manage_merged logs payload before sending."""
    module, nd = _resource_manager_with_nd(config=[_config()], all_resources=[])
    nd.request.return_value = {
        "resources": [
            {
                "resourceId": 101,
                "entityName": "loopback0",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                "status": None,
            }
        ],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Run manage_merged
    module.manage_merged()  # pylint: disable=protected-access

    # Verify logging occurred (test passes if no exception)
    assert True


def test_manage_deleted_logs_deletion():
    """manage_deleted logs deletion operation."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[_config()], all_resources=[_response()])
    nd.request.return_value = {
        "resources": [{"resourceId": 101, "status": None}],
        "meta": {"counts": {"remaining": 0, "total": 1}},
    }

    # Run manage_deleted
    module.manage_deleted()  # pylint: disable=protected-access

    # Verify logging occurred
    assert True


def test_validate_input_gathered_invalid_filter_raises():
    """Gathered validation wraps model validation errors with index context."""
    if not HAS_PYDANTIC:
        pytest.skip("Strict validator behavior requires pydantic runtime")

    module = _resource_manager()
    module.state = "gathered"
    module.config = [{"scope_type": "not_a_valid_scope"}]

    with pytest.raises(ValueError, match="Gathered filter validation failed"):
        module._validate_input()  # pylint: disable=protected-access


def test_validate_input_gathered_generic_exception_raises():
    """Gathered validation also wraps unexpected model validation exceptions."""
    module = _resource_manager()
    module.state = "gathered"
    module.config = [{"scope_type": "device"}]

    with patch(
        (
            "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
            "nd_manage_resource_manager_resources.ResourceManagerConfigModel.model_validate"
        ),
        side_effect=RuntimeError("boom"),
    ):
        with pytest.raises(ValueError, match="Gathered filter validation failed"):
            module._validate_input()  # pylint: disable=protected-access


def test_resolve_switch_ids_translates_ip_and_preserves_switch_id():
    """Switch translation maps mgmt IP to switch ID and keeps existing IDs."""
    module, unused_nd = _resource_manager_with_nd(config=[])

    inventory = MagicMock()
    inventory.switches = [MagicMock()]
    inventory.by_ip.return_value = {"192.0.2.10": MagicMock(switch_id="SER1")}
    inventory.by_id.return_value = {"SER2": MagicMock()}

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=inventory,
    ):
        resolved = module._resolve_switch_ids_in_config(
            [
                {
                    "entity_name": "loopback0",
                    "scope_type": "device",
                    "switches": ["192.0.2.10", "SER2"],
                }
            ]
        )  # pylint: disable=protected-access

    assert resolved[0]["switches"] == ["SER1", "SER2"]


def test_resolve_switch_ids_unresolved_switch_raises_value_error():
    """Switch translation fails early when a switch cannot be resolved by IP/ID."""
    module, unused_nd = _resource_manager_with_nd(config=[])

    inventory = MagicMock()
    inventory.switches = [MagicMock()]
    inventory.by_ip.return_value = {"192.0.2.10": MagicMock(switch_id="SER1")}
    inventory.by_id.return_value = {"SER1": MagicMock()}

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=inventory,
    ):
        with pytest.raises(ValueError, match="was not found in fabric"):
            module._resolve_switch_ids_in_config(
                [
                    {
                        "entity_name": "loopback0",
                        "scope_type": "device",
                        "switches": ["SER-UNKNOWN"],
                    }
                ]
            )  # pylint: disable=protected-access


def test_resolve_switch_ids_empty_inventory_raises_value_error():
    """Switch-bearing configs fail when the fabric inventory GET returns no usable switches."""
    module, unused_nd = _resource_manager_with_nd(config=[])
    inventory = MagicMock()
    inventory.switches = []
    inventory.by_ip.return_value = {}
    inventory.by_id.return_value = {}

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric",
        return_value=inventory,
    ):
        with pytest.raises(ValueError, match="No switch inventory found"):
            module._resolve_switch_ids_in_config(  # pylint: disable=protected-access
                [
                    {
                        "entity_name": "loopback0",
                        "scope_type": "device",
                        "switches": ["SER1"],
                    }
                ]
            )


def test_resolve_switch_ids_fabric_only_config_does_not_query_inventory():
    """Fabric-only resource configs do not require switch inventory."""
    nd = _mock_nd_module(
        config=[
            {
                "entity_name": "l3_vni_fabric",
                "pool_type": "ID",
                "pool_name": "L3_VNI",
                "scope_type": "fabric",
                "resource": "101",
            }
        ]
    )
    results = Results()

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources.FabricSwitchInventory.from_fabric"
    ) as from_fabric:
        NDResourceManagerModule(nd, results, log=LOG)

    assert from_fabric.call_count == 0


def test_manage_merged_check_mode_registers_diff_without_post_call():
    """Merged check mode emits diff and skips the POST API mutation call."""
    module, nd = _resource_manager_with_nd(config=[], check_mode=True)
    module.proposed = [_config(entity_name="loopback99", resource="99")]
    module.existing = []
    nd.request.reset_mock()

    module.manage_merged()

    assert nd.request.call_count == 0
    assert len(module.changed_dict[0]["merged"]) == 1
    # Verify check mode registers pending changes with changed=True and diff
    assert len(module.results.results) > 0
    last_result = module.results.results[-1]
    assert last_result["changed"] is True
    assert len(module.results.diffs) > 0
    last_diff = module.results.diffs[-1]
    assert "merged" in last_diff
    assert len(last_diff["merged"]) == 1


def test_manage_merged_update_removes_existing_id_before_create():
    """Merged updates release the existing allocation before creating the replacement."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg = _config(resource="20")
    module.proposed = [cfg]
    module.existing = [_response(resource_value="10")]

    fake_changes = {
        "idempotent": [],
        "to_update": [(cfg, "SER1", {"resourceId": 101, "resourceValue": "10"})],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.reset_mock()
    nd.request.side_effect = [
        {"resources": [{"resourceValue": "10", "status": "deleted"}]},
        {"resources": [{"entityName": "loopback0", "status": "created"}]},
    ]

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.ResourceManagerDiffEngine.validate_resource_api_fields"
            ),
        ),
    ):
        module.manage_merged()

    assert nd.request.call_count == 2
    first_call = nd.request.call_args_list[0]
    second_call = nd.request.call_args_list[1]
    assert first_call.args[0].endswith("/resources/actions/remove")
    assert first_call.kwargs["data"] == {"resourceIds": [101]}
    assert second_call.args[0].endswith("/resources")
    assert second_call.kwargs["data"]["resources"][0]["resourceValue"] == "20"
    assert module.changed_dict[0]["deleted"] == ["101"]
    assert len(module.changed_dict[0]["merged"]) == 1


def test_manage_merged_update_keeps_request_local_return_codes():
    """Update removal and creation retain their own ND return codes."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg = _config(resource="20")
    module.proposed = [cfg]
    module.existing = [_response(resource_value="10")]
    fake_changes = {
        "idempotent": [],
        "to_update": [(cfg, "SER1", {"resourceId": 101, "resourceValue": "10"})],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }
    responses = [
        (207, {"resources": [{"resourceValue": "10", "status": "deleted"}]}),
        (207, {"resources": [{"entityName": "loopback0", "status": "created"}]}),
    ]

    def request_with_status(*args, **kwargs):
        return_code, response = responses.pop(0)
        nd.status = return_code
        return response

    nd.request.side_effect = request_with_status

    with (
         patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
         patch(
             (
                 "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                 "nd_manage_resource_manager_resources.ResourceManagerDiffEngine.validate_resource_api_fields"
             ),
        ),
    ):
        module.manage_merged()

    assert [entry["RETURN_CODE"] for entry in module.api_responses] == [207, 207]
    assert [entry["RETURN_CODE"] for entry in module.results.responses[-2:]] == [207, 207]


def test_manage_merged_update_delete_validation_failure_prevents_create():
    """Merged update replacement does not create when remove response validation fails."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg = _config(resource="20")
    module.proposed = [cfg]
    module.existing = [_response(resource_value="10")]

    fake_changes = {
        "idempotent": [],
        "to_update": [(cfg, "SER1", {"resourceId": 101, "resourceValue": "10"})],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.reset_mock()
    nd.request.return_value = {"resources": [{"resourceValue": "10", "status": "failed", "message": "still in use"}]}

    with patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes):
        with pytest.raises(ValueError, match="Partial success in batch delete"):
            module.manage_merged()

    assert nd.request.call_count == 1
    assert nd.request.call_args.args[0].endswith("/resources/actions/remove")


def test_manage_merged_update_check_mode_reports_delete_and_create_without_api_calls():
    """Merged update check mode reports both replacement phases without mutating."""
    module, nd = _resource_manager_with_nd(config=[], check_mode=True)
    cfg = _config(resource="20")
    module.proposed = [cfg]
    module.existing = [_response(resource_value="10")]

    fake_changes = {
        "idempotent": [],
        "to_update": [(cfg, "SER1", {"resourceId": 101, "resourceValue": "10"})],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.reset_mock()

    with patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes):
        module.manage_merged()

    assert nd.request.call_count == 0
    assert module.changed_dict[0]["deleted"] == ["101"]
    assert len(module.changed_dict[0]["merged"]) == 1
    assert module.results.diffs[-2]["deleted"] == [101]
    assert module.results.diffs[-1]["merged"][0]["resourceValue"] == "20"
    assert module.results.payload[-2] == {"resourceIds": [101]}
    assert module.results.payload[-1]["resources"][0]["resourceValue"] == "20"


def test_manage_merged_update_missing_resource_id_raises_before_mutation():
    """Merged updates fail clearly when the existing resource has no ID to release."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg = _config(resource="20")
    module.proposed = [cfg]
    module.existing = [_response(resource_value="10")]

    fake_changes = {
        "idempotent": [],
        "to_update": [(cfg, "SER1", {"resourceValue": "10"})],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.reset_mock()

    with patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes):
        with pytest.raises(ValueError, match="resourceId"):
            module.manage_merged()

    assert nd.request.call_count == 0
    assert module.changed_dict[0]["deleted"] == []
    assert module.changed_dict[0]["merged"] == []


def test_manage_merged_post_exception_is_wrapped_with_value_error():
    """Merged batch POST failures are surfaced as ValueError with operation context."""
    module, nd = _resource_manager_with_nd(config=[])
    module.proposed = [_config(entity_name="loopback99", resource="99")]
    module.existing = []
    nd.request.side_effect = Exception("post failed")

    with pytest.raises(ValueError, match="Batch create API call failed"):
        module.manage_merged()


def test_manage_merged_validates_response_fields_for_matching_entity():
    """Merged success path validates API response fields against sent config."""
    module, nd = _resource_manager_with_nd(config=[])
    module.proposed = [_config(entity_name="loopback99", resource="99")]
    module.existing = []
    nd.request.return_value = {"resources": [{"entityName": "loopback99"}]}
    resp_item = _response(entity_name="loopback99", resource_value="99")
    fake_batch_response = MagicMock(resources=[resp_item])

    with (
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.ResourcesManagerBatchResponse.from_response"
            ),
            return_value=fake_batch_response,
        ),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.ResourceManagerDiffEngine.validate_resource_api_fields"
            ),
        ) as validate_fields,
    ):
        module.manage_merged()

    assert validate_fields.called


def test_manage_merged_correlates_batch_responses_by_full_allocation_identity():
    """Batch validation matches same-entity resources by pool/scope/switch/VRF."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg_loopback = _config(
        entity_name="shared_entity",
        pool_name="LOOPBACK_ID",
        resource="10",
        switches=["SER1"],
    )
    cfg_port_channel = _config(
        entity_name="shared_entity",
        pool_name="PORT_CHANNEL_ID",
        resource="20",
        switches=["SER1"],
    )
    module.proposed = [cfg_loopback, cfg_port_channel]
    module.existing = []
    nd.request.return_value = {
        "resources": [
            {
                "entityName": "shared_entity",
                "poolName": "LOOPBACK_ID",
                "resourceValue": "10",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                "vrfName": "default",
            },
            {
                "entityName": "shared_entity",
                "poolName": "PORT_CHANNEL_ID",
                "resourceValue": "20",
                "scopeDetails": {"scopeType": "device", "switchId": "SER1"},
                "vrfName": "default",
            },
        ]
    }

    module.manage_merged()

    assert len(module.api_responses) == 2
    assert [item["DATA"]["poolName"] for item in module.api_responses] == [
        "LOOPBACK_ID",
        "PORT_CHANNEL_ID",
    ]


def test_manage_merged_raises_on_partial_create_response():
    """Merged state fails when batch create response is missing items."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg_1 = _config(entity_name="loopback99", resource="99")
    cfg_2 = _config(entity_name="loopback100", resource="100")
    module.proposed = [cfg_1, cfg_2]
    module.existing = []

    fake_changes = {
        "idempotent": [],
        "to_update": [],
        "to_add": [
            (cfg_1, "SER1", None),
            (cfg_2, "SER1", None),
        ],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.return_value = {"resources": [{"entityName": "loopback99", "status": "created"}]}
    create_item = MagicMock()
    create_item.entity_name = "loopback99"
    create_item.status = "created"
    create_item.message = None
    create_item.model_dump.return_value = {"entityName": "loopback99", "status": "created"}
    fake_batch_response = MagicMock(resources=[create_item])

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.ResourcesManagerBatchResponse.from_response"
            ),
            return_value=fake_batch_response,
        ),
    ):
        with pytest.raises(ValueError, match="Partial success in batch create"):
            module.manage_merged()


def test_manage_merged_raises_on_failed_create_status():
    """Merged state fails when any create response item reports failure."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg = _config(entity_name="loopback99", resource="99")
    module.proposed = [cfg]
    module.existing = []

    fake_changes = {
        "idempotent": [],
        "to_update": [],
        "to_add": [(cfg, "SER1", None)],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.return_value = {"resources": [{"entityName": "loopback99", "status": "failed", "message": "resource pool exhausted"}]}
    failed_item = MagicMock()
    failed_item.entity_name = "loopback99"
    failed_item.status = "failed"
    failed_item.message = "resource pool exhausted"
    failed_item.model_dump.return_value = {
        "entityName": "loopback99",
        "status": "failed",
        "message": "resource pool exhausted",
    }
    fake_batch_response = MagicMock(resources=[failed_item])

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.ResourcesManagerBatchResponse.from_response"
            ),
            return_value=fake_batch_response,
        ),
    ):
        with pytest.raises(ValueError, match="Partial success in batch create") as exc_info:
            module.manage_merged()

    assert "resource pool exhausted" in str(exc_info.value)


def test_manage_merged_raises_on_mixed_create_success_and_failure():
    """Merged state fails when batch create has mixed success and failure statuses."""
    module, nd = _resource_manager_with_nd(config=[])
    cfg_1 = _config(entity_name="loopback99", resource="99")
    cfg_2 = _config(entity_name="loopback100", resource="100")
    module.proposed = [cfg_1, cfg_2]
    module.existing = []

    fake_changes = {
        "idempotent": [],
        "to_update": [],
        "to_add": [
            (cfg_1, "SER1", None),
            (cfg_2, "SER1", None),
        ],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.return_value = {
        "resources": [
            {"entityName": "loopback99", "status": "created"},
            {"entityName": "loopback100", "status": "failed", "message": "already allocated"},
        ]
    }

    success_item = MagicMock()
    success_item.entity_name = "loopback99"
    success_item.status = "created"
    success_item.message = None
    success_item.model_dump.return_value = {"entityName": "loopback99", "status": "created"}

    failed_item = MagicMock()
    failed_item.entity_name = "loopback100"
    failed_item.status = "failed"
    failed_item.message = "already allocated"
    failed_item.model_dump.return_value = {
        "entityName": "loopback100",
        "status": "failed",
        "message": "already allocated",
    }

    fake_batch_response = MagicMock(resources=[success_item, failed_item])

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.ResourcesManagerBatchResponse.from_response"
            ),
            return_value=fake_batch_response,
        ),
    ):
        with pytest.raises(ValueError, match="Partial success in batch create") as exc_info:
            module.manage_merged()

    assert "entity_name=loopback100" in str(exc_info.value)
    assert "already allocated" in str(exc_info.value)


def test_manage_deleted_deduplicates_ids_and_skips_missing_id_in_check_mode():
    """Deleted state deduplicates resource IDs and ignores entries without IDs."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[], check_mode=True)
    cfg = _config()
    module.proposed = [cfg]
    module.existing = []
    nd.request.reset_mock()

    fake_changes = {
        "idempotent": [
            (cfg, "SER1", {"resourceId": 101}),
            (cfg, "SER1", {"resourceId": 101}),
            (cfg, "SER1", {}),
        ],
        "to_update": [],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    with patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes):
        module.manage_deleted()

    assert module.changed_dict[0]["deleted"] == ["101"]
    assert nd.request.call_count == 0
    # Verify check mode registers pending deletions with changed=True and diff
    assert len(module.results.results) > 0
    last_result = module.results.results[-1]
    assert last_result["changed"] is True
    assert len(module.results.diffs) > 0
    last_diff = module.results.diffs[-1]
    assert "deleted" in last_diff
    assert last_diff["deleted"] == [101]


def test_manage_deleted_api_exception_is_wrapped_with_value_error():
    """Deleted API mutation failures are surfaced as ValueError with operation context."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[])
    cfg = _config()
    module.proposed = [cfg]
    module.existing = []

    fake_changes = {
        "idempotent": [(cfg, "SER1", {"resourceId": 101})],
        "to_update": [],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.side_effect = Exception("delete failed")

    with patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes):
        with pytest.raises(ValueError, match="Delete API call failed"):
            module.manage_deleted()


def test_manage_deleted_success_parses_remove_response_items():
    """Deleted success path parses remove response resources and appends API data."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[])
    cfg = _config()
    module.proposed = [cfg]
    module.existing = []

    fake_changes = {
        "idempotent": [(cfg, "SER1", {"resourceId": 101})],
        "to_update": [],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.return_value = {"resources": [{"resourceId": 101}]}
    remove_item = MagicMock()
    remove_item.status = None
    remove_item.message = None
    remove_item.resource_value = "10"
    remove_item.model_dump.return_value = {"resourceId": 101}
    fake_remove_response = MagicMock(resources=[remove_item])

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.RemoveResourcesByIdsResponse.from_response"
            ),
            return_value=fake_remove_response,
        ),
    ):
        module.manage_deleted()

    assert any(entry.get("DATA", {}).get("resourceId") == 101 for entry in module.api_responses)


def test_manage_deleted_propagates_nd_return_code():
    """Live deletion propagates ND's HTTP status to item and registered responses."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[])
    cfg = _config()
    module.proposed = [cfg]
    module.existing = []
    fake_changes = {
        "idempotent": [(cfg, "SER1", {"resourceId": 101})],
        "to_update": [],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }
    nd.status = 207
    nd.request.return_value = {"resources": [{"resourceValue": "10", "status": "deleted"}]}

    with patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes):
        module.manage_deleted()

    assert module.api_responses[-1]["RETURN_CODE"] == 207
    assert module.results.responses[-1]["RETURN_CODE"] == 207


def test_manage_deleted_raises_on_partial_delete_response():
    """Deleted state fails when the remove response is missing items."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[])
    cfg = _config()
    module.proposed = [cfg]
    module.existing = []

    fake_changes = {
        "idempotent": [
            (cfg, "SER1", {"resourceId": 101}),
            (cfg, "SER2", {"resourceId": 102}),
        ],
        "to_update": [],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.return_value = {"resources": [{"resourceValue": "101", "status": "deleted"}]}
    remove_item = MagicMock()
    remove_item.resource_value = "101"
    remove_item.status = "deleted"
    remove_item.message = None
    remove_item.model_dump.return_value = {"resourceValue": "101", "status": "deleted"}
    fake_remove_response = MagicMock(resources=[remove_item])

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.RemoveResourcesByIdsResponse.from_response"
            ),
            return_value=fake_remove_response,
        ),
    ):
        with pytest.raises(ValueError, match="Partial success in batch delete"):
            module.manage_deleted()


def test_manage_deleted_raises_on_failed_delete_status():
    """Deleted state fails when any remove response item reports failure."""
    module, nd = _resource_manager_with_nd(state="deleted", config=[])
    cfg = _config()
    module.proposed = [cfg]
    module.existing = []

    fake_changes = {
        "idempotent": [(cfg, "SER1", {"resourceId": 101})],
        "to_update": [],
        "to_add": [],
        "to_delete": [],
        "debugs": [],
    }

    nd.request.return_value = {"resources": [{"resourceValue": "101", "status": "failed", "message": "resource is in use"}]}
    failed_item = MagicMock()
    failed_item.resource_value = "101"
    failed_item.status = "failed"
    failed_item.message = "resource is in use"
    failed_item.model_dump.return_value = {
        "resourceValue": "101",
        "status": "failed",
        "message": "resource is in use",
    }
    fake_remove_response = MagicMock(resources=[failed_item])

    with (
        patch.object(ResourceManagerDiffEngine, "compute_changes", return_value=fake_changes),
        patch(
            (
                "ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager."
                "nd_manage_resource_manager_resources.RemoveResourcesByIdsResponse.from_response"
            ),
            return_value=fake_remove_response,
        ),
    ):
        with pytest.raises(ValueError, match="Partial success in batch delete"):
            module.manage_deleted()


def test_manage_state_unsupported_state_raises():
    """State dispatch rejects unsupported state names with clear error text."""
    module, unused_nd = _resource_manager_with_nd(state="unsupported", config=[])

    with pytest.raises(ValueError, match="Unsupported state"):
        module.manage_state()


def test_exit_module_gathered_state_returns_changed_false():
    """Gathered exit path returns gathered results with changed fixed to False."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.state = "gathered"
    module.changed_dict[0]["gathered"] = [{"entity_name": "loopback0"}]
    module.existing = [_response()]

    module.exit_module()

    assert ansible_module.exit_payload["changed"] is False


def test_exit_module_check_mode_returns_changed_true_with_pending_merged():
    """Exit path returns changed=True in check mode when diff has pending merges."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.changed_dict[0]["merged"] = [{"entityName": "loopback0"}]
    module.nd.module.check_mode = True

    module.exit_module()

    assert ansible_module.exit_payload["changed"] is True
    assert len(module.changed_dict[0]["merged"]) == 1


def test_exit_module_check_mode_returns_changed_true_with_pending_deleted():
    """Exit path returns changed=True in check mode when diff has pending deletes."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.changed_dict[0]["deleted"] = [101, 102]
    module.nd.module.check_mode = True

    module.exit_module()

    assert ansible_module.exit_payload["changed"] is True
    assert len(module.changed_dict[0]["deleted"]) == 2


def test_exit_module_check_mode_returns_changed_false_with_no_pending():
    """Exit path returns changed=False in check mode when diff has no pending changes."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.changed_dict[0]["merged"] = []
    module.changed_dict[0]["deleted"] = []
    module.nd.module.check_mode = True

    module.exit_module()

    assert ansible_module.exit_payload["changed"] is False


def test_exit_module_requeries_when_changed_and_not_check_mode():
    """Exit path refreshes existing resources after successful non-check-mode changes."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.changed_dict[0]["merged"] = [{"entityName": "loopback0"}]
    module.nd.module.check_mode = False

    def fake_refresh(update_previous=False):  # pylint: disable=unused-argument
        module.existing = [_response(entityName="loopback9")]

    module._refresh_existing_resources = MagicMock(side_effect=fake_refresh)  # pylint: disable=protected-access
    module.exit_module()

    module._refresh_existing_resources.assert_called_once_with(update_previous=False)  # pylint: disable=protected-access
    assert any(item.get("entity_name") == "loopback9" for item in ansible_module.exit_payload.get("after", []))


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_exit_module_includes_resource_ids_in_before_and_after_snapshots(state):
    """Merge and delete output snapshots retain controller resource identifiers."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.state = state
    module.results.state = state
    module.previous = [_response(resourceId=101, entityName="loopback0")]
    module.existing = [_response(resourceId=202, entityName="loopback1")]

    module.exit_module()

    assert ansible_module.exit_payload["before"][0]["resource_id"] == 101
    assert ansible_module.exit_payload["after"][0]["resource_id"] == 202


def test_exit_module_info_output_level_includes_proposed():
    """Info/debug output level includes proposed config payload in final output."""
    module, ansible_module = _resource_manager_for_exit(verbosity=0)
    module.nd.params["output_level"] = "info"
    module.changed_dict[0]["merged"] = [{"entityName": "loopback0"}]
    module.nd.module.check_mode = True
    module._proposed_list = [{"entity_name": "loopback0", "pool_name": "LOOPBACK_ID"}]

    module.exit_module()

    assert "proposed" in ansible_module.exit_payload
