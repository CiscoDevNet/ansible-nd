# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for manage-switches config and inventory models."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.bootstrap_models import BootstrapImportSwitchModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import SwitchConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.rma_models import RMASwitchModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import SwitchDataModel


def _normal_config(**overrides):
    data = {
        "seed_ip": "192.0.2.10",
        "username": "admin",
        "password": "password",
        "role": "leaf",
    }
    data.update(overrides)
    return data


def _inventory_response(**overrides):
    data = {
        "switchId": "SERIAL1",
        "serialNumber": "SERIAL1",
        "fabricManagementIp": "192.0.2.10",
        "hostname": "leaf1",
        "model": "N9K-C93180YC-EX",
        "softwareVersion": "10.3(1)",
        "switchRole": "leaf",
        "additionalData": {
            "discoveryStatus": "ok",
            "systemMode": "normal",
            "platformType": "nx-os",
        },
    }
    data.update(overrides)
    return data


def _bootstrap_import_payload(**overrides):
    data = {
        "serialNumber": "POAP1",
        "model": "N9K-C93180YC-EX",
        "softwareVersion": "10.3(1)",
        "softwareImage": "nxos64-cs.10.3.1.F.bin",
        "hostname": "leaf-poap",
        "ip": "192.0.2.10",
        "password": "password",
        "discoveryAuthProtocol": "md5",
        "fingerPrint": "fingerprint",
        "publicKey": "public-key",
        "dhcpBootstrapIp": "192.0.2.50",
        "seedSwitch": False,
    }
    data.update(overrides)
    return data


def _rma_payload(**overrides):
    data = {
        "gatewayIpMask": "192.0.2.1/24",
        "model": "N9K-C93180YC-EX",
        "softwareVersion": "10.3(1)",
        "softwareImage": "nxos64-cs.10.3.1.F.bin",
        "switchRole": "leaf",
        "password": "password",
        "discoveryAuthProtocol": "md5",
        "hostname": "leaf-replacement",
        "ip": "192.0.2.10",
        "newSwitchId": "NEW1",
        "oldSwitchId": "OLD1",
        "publicKey": "public-key",
        "fingerPrint": "fingerprint",
    }
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, "normal"),
        ({"poap": {"serial_number": "POAP1", "hostname": "leaf-poap"}}, "poap"),
        (
            {
                "preprovision": {
                    "serial_number": "PREPROV1",
                    "model": "N9K-C93180YC-EX",
                    "version": "10.3(1)",
                    "hostname": "leaf-preprov",
                    "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
                }
            },
            "preprovision",
        ),
        (
            {
                "poap": {"serial_number": "POAP1", "hostname": "leaf-poap"},
                "preprovision": {
                    "serial_number": "PREPROV1",
                    "model": "N9K-C93180YC-EX",
                    "version": "10.3(1)",
                    "hostname": "leaf-preprov",
                    "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
                },
            },
            "swap",
        ),
        ({"rma": [{"new_serial_number": "NEWSERIAL1"}]}, "rma"),
    ],
)
def test_switch_config_operation_type(extra, expected):
    """SwitchConfigModel derives the lifecycle operation from nested config blocks."""
    cfg = SwitchConfigModel.model_validate(_normal_config(**extra), context={"state": "merged"})

    assert cfg.operation_type == expected


def test_switch_config_state_defaults_and_gathered_output_mask_credentials():
    """Merged config defaults role, and gathered output is reusable with placeholders."""
    cfg = SwitchConfigModel.model_validate(
        {"seed_ip": "192.0.2.10", "username": "admin", "password": "password"},
        context={"state": "merged"},
    )

    assert cfg.role == "leaf"
    gathered = cfg.to_gathered_dict()
    assert gathered["seed_ip"] == "192.0.2.10"
    assert gathered["username"] == "<username>"
    assert gathered["password"] == "<password>"
    assert "platform_type" not in gathered


def test_switch_config_requires_credentials_for_write_states():
    """Write states reject normal switch configs that omit credentials."""
    with pytest.raises(ValidationError, match="username and password are required"):
        SwitchConfigModel.model_validate({"seed_ip": "192.0.2.10"}, context={"state": "merged"})


def test_switch_config_rejects_invalid_special_operation_combinations():
    """RMA cannot be combined with POAP/preprovision blocks."""
    with pytest.raises(ValidationError, match="Cannot specify 'rma' together"):
        SwitchConfigModel.model_validate(
            _normal_config(
                poap={"serial_number": "POAP1", "hostname": "leaf-poap"},
                rma=[{"new_serial_number": "NEWSERIAL1"}],
            ),
            context={"state": "merged"},
        )


def test_bootstrap_import_model_requires_call_home_identity_fields():
    """Bootstrap import payload rejects missing call-home identity fields."""
    with pytest.raises(ValidationError, match="POAP1.*publicKey.*finish calling home"):
        BootstrapImportSwitchModel.model_validate(_bootstrap_import_payload(publicKey=""))

    with pytest.raises(ValidationError, match="POAP1.*fingerPrint.*finish calling home"):
        BootstrapImportSwitchModel.model_validate(_bootstrap_import_payload(fingerPrint=" "))


def test_bootstrap_import_payload_matches_nd42_schema_fields():
    """Bootstrap payload carries softwareImage and omits removed imagePolicy."""
    payload = BootstrapImportSwitchModel.model_validate(_bootstrap_import_payload(imagePolicy="legacy-policy")).to_payload()

    assert payload["softwareImage"] == "nxos64-cs.10.3.1.F.bin"
    assert payload["dhcpBootstrapIp"] == "192.0.2.50"
    assert "imagePolicy" not in payload
    assert "reAdd" not in payload


def test_rma_model_requires_call_home_identity_fields():
    """RMA payload rejects missing replacement-switch identity fields."""
    with pytest.raises(ValidationError, match="NEW1.*publicKey.*finish calling home"):
        RMASwitchModel.model_validate(_rma_payload(publicKey=""))

    with pytest.raises(ValidationError, match="NEW1.*fingerPrint.*finish calling home"):
        RMASwitchModel.model_validate(_rma_payload(fingerPrint=" "))


def test_rma_payload_matches_nd42_schema_fields():
    """RMA body omits path-only oldSwitchId and removed imagePolicy."""
    payload = RMASwitchModel.model_validate(_rma_payload(imagePolicy="legacy-policy")).to_payload()

    assert payload["softwareImage"] == "nxos64-cs.10.3.1.F.bin"
    assert "oldSwitchId" not in payload
    assert "imagePolicy" not in payload


def test_switch_data_from_inventory_response_and_to_config_dict():
    """Inventory responses are parsed and serialized to the stable config-shaped output."""
    sw = SwitchDataModel.from_response(_inventory_response())

    assert sw.switch_id == "SERIAL1"
    assert sw.fabric_management_ip == "192.0.2.10"
    assert sw.additional_data.discovery_status == "ok"
    assert sw.additional_data.system_mode == "normal"

    config = sw.to_config_dict()
    assert config["seed_ip"] == "192.0.2.10"
    assert config["role"] == "leaf"
    assert config["mode"] == "normal"


def test_switch_data_from_discovery_response():
    """Discovery responses are normalized into inventory-shaped SwitchDataModel objects."""
    sw = SwitchDataModel.from_response(
        {
            "serialNumber": "SERIAL2",
            "ip": "192.0.2.11",
            "hostname": "leaf2",
            "model": "N9K-C93180YC-EX",
            "softwareVersion": "10.3(1)",
            "role": "spine",
        }
    )

    assert sw.switch_id == "SERIAL2"
    assert sw.fabric_management_ip == "192.0.2.11"
    assert sw.switch_role == "spine"


def test_switch_config_from_switch_data_requires_seed_ip():
    """Gathered config cannot be built from inventory records with no management IP."""
    sw = SwitchDataModel.from_response(_inventory_response(fabricManagementIp=None))

    with pytest.raises(ValueError, match="no fabric_management_ip"):
        SwitchConfigModel.from_switch_data(sw)


def test_switch_config_from_switch_data_uses_live_role_and_platform():
    """Inventory records can be converted into config entries for gathered output."""
    sw = SwitchDataModel.from_response(_inventory_response())

    cfg = SwitchConfigModel.from_switch_data(sw)

    assert cfg.seed_ip == "192.0.2.10"
    assert cfg.role == "leaf"
    assert cfg.platform_type == "nx-os"
