# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Preserve-config defaulting through argument validation and Switch workflows."""

# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources import SwitchFabricOps
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import SwitchConfigModel
from ansible_collections.cisco.nd.tests.unit.module_utils.test_nd_switch_resources import FailJsonError, RecordingWait, _resource, _sw


@pytest.mark.parametrize("options,expected", [({}, None), ({"preserve_config": False}, False), ({"preserve_config": True}, True)])
def test_preserve_intent_survives_argument_validation(options, expected):
    """Do not collapse omitted input into false before fabric requirements are known."""
    arguments = {
        "fabric": "FAB1",
        "state": "merged",
        "config": [{"seed_ip": "192.0.2.10", "username": "admin", "password": "password", **options}],
    }
    validated = ArgumentSpecValidator(SwitchConfigModel.get_argument_spec()).validate(arguments)
    assert not validated.error_messages
    cfg = SwitchConfigModel.from_config(validated.validated_parameters["config"][0], context={"state": "merged"})
    assert cfg.preserve_config is expected


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("fabric_type,default", [("vxlanIbgp", False), ("vxlanEbgp", False), ("vxlanCampus", False), ("externalConnectivity", True)])
@pytest.mark.parametrize("options", [{}, {"preserve_config": False}, {"preserve_config": True}])
def test_preserve_default_reaches_add_payload_without_overriding_explicit_input(monkeypatch, state, check_mode, fabric_type, default, options):
    """The existing workflow resolves defaults before preview or add payload construction."""
    config = [{"seed_ip": "192.0.2.10", "username": "admin", "password": "password", **options}]
    validated = ArgumentSpecValidator(SwitchConfigModel.get_argument_spec()).validate({"fabric": "FAB1", "state": state, "config": config})
    assert not validated.error_messages
    resource = _resource(state=state, config=validated.validated_parameters["config"], check_mode=check_mode)
    resource.fabric_details_cache = SimpleNamespace(get_fabric_type=lambda: fabric_type)
    resource.wait_utils = RecordingWait()
    resource.fabric_ops = SwitchFabricOps(resource.ctx, fabric_utils=SimpleNamespace())
    post_add = []
    discoveries = []
    monkeypatch.setattr(resource.fabric_ops, "post_add_processing", post_add.append)

    def discover(configs):
        discoveries.append(configs)
        return {"192.0.2.10": {"hostname": "leaf1", "ip": "192.0.2.10", "serialNumber": "SERIAL1", "model": "N9K-C93180YC-EX"}}

    monkeypatch.setattr(resource.discovery, "discover", discover)
    effective = options.get("preserve_config", default)
    invalid = (fabric_type == "externalConnectivity" and not effective) or (fabric_type in ("vxlanEbgp", "vxlanCampus") and effective)
    if invalid:
        with pytest.raises(FailJsonError, match="preserve_config.*not supported"):
            resource.manage_state()
        assert not discoveries and not resource.nd.calls and not post_add
        assert resource.proposed_cfgs[0].preserve_config is effective
        return

    resource.manage_state()
    assert resource.proposed_cfgs[0].preserve_config is effective
    if check_mode:
        assert not resource.nd.calls and not discoveries and not post_add
        assert resource._build_check_mode_output()["after"][0]["preserve_config"] is effective
    else:
        assert len(discoveries) == len(resource.nd.calls) == len(post_add) == 1
        assert resource.nd.calls[0]["path"] == "/api/v1/manage/fabrics/FAB1/switches"
        assert resource.nd.calls[0]["data"]["preserveConfig"] is effective
        wait_sets = SwitchFabricOps._split_post_add_wait_sets(post_add[0].switch_actions)
        assert [serial for serial, cfg in (wait_sets.nxos_preserve if effective else wait_sets.nxos_reload)] == ["SERIAL1"]


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("fabric_type", ["vxlanIbgp", "vxlanEbgp", "vxlanCampus", "externalConnectivity"])
def test_unchanged_switch_is_not_reimported_when_preserve_default_changes(state, check_mode, fabric_type):
    """Omitted onboarding flags must not cause destructive repeat-run imports."""
    config = [{"seed_ip": "192.0.2.10", "username": "admin", "password": "password"}]
    resource = _resource(state=state, config=config, check_mode=check_mode, existing=[_sw("192.0.2.10", "SERIAL1")])
    resource.fabric_details_cache = SimpleNamespace(get_fabric_type=lambda: fabric_type)
    resource.manage_state()
    assert not resource.nd.calls
    assert resource._plan.idempotent[0].preserve_config is None
    resource.results.build_final_result()
    assert resource.results.final_result["changed"] is False
    if check_mode:
        assert resource._build_check_mode_output()["changed"] is False
