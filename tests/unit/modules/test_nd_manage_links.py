# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ``plugins/modules/nd_manage_links.py`` module wiring."""

from types import SimpleNamespace

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.manage_link import ManageLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.one_manage_link import OneManageLinkStrategy
from ansible_collections.cisco.nd.plugins.modules import nd_manage_links


def _secret_config():
    return {
        "config_data": {
            "policy_type": "multisiteUnderlay",
            "template_inputs": {"ebgp_password": "PrepareSafely!"},
        }
    }


def test_register_secret_values_masks_free_form_inputs_early():
    """Raw template secrets are registered before state-machine construction."""
    module = SimpleNamespace(params={"config": [_secret_config()]}, no_log_values={"already-known"})

    nd_manage_links.register_secret_values(module)

    assert module.no_log_values == {"already-known", "PrepareSafely!"}


def test_main_registers_secrets_before_strategy_and_preparation(monkeypatch):
    """A strategy/preparation failure cannot happen before secret registration."""
    events = []

    class StopMain(Exception):
        pass

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            self.params = {"config": [_secret_config()], "state": "merged"}
            self.no_log_values = set()
            self.check_mode = False
            events.append("module")

        def fail_json(self, **kwargs):
            events.append("fail_json")
            raise StopMain

    def fake_require_pydantic(module):
        events.append("require_pydantic")

    def fake_register_secret_values(module):
        events.append("register_secret_values")

    def fake_determine_strategy(module):
        events.append("determine_strategy")
        raise ValueError("stop after ordering check")

    monkeypatch.setattr(nd_manage_links, "AnsibleModule", FakeAnsibleModule)
    monkeypatch.setattr(nd_manage_links, "require_pydantic", fake_require_pydantic)
    monkeypatch.setattr(nd_manage_links, "register_secret_values", fake_register_secret_values)
    monkeypatch.setattr(nd_manage_links, "determine_strategy", fake_determine_strategy)

    with pytest.raises(StopMain):
        nd_manage_links.main()

    assert events == [
        "module",
        "require_pydantic",
        "register_secret_values",
        "determine_strategy",
        "fail_json",
    ]


def test_determine_strategy_handles_gathered_with_omitted_config():
    """Default auto scope accepts Ansible's explicit ``config=None`` value."""
    module = SimpleNamespace(params={"link_scope": "auto", "fabric_name": "f", "config": None, "state": "gathered"})

    assert isinstance(nd_manage_links.determine_strategy(module), ManageLinkStrategy)


def test_determine_strategy_auto_detects_one_manage_cluster_identity():
    module = SimpleNamespace(
        params={
            "link_scope": "auto",
            "fabric_name": "f",
            "config": [{"src_cluster_name": "c1", "dst_cluster_name": "c2"}],
        }
    )

    assert isinstance(nd_manage_links.determine_strategy(module), OneManageLinkStrategy)


def test_mpls_underlay_documented_example_validates():
    """The shipped MPLS-SR example remains executable against the model contract."""
    tasks = yaml.safe_load(nd_manage_links.EXAMPLES)
    module_args = next(
        task["cisco.nd.nd_manage_links"]
        for task in tasks
        if task.get("cisco.nd.nd_manage_links", {}).get("config", [{}])[0].get("config_data", {}).get("policy_type") == "mplsUnderlay"
    )

    link = NDLinkModel.from_config(module_args["config"][0], context={"state": module_args.get("state", "merged")})

    assert link.config_data.template_inputs.mpls_fabric_type == "mplsSr"
    assert link.config_data.template_inputs.dci_routing_protocol == "is-is"
