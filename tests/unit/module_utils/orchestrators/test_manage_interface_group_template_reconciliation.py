# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Retain declared template comparison semantics through merged write readback."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import InterfaceGroupConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import ManageInterfaceGroupOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

GROUP_PATH = "/api/v1/manage/fabrics/fab1/interfaceGroups/custom-group"
TEMPLATE_PATH = "/api/v1/manage/configTemplates/custom-template"
EXISTING_MEMBER = ("SN1", "Ethernet1/9")
ADDED_MEMBER = ("SN1", "Ethernet1/10")


def _group(value: Any, *, members: tuple[str, ...]) -> InterfaceGroupConfigModel:
    return InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "custom-group",
            "type": "ethernet",
            "switchInterfaces": [{"switchId": "SN1", "interfaceNames": list(members)}],
            "policyDetails": {
                "policyType": "userDefinedSharedTrunk",
                "templateName": "custom-template",
                "templateConfig": {"VALUE": value},
            },
        }
    )


def _workflow(monkeypatch: pytest.MonkeyPatch, parameter_type: str, desired: Any, echo: Any, *, write_mode: str = "unmodified"):
    """Replace only I/O while retaining preflight, merge, PUT and readback logic."""
    before = _group(echo, members=(EXISTING_MEMBER[1],))
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "custom-template",
            "template_config": {"VALUE": desired},
            "switch_interfaces": [{"switch_id": "SN1", "interface_names": [ADDED_MEMBER[1]]}],
        }
    )
    actual = _group(echo, members=(EXISTING_MEMBER[1], ADDED_MEMBER[1]))
    template = {
        "name": "custom-template",
        "templateType": "policy",
        "templateSubType": "interfaceEthernet",
        "contentType": "pythonCli",
        "tags": ["interface_edit_policy,", "interface_edit_shared_policy,", "int_trunk"],
        "content": "##template properties\nuserDefined = true;\n##\n",
        "supportedPlatforms": ["all"],
        "parameters": [{"name": "VALUE", "parameterType": parameter_type, "optional": True}],
    }
    calls: list[tuple[HttpVerbEnum, str, dict[str, Any] | None]] = []

    def request(self, *, path, verb, data=None, **_kwargs):
        calls.append((verb, path, deepcopy(data)))
        if path == TEMPLATE_PATH and verb == HttpVerbEnum.GET:
            return deepcopy(template)
        if path == GROUP_PATH and verb == HttpVerbEnum.GET:
            return actual.to_payload()
        if path == GROUP_PATH and verb == HttpVerbEnum.PUT:
            response = {
                "RETURN_CODE": 500 if write_mode == "ambiguous" else 200,
                "METHOD": "PUT",
                "REQUEST_PATH": path,
                "MESSAGE": "controller interrupted" if write_mode == "ambiguous" else "OK",
                "DATA": {"message": "already present" if write_mode == "unmodified" else "updated"},
                "modified": "false" if write_mode == "unmodified" else "true",
            }
            self.rest_send.response_current = response
            self.rest_send.add_response(response)
            if write_mode == "ambiguous":
                raise RuntimeError("controller interrupted after PUT")
            return response["DATA"]
        raise AssertionError(f"Unexpected {verb} request: {path}")

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", request)
    orchestrator = ManageInterfaceGroupOrchestrator(
        rest_send=RestSend(
            {
                "check_mode": False,
                "fabric_name": "fab1",
                "state": "merged",
                "config_actions": {"deploy": True, "type": "resource"},
                "config": [],
            }
        )
    )
    orchestrator._existing_groups = {"custom-group": deepcopy(before)}
    orchestrator.preflight([proposed])
    collection = NDConfigCollection(InterfaceGroupConfigModel, [deepcopy(before)])
    # Membership must still trigger the real update when template values match.
    assert collection.get_diff_config(proposed, exclude_unset=True) == "changed"
    final = collection.merge(proposed)
    return orchestrator, before, final, calls


@pytest.mark.parametrize(
    ("parameter_type", "desired", "echo"),
    [
        ("boolean", "true", "TRUE"),
        ("boolean", "false", "FALSE"),
        ("boolean", "true", True),
        ("integer", "001", "1"),
        ("integer", "001", 1),
        ("long", "0001", "1"),
        ("float", "1.00", "1.0"),
    ],
)
def test_unmodified_merged_put_confirms_declared_template_echoes(monkeypatch, parameter_type, desired, echo):
    """Accepted quoted values keep their declared semantics after collection merge."""
    orchestrator, before, final, calls = _workflow(monkeypatch, parameter_type, desired, echo)

    orchestrator._put_and_record(before, final)

    assert [(verb, path) for verb, path, _payload in calls] == [
        (HttpVerbEnum.GET, TEMPLATE_PATH),
        (HttpVerbEnum.PUT, GROUP_PATH),
        (HttpVerbEnum.GET, GROUP_PATH),
    ]
    payload = calls[1][2]
    assert payload["policyDetails"]["templateConfig"] == {"VALUE": desired}
    assert payload["switchInterfaces"] == [{"switchId": "SN1", "interfaceNames": ["Ethernet1/10", "Ethernet1/9"]}]
    assert orchestrator.has_accepted_changes is False
    assert orchestrator.has_unattributed_observed_state is True
    assert orchestrator._pending_interfaces == set()
    assert orchestrator._interface_pairs(orchestrator._existing_groups["custom-group"]) == {EXISTING_MEMBER, ADDED_MEMBER}


@pytest.mark.parametrize(("parameter_type", "desired", "echo"), [("boolean", "true", "FALSE"), ("integer", "001", "2")])
def test_unmodified_merged_put_still_rejects_different_values(monkeypatch, parameter_type, desired, echo):
    """Retaining schema must never make a genuinely different readback acceptable."""
    orchestrator, before, final, calls = _workflow(monkeypatch, parameter_type, desired, echo)

    with pytest.raises(RuntimeError, match="bounded readback did not confirm"):
        orchestrator._put_and_record(before, final)

    assert sum(verb == HttpVerbEnum.PUT for verb, _path, _payload in calls) == 1
    assert sum(verb == HttpVerbEnum.GET and path == GROUP_PATH for verb, path, _payload in calls) == 3
    assert orchestrator._existing_groups["custom-group"].to_payload() == before.to_payload()
    assert orchestrator.has_accepted_changes is False
    assert orchestrator.has_unattributed_observed_state is False
    assert orchestrator._pending_interfaces == set()


def test_successful_merged_put_keeps_existing_fast_path(monkeypatch):
    """Normal accepted PUTs require no extra readback or template parameter request."""
    orchestrator, before, final, calls = _workflow(monkeypatch, "boolean", "true", "FALSE", write_mode="success")

    orchestrator._put_and_record(before, final)

    assert [(verb, path) for verb, path, _payload in calls] == [(HttpVerbEnum.GET, TEMPLATE_PATH), (HttpVerbEnum.PUT, GROUP_PATH)]
    assert orchestrator.has_accepted_changes is True
    assert orchestrator.has_unresolved_accepted_changes is False
    assert orchestrator.has_unattributed_observed_state is False
    assert orchestrator._pending_interfaces == {EXISTING_MEMBER, ADDED_MEMBER}


@pytest.mark.parametrize(("parameter_type", "desired", "echo"), [("boolean", "true", "TRUE"), ("integer", "001", "1")])
def test_ambiguous_put_records_matching_merged_state_but_preserves_failure(monkeypatch, parameter_type, desired, echo):
    """Matching readback fixes accepted-state bookkeeping without hiding a PUT error."""
    orchestrator, before, final, calls = _workflow(monkeypatch, parameter_type, desired, echo, write_mode="ambiguous")

    with pytest.raises(RuntimeError, match="controller interrupted after PUT"):
        orchestrator._put_and_record(before, final)

    assert [(verb, path) for verb, path, _payload in calls] == [
        (HttpVerbEnum.GET, TEMPLATE_PATH),
        (HttpVerbEnum.PUT, GROUP_PATH),
        (HttpVerbEnum.GET, GROUP_PATH),
    ]
    assert orchestrator.has_accepted_changes is True
    assert orchestrator.has_unresolved_accepted_changes is False
    # Readback retains the original policy echo, so only new membership deploys.
    assert orchestrator._pending_interfaces == {ADDED_MEMBER}
    assert orchestrator._interface_pairs(orchestrator._existing_groups["custom-group"]) == {EXISTING_MEMBER, ADDED_MEMBER}


@pytest.mark.parametrize(("parameter_type", "desired", "echo"), [("boolean", "true", "FALSE"), ("integer", "001", "2")])
def test_ambiguous_put_does_not_attribute_mismatched_readback(monkeypatch, parameter_type, desired, echo):
    """A modified=true error remains unresolved when actual policy differs."""
    orchestrator, before, final, calls = _workflow(monkeypatch, parameter_type, desired, echo, write_mode="ambiguous")

    with pytest.raises(RuntimeError, match="controller interrupted after PUT"):
        orchestrator._put_and_record(before, final)

    assert sum(verb == HttpVerbEnum.PUT for verb, _path, _payload in calls) == 1
    assert sum(verb == HttpVerbEnum.GET and path == GROUP_PATH for verb, path, _payload in calls) == 3
    assert orchestrator.has_accepted_changes is True
    assert orchestrator.has_unresolved_accepted_changes is True
    assert orchestrator._pending_interfaces == set()
    assert orchestrator._existing_groups["custom-group"].to_payload() == before.to_payload()


def test_string_input_keeps_literal_readback_comparison(monkeypatch):
    """Fixing metadata transfer must not regress exact custom-template text semantics."""
    orchestrator, before, final, _calls = _workflow(monkeypatch, "string", "true", "TRUE")

    with pytest.raises(RuntimeError, match="bounded readback did not confirm"):
        orchestrator._put_and_record(before, final)

    assert orchestrator.has_accepted_changes is False
    assert orchestrator._pending_interfaces == set()
