# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Regression tests for safe updates to authentic port-channel member records (IFACE-004).

These tests deliberately exercise the real ``NDStateMachine`` and concrete access,
trunk, and routed orchestrators.  The controller transport is replaced with a small
in-memory recorder, but discovery, member projection, diff planning, preflight, and
payload construction all remain production code.

The fixtures use the real policy discriminators returned by Nexus Dashboard:
``accessPoMember``, ``poMember``, ``l3PoMember``, ``iosXeAccessPoMember``,
``iosXeTrunkPoMember``, and ``iosXeL3PoMember``.  A host
policy decorated with ``operData.portChannelId`` is not a valid member fixture and
must never be used to test this feature.
"""

# pylint: disable=protected-access
# pylint: disable=too-many-arguments

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from types import MethodType
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import (
    EthernetAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_routed_interface import (
    EthernetRoutedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)

SWITCH_IP = "192.168.1.1"
SWITCH_ID = "FDO11111AAA"
PORT_CHANNEL_ID = 20


@dataclass(frozen=True)
class _MemberCase:
    """One supported member-policy family and its user-facing host orchestrator."""

    name: str
    orchestrator_class: type
    member_policy_type: str
    parent_policy_type: str
    member_mode: str
    parent_mode: str
    network_os_type: str
    interface_name: str
    preserved_policy: dict[str, Any]
    unsafe_policy: dict[str, Any]


MEMBER_CASES = (
    _MemberCase(
        name="access_nxos",
        orchestrator_class=EthernetAccessInterfaceOrchestrator,
        member_policy_type="accessPoMember",
        parent_policy_type="accessPoHost",
        # Captured ND intent uses access mode even though operational data can
        # report trunk mode after the member joins its port-channel.
        member_mode="access",
        parent_mode="access",
        network_os_type="nx-os",
        interface_name="Ethernet1/24",
        preserved_policy={
            "cdp": False,
            "debounceTimer": 250,
            "debounceLinkupTimer": 2000,
            "fec": "rsFec",
            "lacpPortPriority": 4096,
            "lacpRate": "fast",
        },
        unsafe_policy={"access_vlan": 200},
    ),
    _MemberCase(
        name="trunk_nxos",
        orchestrator_class=EthernetTrunkHostInterfaceOrchestrator,
        member_policy_type="poMember",
        parent_policy_type="trunkPoHost",
        member_mode="trunk",
        parent_mode="trunk",
        network_os_type="nx-os",
        interface_name="Ethernet1/25",
        preserved_policy={
            "allowedVlans": "10-20,100",
            "cdp": False,
            "debounceTimer": 250,
            "debounceLinkupTimer": 2000,
            "fec": "rsFec",
            "lacpPortPriority": 4096,
            "lacpRate": "fast",
        },
        unsafe_policy={"allowed_vlans": "200-300"},
    ),
    _MemberCase(
        name="routed_nxos",
        orchestrator_class=EthernetRoutedInterfaceOrchestrator,
        member_policy_type="l3PoMember",
        parent_policy_type="l3Po",
        member_mode="routed",
        parent_mode="routed",
        network_os_type="nx-os",
        interface_name="Ethernet1/26",
        preserved_policy={"fec": "rsFec"},
        unsafe_policy={"mtu": 9000},
    ),
    _MemberCase(
        name="routed_iosxe",
        orchestrator_class=EthernetRoutedInterfaceOrchestrator,
        member_policy_type="iosXeL3PoMember",
        parent_policy_type="iosXeL3PortChannel",
        member_mode="routed",
        parent_mode="routed",
        network_os_type="ios-xe",
        interface_name="GigabitEthernet3",
        preserved_policy={},
        unsafe_policy={"mtu": 9000},
    ),
    _MemberCase(
        name="access_iosxe",
        orchestrator_class=EthernetAccessInterfaceOrchestrator,
        member_policy_type="iosXeAccessPoMember",
        parent_policy_type="iosXeAccessPoHost",
        member_mode="access",
        parent_mode="access",
        network_os_type="ios-xe",
        interface_name="GigabitEthernet1/0/24",
        preserved_policy={},
        unsafe_policy={"access_vlan": 200},
    ),
    _MemberCase(
        name="trunk_iosxe",
        orchestrator_class=EthernetTrunkHostInterfaceOrchestrator,
        member_policy_type="iosXeTrunkPoMember",
        parent_policy_type="iosXeTrunkPoHost",
        member_mode="trunk",
        parent_mode="trunk",
        network_os_type="ios-xe",
        interface_name="GigabitEthernet1/0/25",
        preserved_policy={"allowedVlans": "100-200"},
        unsafe_policy={"allowed_vlans": "200-300"},
    ),
)


def _case_id(case: _MemberCase) -> str:
    return case.name


@dataclass
class _Controller:
    """Record controller calls and serve one switch's interface inventory."""

    interfaces: list[dict[str, Any]]
    calls: list[dict[str, Any]] = field(default_factory=list)
    fail_put: bool = False
    fail_put_number: int | None = None
    inventory_pages: dict[int, dict[str, Any]] | None = None

    def request(
        self,
        _orchestrator,
        path: str,
        verb: HttpVerbEnum,
        data: dict[str, Any] | None = None,
        not_found_ok: bool = False,
        operation_type=None,
    ) -> dict[str, Any]:
        """Return deterministic GET/PUT responses and reject unexpected requests."""
        del not_found_ok, operation_type
        verb_value = verb.value if isinstance(verb, HttpVerbEnum) else str(verb)
        self.calls.append({"path": path, "verb": verb_value, "data": deepcopy(data)})
        if verb_value == HttpVerbEnum.GET.value and path.split("?", 1)[0].endswith(f"/switches/{SWITCH_ID}/interfaces"):
            if self.inventory_pages is not None:
                offset = int(parse_qs(urlsplit(path).query).get("offset", ["0"])[0])
                return deepcopy(self.inventory_pages[offset])
            return {"interfaces": deepcopy(self.interfaces)}
        if verb_value == HttpVerbEnum.GET.value and "/api/v1/manage/links" in path:
            return {"links": []}
        if verb_value == HttpVerbEnum.PUT.value and "/interfaces/" in path:
            put_number = sum(call["verb"] == HttpVerbEnum.PUT.value for call in self.calls)
            if self.fail_put or put_number == self.fail_put_number:
                raise RuntimeError("injected member PUT failure")
            return {}
        if verb_value == HttpVerbEnum.POST.value and path.endswith("/interfaceActions/preview"):
            interfaces = data.get("interfaces", []) if isinstance(data, dict) else []
            return {
                "configurationDiffs": [
                    {
                        "interfaceName": item["interfaceName"],
                        "switchId": item["switchId"],
                        "status": "success",
                        "combinedConfigs": [{"configType": "pending", "lines": 0, "config": ""}],
                    }
                    for item in interfaces
                ]
            }
        if verb_value == HttpVerbEnum.POST.value and path.endswith("/interfaceActions/deploy"):
            return {}
        raise AssertionError(f"Unexpected controller request: {verb_value} {path}; data={data}")

    @property
    def _encoded_member_name(self) -> str:
        member = next(item for item in self.interfaces if item.get("interfaceType") == "ethernet")
        return member["interfaceName"].replace("/", "%2F")


class _FabricContext:
    """Minimal already-loaded fabric context used by interface orchestrators."""

    switch_map = {SWITCH_IP: SWITCH_ID}

    def __init__(self, platform_type: str) -> None:
        self.platform_type = PlatformType(platform_type)

    @staticmethod
    def validate_for_read() -> None:
        """The synthetic fabric is local, present, and readable."""

    @staticmethod
    def validate_for_mutation() -> None:
        """The synthetic fabric is local, present, and not frozen."""

    @staticmethod
    def get_switch_id(switch_ip: str) -> str:
        """Resolve the sole test switch."""
        if switch_ip != SWITCH_IP:
            raise RuntimeError(f"Switch with IP '{switch_ip}' not found in fabric 'fabric_1'.")
        return SWITCH_ID

    def get_platform_type(self, switch_ip: str) -> PlatformType:
        """Return the platform reported by the synthetic switch inventory."""
        if switch_ip != SWITCH_IP:
            raise RuntimeError(f"Switch with IP '{switch_ip}' not found in fabric 'fabric_1'.")
        return self.platform_type


def _member_record(
    case: _MemberCase,
    *,
    policy_overrides: dict[str, Any] | None = None,
    operational_port_channel_id: Any = PORT_CHANNEL_ID,
) -> dict[str, Any]:
    """Return an authentic configured port-channel member response."""
    policy = {
        "policyType": case.member_policy_type,
        "portChannelId": f"Port-channel{PORT_CHANNEL_ID}",
        "portChannelMode": "active",
        "adminState": True,
        "description": "old member description",
        "extraConfig": "logging event link-status",
        **case.preserved_policy,
        **(policy_overrides or {}),
    }
    # ND 4.2.1 injects this undeclared key on NX-OS member reads.  It is useful
    # evidence that response-only/unknown data is not blindly replayed.
    if case.network_os_type == "nx-os":
        policy.setdefault("ptp", False)
    return {
        "interfaceName": case.interface_name,
        "interfaceType": "ethernet",
        "switchId": SWITCH_ID,
        "configData": {
            "mode": case.member_mode,
            "networkOS": {
                "networkOSType": case.network_os_type,
                "policy": policy,
            },
        },
        "operData": {"portChannelId": operational_port_channel_id},
    }


def _parent_record(case: _MemberCase) -> dict[str, Any]:
    """Return the compatible parent that proves ownership of the member."""
    return {
        "interfaceName": f"port-channel{PORT_CHANNEL_ID}",
        "interfaceType": "portChannel",
        "switchId": SWITCH_ID,
        "configData": {
            "mode": case.parent_mode,
            "networkOS": {
                "networkOSType": case.network_os_type,
                "policy": {
                    "policyType": case.parent_policy_type,
                    "ports": [case.interface_name],
                    "portChannelMode": "active",
                },
            },
        },
    }


def _config(
    case: _MemberCase,
    policy: dict[str, Any] | None = None,
    *,
    interface_name: str | None = None,
) -> dict[str, Any]:
    """Return valid user input for the case's host-facing standalone module."""
    network_os: dict[str, Any] = {"policy": policy or {}}
    if case.name.startswith("routed_") or case.network_os_type == "ios-xe":
        network_os["network_os_type"] = case.network_os_type
    return {
        "switch_ip": SWITCH_IP,
        "interface_name": interface_name or case.interface_name,
        "config_data": {"network_os": network_os},
    }


def _host_record(case: _MemberCase, interface_name: str) -> dict[str, Any]:
    """Return an ordinary host-policy response owned by the tested orchestrator."""
    policy_type = {
        "access_nxos": "accessHost",
        "access_iosxe": "iosXeAccess",
        "trunk_nxos": "trunkHost",
        "trunk_iosxe": "iosXeTrunkHost",
        "routed_nxos": "routedHost",
        "routed_iosxe": "iosXeRoutedHost",
    }[case.name]
    return {
        "interfaceName": interface_name,
        "interfaceType": "ethernet",
        "switchId": SWITCH_ID,
        "configData": {
            "mode": case.parent_mode,
            "networkOS": {
                "networkOSType": case.network_os_type,
                "policy": {
                    "policyType": policy_type,
                    "description": "managed host",
                },
            },
        },
        "operData": {"portChannelId": -1},
    }


def _host_record_with_stale_membership(case: _MemberCase) -> dict[str, Any]:
    """Return current host intent with a stale positive operational bundle ID."""
    record = _host_record(case, case.interface_name)
    record["operData"]["portChannelId"] = PORT_CHANNEL_ID
    return record


def _rest_send(params: dict[str, Any]) -> RestSend:
    """Build the RestSend required by a concrete orchestrator."""
    rest_send = RestSend({**params, "check_mode": False})
    rest_send.response_handler = ResponseHandler()
    return rest_send


def _state_machine(
    case: _MemberCase,
    *,
    state: str,
    policy: dict[str, Any] | None = None,
    check_mode: bool = False,
    member_policy_overrides: dict[str, Any] | None = None,
    operational_port_channel_id: Any = PORT_CHANNEL_ID,
    config_override: list[dict[str, Any]] | None = None,
    inventory_override: list[dict[str, Any]] | None = None,
    fail_put: bool = False,
    fail_put_number: int | None = None,
    deploy: bool = False,
    inventory_pages: dict[int, dict[str, Any]] | None = None,
) -> tuple[NDStateMachine, _Controller]:
    """Construct a state machine backed by authentic member and parent inventory."""
    if config_override is not None:
        config = config_override
    elif state == "gathered":
        # Gathered config is a list of optional read filters, not a write-state
        # model.  An empty list intentionally queries the whole fabric.
        config = []
    elif state == "deleted":
        config = [{"switch_ip": SWITCH_IP, "interface_name": case.interface_name}]
    else:
        config = [_config(case, policy)]
    params = {
        "state": state,
        "config": config,
        "output_level": "normal",
        "ignore_errors": False,
        "fabric_name": "fabric_1",
        "config_actions": {"deploy": deploy},
    }
    orchestrator = case.orchestrator_class(rest_send=_rest_send(params))
    orchestrator.apply_config_actions(params)
    inventory = inventory_override or [
        _parent_record(case),
        _member_record(
            case,
            policy_overrides=member_policy_overrides,
            operational_port_channel_id=operational_port_channel_id,
        ),
    ]
    controller = _Controller(inventory, fail_put=fail_put, fail_put_number=fail_put_number, inventory_pages=inventory_pages)
    object.__setattr__(orchestrator, "_fabric_context", _FabricContext(case.network_os_type))
    object.__setattr__(orchestrator, "_request", MethodType(controller.request, orchestrator))

    module = MockAnsibleModule()
    module.params = params
    module.check_mode = check_mode
    module.no_log_values = set()
    return NDStateMachine(module=module, model_orchestrator=orchestrator), controller


def _write_calls(controller: _Controller) -> list[dict[str, Any]]:
    """Return all recorded PUT/POST/DELETE requests."""
    return [call for call in controller.calls if call["verb"] != HttpVerbEnum.GET.value]


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_member_merge_is_planned_as_update_and_preserves_member_payload(
    case: _MemberCase,
) -> None:
    """A named real member is updated with PUT and retains its policy/parent fields."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={
            "admin_state": False,
            "description": "updated by standalone module",
            "extra_config": "logging event trunk-status",
        },
    )

    before = list(state_machine.before)
    assert [(item.switch_ip, item.interface_name) for item in before] == [(SWITCH_IP, case.interface_name)]

    state_machine.manage_state()

    writes = _write_calls(controller)
    assert len(writes) == 1
    assert writes[0]["verb"] == HttpVerbEnum.PUT.value
    assert writes[0]["path"].endswith("/interfaces/" + case.interface_name.replace("/", "%2F"))
    payload = writes[0]["data"]
    policy = payload["configData"]["networkOS"]["policy"]
    assert payload["interfaceName"] == case.interface_name
    assert payload["switchId"] == SWITCH_ID
    assert payload["configData"]["mode"] == case.member_mode
    assert payload["configData"]["networkOS"]["networkOSType"] == case.network_os_type
    assert policy["policyType"] == case.member_policy_type
    assert policy["portChannelId"] == f"Port-channel{PORT_CHANNEL_ID}"
    assert policy["portChannelMode"] == "active"
    assert policy["adminState"] is False
    assert policy["description"] == "updated by standalone module"
    assert policy["extraConfig"] == "logging event trunk-status"
    for key, value in case.preserved_policy.items():
        assert policy[key] == value
    assert "ptp" not in policy
    assert "operData" not in payload
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)
    inventory_gets = [
        call
        for call in controller.calls
        if call["verb"] == HttpVerbEnum.GET.value and call["path"].split("?", 1)[0].endswith(f"/switches/{SWITCH_ID}/interfaces")
    ]
    assert len(inventory_gets) == 1


@pytest.mark.parametrize("case", MEMBER_CASES[:3], ids=_case_id)
@pytest.mark.parametrize("ptp", [True, False, "true", "false"])
def test_nxos_member_update_accepts_qualified_ptp_echo_without_replaying_it(
    case: _MemberCase,
    ptp: object,
) -> None:
    """Observed 4.2.1 and 4.3.1 ``ptp`` echoes permit the same safe PUT."""

    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "updated with qualified ptp echo"},
        member_policy_overrides={"ptp": ptp},
    )

    state_machine.manage_state()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [HttpVerbEnum.PUT.value]
    policy = writes[0]["data"]["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == case.member_policy_type
    assert policy["description"] == "updated with qualified ptp echo"
    assert "ptp" not in policy
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_member_on_second_inventory_page_uses_put_and_never_host_post(case: _MemberCase) -> None:
    """A named member omitted from page one remains an exact member-policy update."""

    pages = {
        0: {
            "interfaces": [_parent_record(case)],
            "meta": {"counts": {"total": 2, "remaining": 1}},
        },
        1: {
            "interfaces": [_member_record(case)],
            "meta": {"counts": {"total": 2, "remaining": 0}},
        },
    }
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "member discovered on page two"},
        inventory_pages=pages,
    )

    state_machine.manage_state()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [HttpVerbEnum.PUT.value]
    assert writes[0]["data"]["configData"]["networkOS"]["policy"]["policyType"] == case.member_policy_type
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)
    inventory_gets = [call for call in controller.calls if call["verb"] == HttpVerbEnum.GET.value and "/switches/FDO11111AAA/interfaces?" in call["path"]]
    assert [parse_qs(urlsplit(call["path"]).query)["offset"] for call in inventory_gets] == [["0"], ["1"]]


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_parent_on_second_inventory_page_proves_member_ownership(case: _MemberCase) -> None:
    """Ownership validation waits for a parent record returned on the next page."""

    pages = {
        0: {
            "interfaces": [_member_record(case)],
            "meta": {"counts": {"total": 2, "remaining": 1}},
        },
        1: {
            "interfaces": [_parent_record(case)],
            "meta": {"counts": {"total": 2, "remaining": 0}},
        },
    }
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "parent discovered on page two"},
        inventory_pages=pages,
    )

    state_machine.manage_state()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [HttpVerbEnum.PUT.value]
    assert writes[0]["data"]["configData"]["networkOS"]["policy"]["policyType"] == case.member_policy_type


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
@pytest.mark.parametrize(
    "requested_policy",
    (
        {"admin_state": False},
        {"description": "safe member description"},
        {"extra_config": "logging event trunk-status"},
    ),
    ids=("admin_state", "description", "extra_config"),
)
def test_each_safe_member_field_uses_put(case: _MemberCase, requested_policy: dict[str, Any]) -> None:
    """Each documented member-safe field is independently mutable."""
    state_machine, controller = _state_machine(case, state="merged", policy=requested_policy)

    state_machine.manage_state()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [HttpVerbEnum.PUT.value]
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_idempotent_member_merge_performs_no_write(case: _MemberCase) -> None:
    """A safe field already at the requested value is neither PUT nor deployed."""
    state_machine, controller = _state_machine(case, state="merged", policy={"description": "old member description"})

    state_machine.manage_state()

    assert _write_calls(controller) == []
    assert state_machine.output.format()["changed"] is False
    assert state_machine.model_orchestrator._pending_deploys == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_member_update_deploys_exactly_once_when_enabled(case: _MemberCase) -> None:
    """Each standalone member policy produces one PUT and one consolidated deploy."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "deployed member update"},
        deploy=True,
    )

    state_machine.manage_state()
    state_machine.model_orchestrator.deploy_pending()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [
        HttpVerbEnum.PUT.value,
        HttpVerbEnum.POST.value,
    ]
    assert writes[1]["path"].endswith("/interfaceActions/deploy")
    assert writes[1]["data"] == {
        "interfaces": [
            {
                "interfaceName": case.interface_name,
                "switchId": SWITCH_ID,
            }
        ]
    }
    assert state_machine.model_orchestrator._pending_deploys == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_idempotent_member_replay_verifies_but_never_redeploys_when_converged(case: _MemberCase) -> None:
    """Deploy true verifies execution convergence without repeating PUT or deploy."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "old member description"},
        deploy=True,
    )

    state_machine.manage_state()
    state_machine.model_orchestrator.deploy_pending()

    writes = _write_calls(controller)
    assert len(writes) == 1
    assert writes[0]["verb"] == HttpVerbEnum.POST.value
    assert writes[0]["path"].endswith("/interfaceActions/preview")
    assert state_machine.output.format()["changed"] is False


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_unsafe_member_field_fails_atomically_before_write(case: _MemberCase) -> None:
    """A mixed safe/unsafe request is rejected without a partial member update."""
    requested = {"description": "must not be partially applied", **case.unsafe_policy}
    state_machine, controller = _state_machine(case, state="merged", policy=requested)

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(only|cannot|safe)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []
    assert state_machine.model_orchestrator._pending_deploys == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_member_update_rejects_replacement_states(case: _MemberCase, state: str) -> None:
    """Standalone modules require merged semantics for a member-safe update."""
    state_machine, controller = _state_machine(case, state=state, policy={"description": "replacement is unsafe"})

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*merged"):
        state_machine.manage_state()

    assert _write_calls(controller) == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_explicit_member_delete_is_rejected(case: _MemberCase) -> None:
    """Deleting/defaulting a member remains a parent-controlled operation."""
    state_machine, controller = _state_machine(case, state="deleted")

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(delete|normalize|parent)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_check_mode_plans_change_without_sending_member_put(case: _MemberCase) -> None:
    """Check mode runs member validation and reports the planned update without I/O."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "check mode update"},
        check_mode=True,
    )

    state_machine.manage_state()

    assert _write_calls(controller) == []
    assert state_machine.output.format()["changed"] is True


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_gathered_keeps_members_out_of_host_family_output(case: _MemberCase) -> None:
    """Gathered output remains scoped to host policies and does not expose planning projections."""
    state_machine, controller = _state_machine(case, state="gathered")

    state_machine.manage_state()

    assert list(state_machine.before) == []
    assert _write_calls(controller) == []
    assert state_machine.output.format()["changed"] is False


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
@pytest.mark.parametrize("operational_id", (-1, None), ids=("stale_minus_one", "missing"))
def test_configured_member_delete_is_rejected_when_operational_membership_is_stale(case: _MemberCase, operational_id: Any) -> None:
    """Configured member intent blocks deletion even when operData is stale."""
    state_machine, controller = _state_machine(
        case,
        state="deleted",
        operational_port_channel_id=operational_id,
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(delete|normalize|parent)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_unsafe_member_request_is_rejected_in_check_mode(case: _MemberCase) -> None:
    """Dry-run preflight enforces the same safe-field allowlist as execution."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "must not apply", **case.unsafe_policy},
        check_mode=True,
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(only|cannot|safe)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_member_delete_is_rejected_in_check_mode(case: _MemberCase) -> None:
    """Dry-run delete cannot report a member normalization execution would refuse."""
    state_machine, controller = _state_machine(case, state="deleted", check_mode=True)

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(delete|normalize|parent)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
@pytest.mark.parametrize("operation", ("create", "create_bulk"))
def test_direct_create_paths_never_post_an_existing_member(case: _MemberCase, operation: str) -> None:
    """Defensive direct calls cannot bypass UPDATE planning and issue POST."""
    state_machine, controller = _state_machine(case, state="merged", policy={"description": "direct"})
    model = next(iter(state_machine.proposed))
    orchestrator = state_machine.model_orchestrator

    with pytest.raises(RuntimeError, match=r"(?i)member.*never.*create"):
        if operation == "create":
            orchestrator.create(model)
        else:
            orchestrator.create_bulk([model])

    assert _write_calls(controller) == []
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
@pytest.mark.parametrize("operation", ("delete", "delete_bulk"))
def test_direct_delete_paths_reject_configured_member_with_stale_operdata(case: _MemberCase, operation: str) -> None:
    """Configured membership guards every delete entry point without relying on operData."""
    state_machine, controller = _state_machine(
        case,
        state="deleted",
        operational_port_channel_id=-1,
    )
    model = next(iter(state_machine.proposed))
    orchestrator = state_machine.model_orchestrator

    with pytest.raises(RuntimeError, match=r"(?i)member.*(normalize|strip)"):
        if operation == "delete":
            orchestrator.delete(model)
        else:
            orchestrator.delete_bulk([model])

    assert _write_calls(controller) == []
    assert orchestrator._pending_normalizes == []
    assert orchestrator._pending_resets == []


def test_stale_operational_membership_allows_single_host_delete() -> None:
    """Current host intent wins over stale positive operData after parent removal."""
    case = MEMBER_CASES[0]
    state_machine, controller = _state_machine(
        case,
        state="deleted",
        inventory_override=[_host_record_with_stale_membership(case)],
    )
    model = next(iter(state_machine.proposed))
    orchestrator = state_machine.model_orchestrator

    orchestrator.delete(model)

    assert _write_calls(controller) == []
    assert orchestrator._pending_normalizes == [(case.interface_name, SWITCH_ID)]
    assert orchestrator._pending_deploys == [(case.interface_name, SWITCH_ID)]


def test_stale_operational_membership_allows_bulk_host_delete() -> None:
    """The normal state-machine bulk-delete path applies the same intent-first decision."""
    case = MEMBER_CASES[0]
    state_machine, controller = _state_machine(
        case,
        state="deleted",
        inventory_override=[_host_record_with_stale_membership(case)],
    )

    state_machine.manage_state()

    assert _write_calls(controller) == []
    assert state_machine.model_orchestrator._pending_normalizes == [(case.interface_name, SWITCH_ID)]
    assert state_machine.model_orchestrator._pending_deploys == [(case.interface_name, SWITCH_ID)]
    assert state_machine.output.format()["changed"] is True


def test_stale_operational_membership_allows_overridden_host_cleanup() -> None:
    """Overridden no longer preserves an omitted host solely because operData is stale."""
    case = MEMBER_CASES[0]
    state_machine, controller = _state_machine(
        case,
        state="overridden",
        config_override=[],
        inventory_override=[_host_record_with_stale_membership(case)],
    )

    state_machine.manage_state()

    assert _write_calls(controller) == []
    assert state_machine.model_orchestrator._pending_normalizes == [(case.interface_name, SWITCH_ID)]
    assert state_machine.model_orchestrator._pending_deploys == [(case.interface_name, SWITCH_ID)]


def test_parent_claim_blocks_host_policy_delete() -> None:
    """A current parent claim outranks a host-policy echo during reconciliation."""
    case = MEMBER_CASES[0]
    state_machine, controller = _state_machine(
        case,
        state="deleted",
        inventory_override=[
            _parent_record(case),
            _host_record_with_stale_membership(case),
        ],
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)claimed by parent intent.*port-channel20"):
        state_machine.manage_state()

    assert _write_calls(controller) == []
    assert state_machine.model_orchestrator._pending_normalizes == []
    assert state_machine.model_orchestrator._pending_deploys == []


def test_unexplained_positive_operational_membership_fails_closed() -> None:
    """A non-host policy cannot use the stale-operData exception."""
    case = MEMBER_CASES[0]
    unknown = _host_record_with_stale_membership(case)
    unknown["configData"]["networkOS"]["policy"]["policyType"] = "unmodeledEthernetPolicy"
    state_machine, controller = _state_machine(
        case,
        state="deleted",
        inventory_override=[unknown],
    )
    model = next(iter(state_machine.proposed))

    with pytest.raises(RuntimeError, match=r"(?i)inconsistent ownership evidence"):
        state_machine.model_orchestrator.delete(model, existing_data=unknown)

    assert _write_calls(controller) == []
    assert state_machine.model_orchestrator._pending_normalizes == []
    assert state_machine.model_orchestrator._pending_deploys == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_overridden_omits_member_from_host_family_scope(case: _MemberCase) -> None:
    """An omitted member is preserved while an ordinary host remains converged."""
    host_name = "Ethernet1/30" if case.network_os_type == "nx-os" else "GigabitEthernet4"
    inventory = [
        _parent_record(case),
        _member_record(
            case,
            operational_port_channel_id=-1,
        ),
        _host_record(case, host_name),
    ]
    state_machine, controller = _state_machine(
        case,
        state="overridden",
        config_override=[
            _config(
                case,
                {"description": "managed host"},
                interface_name=host_name,
            )
        ],
        inventory_override=inventory,
    )
    assert [item.interface_name for item in state_machine.before] == [host_name]

    state_machine.manage_state()

    assert state_machine.output.format()["changed"] is False
    assert _write_calls(controller) == []
    assert state_machine.model_orchestrator._pending_normalizes == []
    assert state_machine.model_orchestrator._pending_resets == []


@pytest.mark.parametrize(
    "case,unsafe_policy,member_policy_overrides",
    [
        (MEMBER_CASES[0], {"cdp": False}, {"cdp": False}),
        (MEMBER_CASES[1], {"allowed_vlans": "10-20,100"}, {"allowedVlans": "10-20,100"}),
        (MEMBER_CASES[2], {"fec": "rsFec"}, {"fec": "rsFec"}),
    ],
    ids=("access_nxos", "trunk_nxos", "routed_nxos"),
)
def test_explicit_unsafe_field_is_rejected_even_when_equal_to_current(
    case: _MemberCase,
    unsafe_policy: dict[str, Any],
    member_policy_overrides: dict[str, Any],
) -> None:
    """A real shared-but-unsafe member field is rejected even when unchanged."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy=unsafe_policy,
        member_policy_overrides=member_policy_overrides,
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)member.*(only|cannot|safe)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_member_put_failure_never_falls_back_to_post_or_queues_deploy(
    case: _MemberCase,
) -> None:
    """A rejected member PUT fails closed without host-policy fallback or deployment."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "controller will reject"},
        fail_put=True,
    )

    with pytest.raises(NDStateMachineError, match=r"injected member PUT failure"):
        state_machine.manage_state()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [HttpVerbEnum.PUT.value]
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)
    assert state_machine.model_orchestrator._pending_deploys == []
    output = state_machine.output.format()
    assert output["changed"] is False
    assert output["after"] == output["before"]
    assert output["diff"] == []


@pytest.mark.parametrize(
    ("target_case", "member_case"),
    (
        (MEMBER_CASES[0], MEMBER_CASES[1]),
        (MEMBER_CASES[1], MEMBER_CASES[0]),
        (MEMBER_CASES[2], MEMBER_CASES[1]),
        (MEMBER_CASES[3], MEMBER_CASES[1]),
    ),
    ids=(
        "access_vs_trunk",
        "trunk_vs_access",
        "routed_nx_vs_trunk",
        "routed_xe_vs_trunk",
    ),
)
@pytest.mark.parametrize("state", ("merged", "deleted"))
def test_wrong_family_member_is_rejected_without_write(target_case: _MemberCase, member_case: _MemberCase, state: str) -> None:
    """A standalone family cannot create over or delete another family's member."""
    inventory = [_parent_record(member_case), _member_record(member_case)]
    if state == "deleted":
        config = [{"switch_ip": SWITCH_IP, "interface_name": member_case.interface_name}]
    else:
        config = [
            _config(
                target_case,
                {"description": "wrong family"},
                interface_name=member_case.interface_name,
            )
        ]
    state_machine, controller = _state_machine(
        target_case,
        state=state,
        config_override=config,
        inventory_override=inventory,
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)member"):
        state_machine.manage_state()

    assert _write_calls(controller) == []
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
@pytest.mark.parametrize("state", ("merged", "deleted"))
def test_protected_internal_member_is_rejected_without_write(case: _MemberCase, state: str) -> None:
    """Known internal member intent cannot be overwritten or normalized."""
    state_machine, controller = _state_machine(
        case,
        state=state,
        member_policy_overrides={"policyType": "l3PoMemberInternal"},
    )

    with pytest.raises(NDStateMachineError, match=r"(?i)(member|protected|fabric)"):
        state_machine.manage_state()

    assert _write_calls(controller) == []
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)


@pytest.mark.parametrize("case", MEMBER_CASES, ids=_case_id)
def test_direct_update_rejects_protected_internal_member(case: _MemberCase) -> None:
    """Direct update calls retain the protected-policy ownership guard."""
    state_machine, controller = _state_machine(
        case,
        state="merged",
        policy={"description": "must not apply"},
        member_policy_overrides={"policyType": "l3PoMemberInternal"},
    )
    model = next(iter(state_machine.proposed))

    with pytest.raises(RuntimeError, match=r"(?i)(protected|unsupported|fabric)"):
        state_machine.model_orchestrator.update(model)

    assert _write_calls(controller) == []


def test_second_member_put_failure_preserves_only_first_accepted_deploy() -> None:
    """Sequential member updates fail closed without POST fallback or false deploys."""
    case = MEMBER_CASES[1]
    second_name = "Ethernet1/27"
    first_member = _member_record(case)
    second_member = deepcopy(first_member)
    second_member["interfaceName"] = second_name
    parent = _parent_record(case)
    parent["configData"]["networkOS"]["policy"]["ports"] = [
        case.interface_name,
        second_name,
    ]
    config = [
        _config(case, {"description": "first accepted"}),
        _config(
            case,
            {"description": "second rejected"},
            interface_name=second_name,
        ),
    ]
    state_machine, controller = _state_machine(
        case,
        state="merged",
        config_override=config,
        inventory_override=[parent, first_member, second_member],
        fail_put_number=2,
    )

    with pytest.raises(NDStateMachineError, match=r"injected member PUT failure"):
        state_machine.manage_state()

    writes = _write_calls(controller)
    assert [call["verb"] for call in writes] == [
        HttpVerbEnum.PUT.value,
        HttpVerbEnum.PUT.value,
    ]
    assert not any(call["verb"] == HttpVerbEnum.POST.value for call in controller.calls)
    assert state_machine.model_orchestrator._pending_deploys == [(case.interface_name, SWITCH_ID)]
    output = state_machine.output.format()
    assert output["changed"] is True
    descriptions = {item["interface_name"]: item["config_data"]["network_os"]["policy"]["description"] for item in output["after"]}
    assert descriptions == {
        case.interface_name: "first accepted",
        second_name: "old member description",
    }
    assert output["diff"] == []
