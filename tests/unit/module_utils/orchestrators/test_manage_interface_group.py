# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the Interface Group orchestrator."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_interface_groups import (
    EpManageFabricsInterfaceGroupsActionsRemovePost,
    EpManageFabricsInterfaceGroupsGet,
    EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete,
    EpManageFabricsInterfaceGroupsInterfaceGroupNameGet,
    EpManageFabricsInterfaceGroupsInterfaceGroupNamePut,
    EpManageFabricsInterfaceGroupsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
    InterfaceGroupGatheredFilterModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import (
    ManageInterfaceGroupOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _orchestrator(**params) -> ManageInterfaceGroupOrchestrator:
    module_params = {
        "check_mode": False,
        "fabric_name": "fab1",
        "state": "merged",
        "config": [],
    }
    module_params.update(params)
    return ManageInterfaceGroupOrchestrator(rest_send=RestSend(module_params))


def _group(
    name: str,
    *,
    group_type: str = "portChannel",
    networks: list[str] | None = None,
    members: list[tuple[str, list[str]]] | None = None,
    ethernet_attributes: dict | None = None,
) -> InterfaceGroupConfigModel:
    data = {
        "interfaceGroupName": name,
        "type": group_type,
        "networkNames": networks,
        "switchInterfaces": [
            {"switchId": switch_id, "interfaceNames": interface_names}
            for switch_id, interface_names in members or []
        ],
        "ethernetAttributes": ethernet_attributes,
    }
    return InterfaceGroupConfigModel.from_response(data)


def test_manage_interface_group_00005() -> None:
    """Expose the state-machine capabilities, endpoints, and config-action defaults."""
    orchestrator = _orchestrator()

    assert orchestrator.model_class is InterfaceGroupConfigModel
    assert orchestrator.supports_bulk_create is True
    assert orchestrator.supports_bulk_delete is True
    assert orchestrator.create_endpoint is EpManageFabricsInterfaceGroupsPost
    assert (
        orchestrator.update_endpoint
        is EpManageFabricsInterfaceGroupsInterfaceGroupNamePut
    )
    assert (
        orchestrator.delete_endpoint
        is EpManageFabricsInterfaceGroupsInterfaceGroupNameDelete
    )
    assert (
        orchestrator.query_one_endpoint
        is EpManageFabricsInterfaceGroupsInterfaceGroupNameGet
    )
    assert orchestrator.query_all_endpoint is EpManageFabricsInterfaceGroupsGet
    assert orchestrator.create_bulk_endpoint is EpManageFabricsInterfaceGroupsPost
    assert (
        orchestrator.delete_bulk_endpoint
        is EpManageFabricsInterfaceGroupsActionsRemovePost
    )
    assert orchestrator.fabric_name == "fab1"
    assert orchestrator.config_actions == {"deploy": True, "type": "switch"}

    configured = _orchestrator(
        config_actions={"deploy": False, "type": "resource"},
    )
    assert configured.config_actions == {"deploy": False, "type": "resource"}


def test_manage_interface_group_00010() -> None:
    """Queue only changes that can affect switch interface configuration."""
    no_config_before = _group("pc", members=[("SN1", ["Port-channel10"])])
    no_config_after = _group(
        "pc", members=[("SN1", ["Port-channel10", "Port-channel20"])]
    )
    assert (
        ManageInterfaceGroupOrchestrator._affected_interfaces(
            no_config_before, no_config_after
        )
        == set()
    )

    policyless_before = _group(
        "eth-no-policy",
        group_type="ethernetWithoutPolicy",
        members=[("SN1", ["Ethernet1/1"])],
    )
    policyless_after = _group(
        "eth-no-policy",
        group_type="ethernetWithoutPolicy",
        members=[("SN1", ["Ethernet1/1", "Ethernet1/2"])],
    )
    assert (
        ManageInterfaceGroupOrchestrator._affected_interfaces(
            policyless_before, policyless_after
        )
        == set()
    )

    policyless_with_network = _group(
        "eth-no-policy",
        group_type="ethernetWithoutPolicy",
        networks=["net-a"],
        members=[("SN1", ["Ethernet1/1", "Ethernet1/2"])],
    )
    assert ManageInterfaceGroupOrchestrator._affected_interfaces(
        policyless_after, policyless_with_network
    ) == {("SN1", "Ethernet1/1"), ("SN1", "Ethernet1/2")}

    network_before = _group(
        "pc",
        networks=["net-a"],
        members=[("SN1", ["Port-channel10"])],
    )
    member_added = _group(
        "pc",
        networks=["net-a"],
        members=[("SN1", ["Port-channel10", "Port-channel20"])],
    )
    assert ManageInterfaceGroupOrchestrator._affected_interfaces(
        network_before, member_added
    ) == {("SN1", "Port-channel20")}

    network_removed = _group(
        "pc",
        networks=[],
        members=[("SN1", ["Port-channel10"])],
    )
    assert ManageInterfaceGroupOrchestrator._affected_interfaces(
        network_before, network_removed
    ) == {("SN1", "Port-channel10")}


def test_manage_interface_group_00020() -> None:
    """Gather locally with AND, OR, list-containment, and empty-list semantics."""
    orchestrator = _orchestrator(state="gathered")
    custom = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "custom",
            "type": "ethernet",
            "networkNames": ["network-a", "network-b"],
            "switchInterfaces": [
                {
                    "switchId": "SN1",
                    "interfaceNames": ["Ethernet1/1", "Ethernet1/2"],
                }
            ],
            "policyDetails": {
                "policyType": "userDefinedSharedTrunk",
                "templateName": "custom-template",
                "templateConfig": {"FLAG": "true", "MTU": "9216"},
            },
        }
    )
    policy = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "policy",
            "type": "ethernet",
            "networkNames": ["network-a"],
            "switchInterfaces": [
                {"switchId": "SN2", "interfaceNames": ["Ethernet1/10"]}
            ],
            "policyDetails": {
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {
                    "adminState": True,
                    "mtu": "jumbo",
                },
            },
        }
    )
    empty = _group("empty")
    orchestrator._existing_groups = {
        item.interface_group_name: item for item in [policy, empty, custom]
    }

    def names(filters=None):
        return [item["interface_group_name"] for item in orchestrator.gather(filters)]

    assert names() == ["custom", "empty", "policy"]
    assert names(
        [
            InterfaceGroupGatheredFilterModel.model_validate(
                {
                    "type": "ethernetCustom",
                    "networks": ["network-a"],
                    "switch_interfaces": [
                        {
                            "switch_id": "SN1",
                            "interface_names": ["eth1/2"],
                        }
                    ],
                    "template_name": "custom-template",
                    "template_config": {"FLAG": True},
                }
            )
        ]
    ) == ["custom"]
    assert names(
        [
            InterfaceGroupGatheredFilterModel.model_validate(
                {"networks": [], "switch_interfaces": []}
            )
        ]
    ) == ["empty"]
    assert names(
        [
            InterfaceGroupGatheredFilterModel.model_validate(
                {"switch_interfaces": [{"switch_id": "SN1"}]}
            ),
            InterfaceGroupGatheredFilterModel.model_validate(
                {"networks": ["network-a"]}
            ),
        ]
    ) == ["custom", "policy"]
    assert names(
        [
            InterfaceGroupGatheredFilterModel.model_validate(
                {
                    "type": "ethernetWithPolicy",
                    "ethernet_attributes": {
                        "admin_status": True,
                        "mtu": "jumbo",
                    },
                }
            )
        ]
    ) == ["policy"]
    assert (
        names(
            [
                InterfaceGroupGatheredFilterModel.model_validate(
                    {"interface_group_name": "missing"}
                )
            ]
        )
        == []
    )


def test_manage_interface_group_00021() -> None:
    """Resolve member management IPs before Interface Group preflight planning."""
    calls: list[str] = []
    orchestrator = _orchestrator()
    orchestrator._fabric_context = SimpleNamespace(
        get_switch_id=lambda switch_ip: calls.append(switch_ip) or "SN1"
    )
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group-a",
            "type": "portChannel",
            "switch_interfaces": [
                {
                    "switch_id": "10.0.0.1",
                    "interface_names": ["Port-channel10"],
                }
            ],
        }
    )

    orchestrator.preflight([proposed])

    assert calls == ["10.0.0.1"]
    assert proposed.switch_interfaces[0].switch_id == "SN1"
    assert proposed.to_payload()["switchInterfaces"][0]["switchId"] == "SN1"


def test_manage_interface_group_00022() -> None:
    """Resolve gathered switch filters while leaving serial-number inputs untouched."""
    calls: list[str] = []
    orchestrator = _orchestrator(state="gathered")
    orchestrator._fabric_context = SimpleNamespace(
        get_switch_id=lambda switch_ip: calls.append(switch_ip) or "SN1"
    )
    orchestrator._existing_groups = {
        "group-a": _group(
            "group-a",
            members=[("SN1", ["Port-channel10"])],
        )
    }
    ip_filter = InterfaceGroupGatheredFilterModel.model_validate(
        {
            "switch_interfaces": [
                {
                    "switch_id": "10.0.0.1",
                    "interface_names": ["Port-channel10"],
                }
            ]
        }
    )

    assert orchestrator.gather([ip_filter]) == [
        orchestrator._existing_groups["group-a"].to_config()
    ]
    assert calls == ["10.0.0.1"]
    assert ip_filter.switch_interfaces[0].switch_id == "SN1"

    assert orchestrator._resolve_switch_id("SN1") == "SN1"
    assert calls == ["10.0.0.1"]


def test_manage_interface_group_00023() -> None:
    """Report an actionable error when an input management IP is unknown."""
    orchestrator = _orchestrator()
    orchestrator._fabric_context = SimpleNamespace(
        get_switch_id=lambda switch_ip: (_ for _ in ()).throw(
            RuntimeError(f"unknown {switch_ip}")
        )
    )

    with pytest.raises(
        RuntimeError,
        match=(
            r"Unable to resolve switch IP '10\.0\.0\.99' to a serial number "
            r"in fabric 'fab1'"
        ),
    ):
        orchestrator._resolve_switch_id("10.0.0.99")


def test_manage_interface_group_00024(monkeypatch) -> None:
    """Treat one vPC member echoed under either peer as idempotent."""
    calls: list[str] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return {"peerSwitchId": "SN2"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    existing = _group(
        "vpc-group",
        group_type="vpc",
        members=[("SN2", ["vPC200"])],
    )
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "vpc-group",
            "type": "vpc",
            "switch_interfaces": [{"switch_id": "SN1", "interface_names": ["vPC200"]}],
        }
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"vpc-group": existing}

    orchestrator.preflight([proposed])

    current = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(existing)],
    )
    assert current.get_diff_config(proposed, exclude_unset=True) == "no_diff"
    assert proposed.switch_interfaces[0].switch_id == "SN2"
    assert calls == ["/api/v1/manage/fabrics/fab1/switches/SN1/vpcPair"]


def test_manage_interface_group_00025(monkeypatch) -> None:
    """Align only a mixed any group's vPC member and retain exact switch IDs."""
    calls: list[str] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return {"peerSwitchId": "SN2"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    existing = _group(
        "any-group",
        group_type="any",
        members=[
            ("SN1", ["Ethernet1/1", "Port-channel10"]),
            ("SN2", ["vPC200"]),
        ],
    )
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "any-group",
            "type": "any",
            "switch_interfaces": [
                {
                    "switch_id": "SN1",
                    "interface_names": [
                        "Ethernet1/1",
                        "Port-channel10",
                        "vPC200",
                    ],
                }
            ],
        }
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"any-group": existing}

    orchestrator.preflight([proposed])

    assert proposed.to_payload()["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": ["Ethernet1/1", "Port-channel10"],
        },
        {"switchId": "SN2", "interfaceNames": ["vPC200"]},
    ]
    current = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(existing)],
    )
    assert current.get_diff_config(proposed, exclude_unset=True) == "no_diff"
    assert len(calls) == 1


def test_manage_interface_group_00026(monkeypatch) -> None:
    """Do not equate the same vPC name when switch IDs are not peers."""

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        if "/switches/SN1/" in path:
            return {"peerSwitchId": "SN3"}
        return {"peerSwitchId": "SN4"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    existing = _group(
        "vpc-group",
        group_type="vpc",
        members=[("SN2", ["vPC200"])],
    )
    proposed = _group(
        "vpc-group",
        group_type="vpc",
        members=[("SN1", ["vPC200"])],
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"vpc-group": existing}

    orchestrator.preflight([proposed])

    current = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(existing)],
    )
    assert current.get_diff_config(proposed, exclude_unset=True) == "changed"
    assert proposed.switch_interfaces[0].switch_id == "SN1"


def test_manage_interface_group_00027(monkeypatch) -> None:
    """Use peer-aware vPC identity for gathered filters and explicit moves."""

    def fake_request(self, path, verb, **kwargs):
        del self, path, verb, kwargs
        return {"peerSwitchId": "SN2"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    source = _group(
        "source",
        group_type="vpc",
        members=[("SN2", ["vPC200"])],
    )
    target = _group("target", group_type="vpc", members=[])

    gathered = _orchestrator(state="gathered")
    gathered._existing_groups = {"source": source}
    gathered_filter = InterfaceGroupGatheredFilterModel.model_validate(
        {"switch_interfaces": [{"switch_id": "SN1", "interface_names": ["vPC200"]}]}
    )
    assert gathered.gather([gathered_filter]) == [source.to_config()]

    replaced = _orchestrator(
        state="replaced",
        config_actions={"deploy": False, "type": "switch"},
    )
    replaced._existing_groups = {"source": source, "target": target}
    source_desired = _group("source", group_type="vpc", members=[])
    target_desired = _group(
        "target",
        group_type="vpc",
        members=[("SN1", ["vPC200"])],
    )

    replaced.preflight([source_desired, target_desired])

    assert target_desired.switch_interfaces[0].switch_id == "SN2"
    assert set(replaced._move_plan) == {"source"}


def test_manage_interface_group_00028(monkeypatch) -> None:
    """A vPC move never re-buckets retained any members onto its input peer."""
    put_payloads: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        if path.endswith("/switches/SN1/vpcPair"):
            return {"peerSwitchId": "SN2"}
        put_payloads.append(data)
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    any_existing = _group(
        "any-group",
        group_type="any",
        members=[
            ("SN1", ["Ethernet1/3"]),
            ("SN2", ["Ethernet1/3", "Port-channel504"]),
        ],
    )
    vpc_existing = _group(
        "vpc-group",
        group_type="vpc",
        members=[("SN2", ["vPC200"])],
    )
    any_desired = _group(
        "any-group",
        group_type="any",
        members=[
            ("SN1", ["Ethernet1/3", "vPC200"]),
            ("SN2", ["Ethernet1/3", "Port-channel504"]),
        ],
    )
    vpc_desired = _group("vpc-group", group_type="vpc", members=[])
    orchestrator = _orchestrator(
        state="replaced",
        config_actions={"deploy": False, "type": "resource"},
    )
    orchestrator._existing_groups = {
        "any-group": any_existing,
        "vpc-group": vpc_existing,
    }

    orchestrator.preflight([any_desired, vpc_desired])
    orchestrator.update(any_desired)

    assert put_payloads[-1]["switchInterfaces"] == [
        {"switchId": "SN1", "interfaceNames": ["Ethernet1/3"]},
        {
            "switchId": "SN2",
            "interfaceNames": ["Ethernet1/3", "Port-channel504", "vPC200"],
        },
    ]


def test_manage_interface_group_00030() -> None:
    """Merged rejects implicit moves while replaced plans remove-before-add."""
    source = _group("source", members=[("SN1", ["Port-channel10"])])
    target = _group("target", members=[("SN1", ["Port-channel20"])])

    merged = _orchestrator(state="merged")
    merged._existing_groups = {"source": source, "target": target}
    target_merged = deepcopy(target)
    target_merged.switch_interfaces = [
        {"switch_id": "SN1", "interface_names": ["Port-channel20", "Port-channel10"]}
    ]
    with pytest.raises(RuntimeError, match="state=merged is additive"):
        merged._plan_moves([target_merged], {"target": target_merged})

    replaced = _orchestrator(state="replaced")
    replaced._existing_groups = {"source": source, "target": target}
    source_desired = _group("source", members=[])
    target_desired = deepcopy(target_merged)
    replaced._plan_moves(
        [source_desired, target_desired],
        {"source": source_desired, "target": target_desired},
    )

    assert set(replaced._move_plan) == {"source"}
    assert replaced._move_plan["source"].switch_interfaces == []

    overridden = _orchestrator(state="overridden")
    overridden._existing_groups = {"source": source, "target": target}
    overridden._plan_moves(
        [target_desired],
        {"target": target_desired},
    )
    assert set(overridden._move_plan) == {"source"}
    assert overridden._move_plan["source"].switch_interfaces == []


def test_manage_interface_group_00040() -> None:
    """The move prerequisite updates predicted state in check mode without writes."""
    source = _group("source", members=[("SN1", ["Port-channel10"])])
    target = _group("target", members=[("SN1", ["Port-channel20"])])
    orchestrator = _orchestrator(state="replaced")
    orchestrator._existing_groups = {"source": source, "target": target}
    orchestrator._move_plan = {"source": _group("source", members=[])}
    existing = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(source), deepcopy(target)],
    )
    proposed = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[_group("source", members=[]), deepcopy(target)],
    )

    orchestrator.prepare_mutations(existing, proposed, check_mode=True)

    assert existing.get("source").switch_interfaces == []


def test_manage_interface_group_00050(monkeypatch) -> None:
    """Resource preflight validates existence and warns about network deploy scope."""
    config = [
        {
            "interface_group_name": "pc",
            "type": "portChannel",
            "networks": ["net-a"],
            "switch_interfaces": [
                {"switch_id": "SN1", "interface_names": ["Port-channel10"]}
            ],
        }
    ]
    orchestrator = _orchestrator(
        config=config,
        config_actions={"deploy": True, "type": "resource"},
    )
    proposed = InterfaceGroupConfigModel.from_config(config[0])
    warnings: list[str] = []

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_network_exists",
        lambda self, network_name: True,
    )
    monkeypatch.setattr(orchestrator.rest_send, "warn", warnings.append)

    orchestrator.preflight([proposed])

    assert len(warnings) == 1
    assert orchestrator.warnings == warnings
    assert "'net-a'" in warnings[0]
    assert "affected interfaces" in warnings[0]
    assert "cisco.nd.nd_manage_networks" in warnings[0]


def test_manage_interface_group_00055() -> None:
    """Create-only fields are enforced after existing groups are known."""
    orchestrator = _orchestrator()
    missing_type = InterfaceGroupConfigModel.from_config(
        {"interface_group_name": "new-group"}
    )
    with pytest.raises(RuntimeError, match="requires type"):
        orchestrator.preflight_create([missing_type])

    missing_template = InterfaceGroupConfigModel.from_config(
        {"interface_group_name": "custom-group", "type": "ethernetCustom"}
    )
    with pytest.raises(RuntimeError, match="requires template_name"):
        orchestrator.preflight_create([missing_template])


def test_manage_interface_group_00060(monkeypatch) -> None:
    """A missing referenced network fails before any mutation."""
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    proposed = _group(
        "pc",
        networks=["missing-network"],
        members=[("SN1", ["Port-channel10"])],
    )
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_network_exists",
        lambda self, network_name: False,
    )

    with pytest.raises(RuntimeError, match="do not exist"):
        orchestrator.preflight([proposed])


def test_manage_interface_group_00065(monkeypatch) -> None:
    """Unchanged network associations do not trigger redundant existence queries."""
    existing = _group("pc", networks=["net-a"])
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "pc",
            "switch_interfaces": [
                {"switch_id": "SN1", "interface_names": ["Port-channel10"]}
            ],
        }
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"pc": existing}

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_network_exists",
        lambda self, network_name: pytest.fail(
            f"unexpected network query for {network_name}"
        ),
    )

    orchestrator.preflight([proposed])


def test_manage_interface_group_00070(monkeypatch) -> None:
    """Create and delete use the API wrappers and clear associations before delete."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        calls.append({"path": path, "data": data})
        if path.endswith("/actions/remove"):
            return {
                "interfaceGroups": [
                    {
                        "interfaceGroupName": "pc",
                        "status": "success",
                        "message": "deleted",
                    }
                ]
            }
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        state="deleted",
        config=[{"interface_group_name": "pc"}],
        config_actions={"deploy": False, "type": "switch"},
    )
    existing = _group(
        "pc",
        networks=["net-a"],
        members=[("SN1", ["Port-channel10"])],
    )
    orchestrator._existing_groups = {"pc": existing}

    orchestrator.delete_bulk([existing])

    assert calls[0]["path"].endswith("/interfaceGroups/pc")
    assert calls[0]["data"]["networkNames"] == []
    assert calls[0]["data"]["switchInterfaces"] == []
    assert calls[1]["path"].endswith("/interfaceGroups/actions/remove")
    assert calls[1]["data"] == {"interfaceGroupNames": ["pc"]}


@pytest.mark.parametrize(
    ("deploy_type", "expected_path", "expected_payload"),
    [
        (
            "resource",
            "/interfaceActions/deploy",
            {"interfaces": [{"switchId": "SN1", "interfaceName": "Port-channel10"}]},
        ),
        (
            "switch",
            "/switchActions/deploy",
            {"switchIds": ["SN1"]},
        ),
    ],
)
def test_manage_interface_group_00080(
    monkeypatch,
    deploy_type: str,
    expected_path: str,
    expected_payload: dict,
) -> None:
    """Deploy queues call the endpoint selected by config_actions.type."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        calls.append({"path": path, "data": data})
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        config_actions={"deploy": True, "type": deploy_type},
    )
    orchestrator._pending_interfaces = {("SN1", "Port-channel10")}
    orchestrator._pending_switches = {"SN1"}

    orchestrator.deploy_pending()

    assert expected_path in calls[0]["path"]
    assert calls[0]["data"] == expected_payload


def test_manage_interface_group_00090() -> None:
    """Pagination helpers cover remaining, total, full-page, and terminal responses."""
    assert (
        ManageInterfaceGroupOrchestrator._has_next_page(
            {"meta": {"counts": {"remaining": 1}}},
            page_count=1,
            total_seen=1,
        )
        is True
    )
    assert (
        ManageInterfaceGroupOrchestrator._has_next_page(
            {"metadata": {"counts": {"total": "2"}}},
            page_count=1,
            total_seen=1,
        )
        is True
    )
    assert (
        ManageInterfaceGroupOrchestrator._has_next_page(
            {},
            page_count=100,
            total_seen=100,
        )
        is True
    )
    assert (
        ManageInterfaceGroupOrchestrator._has_next_page(
            {"meta": {"counts": {"remaining": 0}}},
            page_count=1,
            total_seen=1,
        )
        is False
    )
    assert (
        ManageInterfaceGroupOrchestrator._has_next_page(
            {"meta": {"counts": {"remaining": 5}}},
            page_count=0,
            total_seen=0,
        )
        is False
    )
    assert ManageInterfaceGroupOrchestrator._coerce_int("bad") is None


def test_manage_interface_group_00100(monkeypatch) -> None:
    """Query-all paginates and caches the normalized models."""
    orchestrator = _orchestrator()
    orchestrator._fabric_context = SimpleNamespace(validate_for_mutation=lambda: None)
    calls: list[str] = []
    responses = iter(
        [
            {
                "interfaceGroupDetails": [
                    {"interfaceGroupName": "group-a", "type": "portChannel"}
                ],
                "meta": {"counts": {"remaining": 1, "total": 2}},
            },
            {
                "interfaceGroupDetails": [
                    {"interfaceGroupName": "group-b", "type": "vpc"}
                ],
                "meta": {"counts": {"remaining": 0, "total": 2}},
            },
        ]
    )

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return next(responses)

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)

    result = orchestrator.query_all()

    assert [item["interfaceGroupName"] for item in result] == ["group-a", "group-b"]
    assert set(orchestrator._existing_groups) == {"group-a", "group-b"}
    assert "max=100" in calls[0]
    assert "offset=0" in calls[0]
    assert "offset=1" in calls[1]


def test_manage_interface_group_00105(monkeypatch) -> None:
    """Gathered reads require the fabric but skip mutation-only validation."""
    validation_calls: list[str] = []
    orchestrator = _orchestrator(state="gathered")
    orchestrator._fabric_context = SimpleNamespace(
        fabric_exists=lambda: validation_calls.append("fabric_exists") or True,
        validate_for_mutation=lambda: validation_calls.append("validate_for_mutation"),
    )

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        lambda *args, **kwargs: {
            "interfaceGroupDetails": [],
            "meta": {"counts": {"remaining": 0}},
        },
    )

    assert orchestrator.query_all() == []
    assert validation_calls == ["fabric_exists"]

    orchestrator._fabric_context = SimpleNamespace(fabric_exists=lambda: False)
    with pytest.raises(RuntimeError, match="Fabric 'fab1' does not exist"):
        orchestrator.query_all()


def test_manage_interface_group_00110(monkeypatch) -> None:
    """Query-one encodes the identifier and treats a missing group as normal."""
    calls: list[dict] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb
        calls.append({"path": path, **kwargs})
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator()

    result = orchestrator.query_one(
        InterfaceGroupConfigModel.from_config({"interface_group_name": "group/one"})
    )

    assert result == {}
    assert "/interfaceGroups/group%2Fone" in calls[0]["path"]
    assert calls[0]["not_found_ok"] is True


def test_manage_interface_group_00120() -> None:
    """Every multi-status response helper rejects failed per-item results."""
    with pytest.raises(RuntimeError, match="member conflict"):
        ManageInterfaceGroupOrchestrator._raise_create_failures(
            {
                "interfaceGroups": [
                    {
                        "type": "portChannel",
                        "status": "failed",
                        "message": "member conflict",
                    }
                ]
            }
        )
    with pytest.raises(RuntimeError, match="group-a: still associated"):
        ManageInterfaceGroupOrchestrator._raise_delete_failures(
            {
                "interfaceGroups": [
                    {
                        "interfaceGroupName": "group-a",
                        "status": "failed",
                        "message": "still associated",
                    }
                ]
            }
        )
    with pytest.raises(RuntimeError, match="Port-channel10: deploy failed"):
        ManageInterfaceGroupOrchestrator._raise_action_failures(
            {
                "results": [
                    {
                        "interfaceName": "Port-channel10",
                        "status": "error",
                        "message": "deploy failed",
                    }
                ]
            },
            "interfaceActions/deploy",
        )

    ManageInterfaceGroupOrchestrator._raise_create_failures(
        {"interfaceGroups": [{"type": "vpc", "status": "success"}]}
    )
    ManageInterfaceGroupOrchestrator._raise_delete_failures(
        {"interfaceGroups": [{"interfaceGroupName": "group-a", "status": "success"}]}
    )
    ManageInterfaceGroupOrchestrator._raise_action_failures([], "deploy")


def test_manage_interface_group_00130(monkeypatch) -> None:
    """Bulk create sends one typed payload and queues deployment."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        calls.append({"path": path, "data": data})
        return {
            "interfaceGroups": [
                {"type": "portChannel", "status": "success", "message": "created"}
            ]
        }

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        config_actions={"deploy": True, "type": "resource"},
        config=[
            {
                "interface_group_name": "group-a",
                "type": "portChannel",
            }
        ],
    )
    group = _group(
        "group-a",
        networks=["network-a"],
        members=[("SN1", ["Port-channel10"])],
    )

    orchestrator.create_bulk([group])

    assert calls[0]["data"] == {
        "interfaceGroups": [
            {
                "interfaceGroupName": "group-a",
                "type": "portChannel",
                "networkNames": ["network-a"],
                "switchInterfaces": [
                    {
                        "switchId": "SN1",
                        "interfaceNames": ["Port-channel10"],
                    }
                ],
            }
        ]
    }
    assert calls[0]["path"].endswith("/interfaceGroups")
    assert orchestrator._pending_interfaces == {("SN1", "Port-channel10")}
    assert orchestrator._existing_groups["group-a"] == group


def test_manage_interface_group_00132(monkeypatch) -> None:
    """Create a mixed any group with one cumulative PUT per member kind."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        calls.append({"path": path, "data": data})
        if path.endswith("/interfaceGroups"):
            return {
                "interfaceGroups": [
                    {"type": "any", "status": "success", "message": "created"}
                ]
            }
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "resource"})
    group = _group(
        "mixed",
        group_type="any",
        networks=["network-a"],
        members=[
            ("SN1", ["Ethernet1/1", "Ethernet1/2", "Port-channel10"]),
            ("SN2", ["vPC20"]),
        ],
    )

    orchestrator.create_bulk([group])

    assert len(calls) == 4
    assert calls[0]["data"]["interfaceGroups"][0]["switchInterfaces"] == []
    assert calls[0]["data"]["interfaceGroups"][0]["networkNames"] == ["network-a"]
    assert calls[1]["data"]["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": ["Ethernet1/1", "Ethernet1/2"],
        }
    ]
    assert calls[2]["data"]["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": [
                "Ethernet1/1",
                "Ethernet1/2",
                "Port-channel10",
            ],
        }
    ]
    assert calls[3]["data"]["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": [
                "Ethernet1/1",
                "Ethernet1/2",
                "Port-channel10",
            ],
        },
        {"switchId": "SN2", "interfaceNames": ["vPC20"]},
    ]
    assert all(call["data"]["networkNames"] == ["network-a"] for call in calls[1:])
    assert orchestrator._existing_groups["mixed"] == group


def test_manage_interface_group_00133(monkeypatch) -> None:
    """Batch same-kind any additions and retain existing mixed members."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, path, verb, kwargs
        calls.append(data)
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        state="merged", config_actions={"deploy": False, "type": "resource"}
    )
    existing = _group(
        "mixed",
        group_type="any",
        members=[("SN1", ["Ethernet1/1", "Port-channel10"])],
    )
    effective = _group(
        "mixed",
        group_type="any",
        networks=["network-a"],
        members=[
            (
                "SN1",
                [
                    "Ethernet1/1",
                    "Ethernet1/2",
                    "Ethernet1/3",
                    "Port-channel10",
                    "vPC20",
                ],
            )
        ],
    )
    orchestrator._existing_groups = {"mixed": existing}

    orchestrator.update(effective)

    assert len(calls) == 2
    assert calls[0]["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": [
                "Ethernet1/1",
                "Ethernet1/2",
                "Ethernet1/3",
                "Port-channel10",
            ],
        }
    ]
    assert calls[1]["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": [
                "Ethernet1/1",
                "Ethernet1/2",
                "Ethernet1/3",
                "Port-channel10",
                "vPC20",
            ],
        }
    ]
    assert all(call["networkNames"] == ["network-a"] for call in calls)


def test_manage_interface_group_00134(monkeypatch) -> None:
    """Any updates without member additions use one authoritative PUT."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, path, verb, kwargs
        calls.append(data)
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        state="replaced", config_actions={"deploy": False, "type": "resource"}
    )
    existing = _group(
        "mixed",
        group_type="any",
        members=[("SN1", ["Ethernet1/1", "Port-channel10"])],
    )
    replacement = _group(
        "mixed",
        group_type="any",
        networks=["network-a"],
        members=[("SN1", ["Port-channel10"])],
    )
    orchestrator._existing_groups = {"mixed": existing}

    orchestrator.update(replacement)

    assert len(calls) == 1
    assert calls[0]["networkNames"] == ["network-a"]
    assert calls[0]["switchInterfaces"] == [
        {"switchId": "SN1", "interfaceNames": ["Port-channel10"]}
    ]


def test_manage_interface_group_00135(monkeypatch) -> None:
    """One group update combines networks and members in one PUT before one deploy."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, kwargs
        calls.append({"path": path, "verb": verb, "data": data})
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        config_actions={"deploy": True, "type": "resource"},
        config=[
            {
                "interface_group_name": "group-a",
                "networks": ["network-b"],
                "switch_interfaces": [
                    {
                        "switch_id": "SN1",
                        "interface_names": ["Port-channel20"],
                    }
                ],
            }
        ],
    )
    existing = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "group-a",
            "type": "portChannel",
            "networkNames": ["network-a"],
            "switchInterfaces": [
                {
                    "switchId": "SN1",
                    "interfaceNames": ["Port-channel10"],
                }
            ],
        }
    )
    orchestrator._existing_groups = {"group-a": existing}
    proposed = InterfaceGroupConfigModel.from_config(
        orchestrator.rest_send.params["config"][0]
    )
    effective = orchestrator._effective_model(proposed)

    orchestrator.update(effective)

    assert len(calls) == 1
    assert calls[0]["path"].endswith("/interfaceGroups/group-a")
    assert calls[0]["data"] == {
        "interfaceGroupName": "group-a",
        "type": "portChannel",
        "networkNames": ["network-a", "network-b"],
        "switchInterfaces": [
            {
                "switchId": "SN1",
                "interfaceNames": ["Port-channel10", "Port-channel20"],
            }
        ],
    }
    assert orchestrator._pending_interfaces == {
        ("SN1", "Port-channel10"),
        ("SN1", "Port-channel20"),
    }

    orchestrator.deploy_pending()

    assert len(calls) == 2
    assert calls[1]["path"].endswith("/interfaceActions/deploy")
    assert calls[1]["data"] == {
        "interfaces": [
            {
                "switchId": "SN1",
                "interfaceName": "Port-channel10",
            },
            {
                "switchId": "SN1",
                "interfaceName": "Port-channel20",
            },
        ]
    }


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_manage_interface_group_00137(monkeypatch, state: str) -> None:
    """Authoritative updates preserve omitted association lists."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        calls.append({"path": path, "data": data})
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        state=state,
        config_actions={"deploy": False, "type": "switch"},
    )
    existing = _group(
        "group-a",
        networks=["network-a", "network-b"],
        members=[("SN1", ["Port-channel10", "Port-channel20"])],
    )
    orchestrator._existing_groups = {"group-a": existing}
    replacement = InterfaceGroupConfigModel.from_config(
        {"interface_group_name": "group-a", "type": "portChannel"}
    )

    orchestrator.preflight([replacement])

    existing_collection = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(existing)],
    )
    assert (
        existing_collection.get_diff_config(replacement, exclude_unset=False)
        == "no_diff"
    )

    orchestrator.update(replacement)

    assert replacement.networks == ["network-a", "network-b"]
    assert replacement.switch_interfaces == existing.switch_interfaces
    assert calls[0]["data"]["networkNames"] == ["network-a", "network-b"]
    assert calls[0]["data"]["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": ["Port-channel10", "Port-channel20"],
        }
    ]
    assert orchestrator._existing_groups["group-a"] == replacement


def test_manage_interface_group_00138() -> None:
    """Supplied association lists remain authoritative and explicit empties clear."""
    orchestrator = _orchestrator(state="replaced")
    existing = _group(
        "group-a",
        networks=["network-a", "network-b"],
        members=[("SN1", ["Port-channel10", "Port-channel20"])],
    )
    orchestrator._existing_groups = {"group-a": existing}

    partial_membership = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group-a",
            "type": "portChannel",
            "switch_interfaces": [
                {
                    "switch_id": "SN1",
                    "interface_names": ["Port-channel20"],
                }
            ],
        }
    )
    explicit_empty = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group-a",
            "type": "portChannel",
            "networks": [],
            "switch_interfaces": [],
        }
    )

    orchestrator._preserve_omitted_associations([partial_membership, explicit_empty])

    assert partial_membership.networks == ["network-a", "network-b"]
    assert partial_membership.switch_interfaces[0].interface_names == ["Port-channel20"]
    assert explicit_empty.networks == []
    assert explicit_empty.switch_interfaces == []


def test_manage_interface_group_00140(monkeypatch) -> None:
    """Explicit empty association lists clear them and refresh cached state."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        calls.append({"path": path, "data": data})
        return {}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        state="replaced",
        config_actions={"deploy": False, "type": "switch"},
    )
    existing = _group(
        "group-a",
        group_type="ethernetWithPolicy",
        networks=["network-a"],
        members=[("SN1", ["Ethernet1/1"])],
        ethernet_attributes={"adminStatus": True},
    )
    orchestrator._existing_groups = {"group-a": existing}
    replacement = _group(
        "group-a",
        group_type="ethernetWithPolicy",
        networks=[],
        members=[],
    )

    orchestrator.update(replacement)

    assert "description" not in calls[0]["data"]
    assert calls[0]["data"]["networkNames"] == []
    assert calls[0]["data"]["switchInterfaces"] == []
    assert calls[0]["data"]["type"] == "ethernet"
    assert calls[0]["data"]["policyDetails"]["policyType"] == "sharedTrunkHost"
    assert calls[0]["data"]["policyDetails"]["ethernetAttributes"]["adminState"] is True
    assert "ethernetAttributes" not in calls[0]["data"]
    assert orchestrator._existing_groups["group-a"] == replacement

    custom = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-a",
            "type": "ethernetCustom",
            "template_name": "custom-template",
        }
    )
    custom_payload = orchestrator._payload_for_update(custom)
    assert custom_payload["type"] == "ethernet"
    assert custom_payload["policyDetails"] == {
        "policyType": "userDefinedSharedTrunk",
        "templateName": "custom-template",
        "templateConfig": {},
    }


def test_manage_interface_group_00150(monkeypatch) -> None:
    """Delete without associations skips detachment and propagates item failures."""
    calls: list[dict] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        calls.append({"path": path, "data": data})
        return {
            "interfaceGroups": [
                {
                    "interfaceGroupName": "group-a",
                    "status": "failed",
                    "message": "controller rejected delete",
                }
            ]
        }

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(
        state="deleted",
        config_actions={"deploy": False, "type": "switch"},
    )
    group = _group("group-a")
    orchestrator._existing_groups = {"group-a": group}

    with pytest.raises(RuntimeError, match="controller rejected delete"):
        orchestrator.delete(group)

    assert len(calls) == 1
    assert calls[0]["path"].endswith("/actions/remove")
    assert "group-a" in orchestrator._existing_groups


def test_manage_interface_group_00160(monkeypatch) -> None:
    """Network existence validation uses GET-one and reports all missing names."""
    calls: list[str] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return {} if "/missing" in path else {"networkName": "network-a"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator()

    assert orchestrator._network_exists("network-a") is True
    with pytest.raises(RuntimeError, match="'missing'"):
        orchestrator._validate_networks_exist({"network-a", "missing"})

    assert all("clusterName=" not in path for path in calls)


def test_manage_interface_group_00170(monkeypatch) -> None:
    """Resource preflight never queries network deployment readiness."""
    calls: list[dict] = []
    warnings: list[str] = []

    def fake_request(self, path, verb, data=None, **kwargs):
        del self, verb, kwargs
        calls.append({"path": path, "data": data})
        return {"networkName": "network-a"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    config = [
        {
            "interface_group_name": "pc",
            "type": "portChannel",
            "networks": ["network-a"],
            "switch_interfaces": [
                {"switch_id": "SN1", "interface_names": ["Port-channel10"]}
            ],
        }
    ]
    orchestrator = _orchestrator(
        check_mode=True,
        config=config,
        config_actions={"deploy": True, "type": "resource"},
    )
    monkeypatch.setattr(orchestrator.rest_send, "warn", warnings.append)

    orchestrator.preflight([InterfaceGroupConfigModel.from_config(config[0])])

    assert len(calls) == 1
    assert "/networks/network-a" in calls[0]["path"]
    assert all("networkActions/preview" not in call["path"] for call in calls)
    assert len(warnings) == 1
    assert orchestrator.warnings == warnings
    assert orchestrator.rest_send.check_mode is True


def test_manage_interface_group_00180(monkeypatch) -> None:
    """Preflight rejects immutable type changes and incomplete explicit moves."""
    source = _group("source", members=[("SN1", ["Port-channel10"])])
    target = _group("target", members=[])
    orchestrator = _orchestrator(
        state="replaced",
        config_actions={"deploy": False, "type": "switch"},
    )
    orchestrator._existing_groups = {"source": source, "target": target}
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_validate_networks_exist",
        lambda self, networks: None,
    )

    with pytest.raises(RuntimeError, match="type cannot be changed"):
        orchestrator.preflight(
            [
                InterfaceGroupConfigModel.from_config(
                    {
                        "interface_group_name": "source",
                        "type": "vpc",
                        "switch_interfaces": [],
                    }
                )
            ]
        )

    with pytest.raises(RuntimeError, match="requires the source group to omit"):
        orchestrator.preflight(
            [
                _group(
                    "target",
                    members=[("SN1", ["Port-channel10"])],
                )
            ]
        )


def test_manage_interface_group_00190(monkeypatch) -> None:
    """Real move preparation writes source first and queues its affected interface."""
    source = _group(
        "source",
        networks=["network-a"],
        members=[("SN1", ["Port-channel10"])],
    )
    intermediate = _group("source", networks=["network-a"], members=[])
    orchestrator = _orchestrator(
        state="replaced",
        config_actions={"deploy": True, "type": "resource"},
        config=[{"interface_group_name": "source", "type": "portChannel"}],
    )
    orchestrator._existing_groups = {"source": source}
    orchestrator._move_plan = {"source": intermediate}
    existing = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(source)],
    )
    proposed = NDConfigCollection(
        model_class=InterfaceGroupConfigModel,
        items=[deepcopy(intermediate)],
    )
    calls: list[str] = []
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_put_group",
        lambda self, item: calls.append(item.interface_group_name),
    )

    orchestrator.prepare_mutations(existing, proposed, check_mode=False)

    assert calls == ["source"]
    assert existing.get("source").switch_interfaces == []
    assert orchestrator._pending_interfaces == {("SN1", "Port-channel10")}


def test_manage_interface_group_00200(monkeypatch) -> None:
    """Deploy no-ops are call-free and failed action results retain pending work."""
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "resource"})
    orchestrator._pending_interfaces = {("SN1", "Port-channel10")}
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        lambda *args, **kwargs: pytest.fail("unexpected deploy request"),
    )
    assert orchestrator.deploy_pending() is None

    enabled = _orchestrator(config_actions={"deploy": True, "type": "resource"})
    assert enabled.deploy_pending() is None

    def failed_request(self, path, verb, data=None, **kwargs):
        del self, path, verb, data, kwargs
        return {
            "results": [
                {
                    "switchId": "SN1",
                    "interfaceName": "Port-channel10",
                    "status": "failed",
                    "message": "switch rejected config",
                }
            ]
        }

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", failed_request)
    enabled._pending_interfaces = {("SN1", "Port-channel10")}
    with pytest.raises(RuntimeError, match="switch rejected config"):
        enabled.deploy_pending()
    assert enabled._pending_interfaces == {("SN1", "Port-channel10")}


def _eligible_custom_template(parameters: list[dict] | None = None) -> dict:
    """Return one complete custom Ethernet template definition."""
    return {
        "name": "custom-template",
        "templateType": "policy",
        "templateSubType": "interfaceEthernet",
        "contentType": "pythonCli",
        "tags": [
            "interface_edit_policy,",
            "interface_edit_shared_policy,",
            "int_trunk",
        ],
        "content": """##template properties
userDefined = true;
##
##template variables
""",
        "supportedPlatforms": ["all"],
        "parameters": parameters or [],
    }


def test_manage_interface_group_00210(monkeypatch) -> None:
    """Strict custom-template preflight validates metadata and caches GET-one."""
    calls: list[str] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return _eligible_custom_template(
            [
                {
                    "name": "DESC",
                    "parameterType": "string",
                    "optional": False,
                }
            ]
        )

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "custom-template",
            "template_config": {"DESC": "server link"},
        }
    )

    orchestrator.preflight([proposed])
    orchestrator.preflight([proposed])

    assert calls == ["/api/v1/manage/configTemplates/custom-template"]


def test_manage_interface_group_00215(monkeypatch) -> None:
    """Accept a null optional integer in the live custom-template schema."""
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        lambda *args, **kwargs: _eligible_custom_template(
            [
                {
                    "name": "NATIVE_VLAN",
                    "parameterType": "integer",
                    "annotations": {"IsMandatory": "false"},
                    "metaProperties": {"min": "1", "max": "4094"},
                }
            ]
        ),
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "custom-template",
            "template_config": {"NATIVE_VLAN": None},
        }
    )

    orchestrator.preflight([proposed])


@pytest.mark.parametrize(
    ("metadata_update", "message"),
    [
        ({"templateType": "fabric"}, "not a policy template"),
        ({"templateSubType": "interfacePortChannel"}, "not Ethernet interface"),
        ({"contentType": "text"}, "not Python or Python CLI"),
        ({"tags": ["unrelated"]}, "editable shared-interface policy"),
        (
            {"content": """##template properties
userDefined = false;
##
"""},
            "not a user-defined template",
        ),
        ({"supportedPlatforms": []}, "supported switch platforms"),
    ],
)
def test_manage_interface_group_00220(
    monkeypatch, metadata_update: dict, message: str
) -> None:
    """Reject custom templates that the Ethernet Interface Group UI cannot use."""
    template = _eligible_custom_template()
    template.update(metadata_update)
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        lambda *args, **kwargs: template,
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "custom-template",
        }
    )

    with pytest.raises(RuntimeError, match=message):
        orchestrator.preflight([proposed])


def test_manage_interface_group_00230(monkeypatch) -> None:
    """Reject missing templates and invalid template_config before mutation."""
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "missing-template",
        }
    )
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        lambda *args, **kwargs: {},
    )

    with pytest.raises(RuntimeError, match="does not exist"):
        orchestrator.preflight([proposed])

    valid_name = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "custom-template",
            "template_config": {"UNKNOWN": "value"},
        }
    )
    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        lambda *args, **kwargs: _eligible_custom_template(
            [
                {
                    "name": "DESC",
                    "parameterType": "string",
                    "optional": False,
                }
            ]
        ),
    )

    with pytest.raises(RuntimeError, match="Unknown template_config key 'UNKNOWN'"):
        orchestrator.preflight([valid_name])


def test_manage_interface_group_00240(monkeypatch) -> None:
    """Validate an effective merged custom config but skip membership-only lookups."""
    calls: list[str] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return _eligible_custom_template(
            [
                {
                    "name": name,
                    "parameterType": "string",
                    "optional": False,
                }
                for name in ("DESC", "CONF")
            ]
        )

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    existing = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "type": "ethernetCustom",
            "template_name": "custom-template",
            "template_config": {"DESC": "server link"},
        }
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"custom-group": existing}

    template_update = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "template_config": {"CONF": "logging event port link-status"},
        }
    )
    orchestrator.preflight([template_update])

    membership_only = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "custom-group",
            "switch_interfaces": [
                {"switch_id": "SN1", "interface_names": ["Ethernet1/1"]}
            ],
        }
    )
    orchestrator.preflight([membership_only])

    assert calls == ["/api/v1/manage/configTemplates/custom-template"]


def test_manage_interface_group_00250() -> None:
    """Collapse serial and management-IP entries before constructing payloads."""
    calls: list[str] = []
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._fabric_context = SimpleNamespace(
        get_switch_id=lambda switch_ip: calls.append(switch_ip) or "SN1"
    )
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group-a",
            "type": "portChannel",
            "switch_interfaces": [
                {
                    "switch_id": "SN1",
                    "interface_names": ["Port-channel10"],
                },
                {
                    "switch_id": "10.0.0.1",
                    "interface_names": ["Port-channel20", "Port-channel10"],
                },
            ],
        }
    )

    orchestrator.preflight([proposed])

    assert calls == ["10.0.0.1"]
    assert proposed.to_payload()["switchInterfaces"] == [
        {
            "switchId": "SN1",
            "interfaceNames": ["Port-channel10", "Port-channel20"],
        }
    ]


def test_manage_interface_group_00260() -> None:
    """Reject cross-group ownership hidden by IP-to-serial translation."""
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._fabric_context = SimpleNamespace(
        get_switch_id=lambda _switch_ip: "SN1"
    )
    first = _group(
        "group-a",
        members=[("SN1", ["Port-channel10"])],
    )
    second = _group(
        "group-b",
        members=[("10.0.0.1", ["Port-channel10"])],
    )

    with pytest.raises(
        RuntimeError,
        match=(
            r"Interface 'Port-channel10' on switch 'SN1' is present in both "
            r"'group-a' and 'group-b'"
        ),
    ):
        orchestrator.preflight([first, second])


def test_manage_interface_group_00270(monkeypatch) -> None:
    """Reject one logical vPC member supplied under opposite peers."""
    calls: list[str] = []

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        calls.append(path)
        return {"switchId": "SN1", "peerSwitchId": "SN2"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    first = _group(
        "group-a",
        group_type="vpc",
        members=[("SN1", ["vPC200"])],
    )
    second = _group(
        "group-b",
        group_type="vpc",
        members=[("SN2", ["vPC200"])],
    )

    with pytest.raises(
        RuntimeError,
        match=(
            r"Interface 'vPC200' on vPC pair 'SN1/SN2' is present in both "
            r"'group-a' and 'group-b'"
        ),
    ):
        orchestrator.preflight([first, second])

    assert calls == ["/api/v1/manage/fabrics/fab1/switches/SN2/vpcPair"]


def test_manage_interface_group_00280(monkeypatch) -> None:
    """Keep same-named vPC members on unrelated pairs independent."""

    def fake_request(self, path, verb, **kwargs):
        del self, verb, kwargs
        if "/switches/SN1/" in path:
            return {"switchId": "SN1", "peerSwitchId": "SN3"}
        return {"switchId": "SN2", "peerSwitchId": "SN4"}

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    first = _group(
        "group-a",
        group_type="vpc",
        members=[("SN1", ["vPC200"])],
    )
    second = _group(
        "group-b",
        group_type="vpc",
        members=[("SN2", ["vPC200"])],
    )

    orchestrator.preflight([first, second])

    assert first.switch_interfaces[0].switch_id == "SN1"
    assert second.switch_interfaces[0].switch_id == "SN2"


def test_manage_interface_group_00290(monkeypatch) -> None:
    """Stop the state machine in preflight before a conflicting vPC PUT."""
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "query_all",
        lambda self: [],
    )

    def fake_request(self, path, verb, **kwargs):
        del self, kwargs
        calls.append((str(verb), path))
        if path.endswith("/switches/SN2/vpcPair"):
            return {"switchId": "SN1", "peerSwitchId": "SN2"}
        raise AssertionError(f"Unexpected mutation request: {verb} {path}")

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", fake_request)
    module = SimpleNamespace(
        check_mode=False,
        params={
            "fabric_name": "fab1",
            "state": "merged",
            "config_actions": {"deploy": False, "type": "switch"},
            "output_level": "normal",
            "config": [
                {
                    "interface_group_name": "group-a",
                    "type": "vpc",
                    "switch_interfaces": [
                        {"switch_id": "SN1", "interface_names": ["vPC200"]}
                    ],
                },
                {
                    "interface_group_name": "group-b",
                    "type": "vpc",
                    "switch_interfaces": [
                        {"switch_id": "SN2", "interface_names": ["vPC200"]}
                    ],
                },
            ],
        },
    )
    state_machine = NDStateMachine(
        module=module,
        model_orchestrator=ManageInterfaceGroupOrchestrator,
    )

    with pytest.raises(
        NDStateMachineError,
        match=r"Interface 'vPC200'.*present in both 'group-a' and 'group-b'",
    ):
        state_machine.manage_state()

    assert calls == [
        (
            "HttpVerbEnum.GET",
            "/api/v1/manage/fabrics/fab1/switches/SN2/vpcPair",
        )
    ]


def test_manage_interface_group_00300(monkeypatch) -> None:
    """Avoid peer lookups when no logical vPC ownership collision is possible."""

    def unexpected_request(*args, **kwargs):
        del args, kwargs
        raise AssertionError("A vPC peer lookup was not required")

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        unexpected_request,
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    unique_vpc = _group(
        "vpc-group",
        group_type="vpc",
        members=[("SN1", ["vPC200"])],
    )
    first_port_channel = _group(
        "pc-group-a",
        members=[("SN1", ["Port-channel10"])],
    )
    second_port_channel = _group(
        "pc-group-b",
        members=[("SN2", ["Port-channel10"])],
    )

    orchestrator.preflight([unique_vpc, first_port_channel, second_port_channel])


@pytest.mark.parametrize(
    ("existing", "partial", "message"),
    [
        (
            _group("group-a", group_type="ethernetWithoutPolicy"),
            {
                "interface_group_name": "group-a",
                "ethernet_attributes": {"admin_status": True},
            },
            "ethernet_attributes must be empty for type=ethernetWithoutPolicy",
        ),
        (
            _group("group-a", group_type="portChannel"),
            {
                "interface_group_name": "group-a",
                "switch_interfaces": [
                    {
                        "switch_id": "SN1",
                        "interface_names": ["Ethernet1/1"],
                    }
                ],
            },
            "is not valid for interface group type 'portChannel'",
        ),
    ],
)
def test_manage_interface_group_00310(
    monkeypatch,
    existing: InterfaceGroupConfigModel,
    partial: dict,
    message: str,
) -> None:
    """Validate partial merged input against the queried Interface Group type."""

    def unexpected_request(*args, **kwargs):
        del args, kwargs
        raise AssertionError("Effective configuration validation needs no request")

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        unexpected_request,
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"group-a": existing}
    proposed = InterfaceGroupConfigModel.from_config(partial)

    with pytest.raises(ValueError, match=message):
        orchestrator.preflight([proposed])

    assert orchestrator._existing_groups["group-a"] == existing


def test_manage_interface_group_00320(monkeypatch) -> None:
    """Accept a valid type-omitted merged update without another query."""

    def unexpected_request(*args, **kwargs):
        del args, kwargs
        raise AssertionError("Effective configuration validation needs no request")

    monkeypatch.setattr(
        ManageInterfaceGroupOrchestrator,
        "_request",
        unexpected_request,
    )
    existing = _group(
        "group-a",
        group_type="portChannel",
        members=[("SN1", ["Port-channel10"])],
    )
    orchestrator = _orchestrator(config_actions={"deploy": False, "type": "switch"})
    orchestrator._existing_groups = {"group-a": existing}
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group-a",
            "switch_interfaces": [
                {
                    "switch_id": "SN1",
                    "interface_names": ["Port-channel20"],
                }
            ],
        }
    )

    orchestrator.preflight([proposed])
    effective = orchestrator._effective_model(proposed)

    assert effective.type == "portChannel"
    assert effective.switch_interfaces[0].interface_names == [
        "Port-channel10",
        "Port-channel20",
    ]
    assert orchestrator._existing_groups["group-a"] == existing
