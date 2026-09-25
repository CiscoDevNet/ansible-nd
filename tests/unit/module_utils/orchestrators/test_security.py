# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for shared security orchestrator behavior."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActions,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import (
    SecurityAssociationModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import (
    SecurityContractModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import (
    SecurityGroupModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityAssociationOrchestrator,
    SecurityContractOrchestrator,
    SecurityGroupOrchestrator,
    SecurityProtocolDefinitionOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _rest_send(
    *,
    state: str = "merged",
    check_mode: bool = False,
    controller_version: str | None = "4.3.1",
    config: list[dict] | None = None,
) -> RestSend:
    """Build a RestSend instance without a live sender."""
    instance = RestSend(
        {
            "check_mode": check_mode,
            "fabric_name": "SITE1",
            "cluster_name": "cluster-a",
            "state": state,
            "config": config or [],
        }
    )
    instance.controller_version = controller_version
    return instance


def _record_response(rest_send: RestSend, data: dict, return_code: int = 207) -> None:
    """Record a controller response so freshness-sensitive recovery can inspect it."""
    response = {"RETURN_CODE": return_code, "MESSAGE": "Multi-Status", "DATA": data}
    rest_send.response_current = response
    rest_send.add_response(response)


def _group(name: str, group_id: int, *, attach: bool | None = None) -> SecurityGroupModel:
    data = {"name": name, "id": group_id, "vrf_names": ["vrf1"]}
    if attach is not None:
        data["attach"] = attach
    return SecurityGroupModel.from_config(data, context={"controller_version": "4.3.1"})


def _association(**overrides) -> SecurityAssociationModel:
    data = {
        "name": "web_to_app",
        "contract_name": "allow_web",
        "src_security_group_name": "web",
        "src_vrf_name": "vrf1",
        "dst_security_group_name": "app",
        "dst_vrf_name": "vrf1",
    }
    data.update(overrides)
    return SecurityAssociationModel.from_config(data, context={"controller_version": "4.3.1"})


def test_security_orchestrator_00010():
    """Verify all concrete orchestrators instantiate and expose their envelope keys."""
    protocol = SecurityProtocolDefinitionOrchestrator(rest_send=_rest_send())
    contract = SecurityContractOrchestrator(rest_send=_rest_send())
    group = SecurityGroupOrchestrator(rest_send=_rest_send())
    association = SecurityAssociationOrchestrator(rest_send=_rest_send())

    assert protocol.list_response_key == "securityProtocolDefinitions"
    assert contract.list_response_key == "securityContracts"
    assert group.list_response_key == "securityGroups"
    assert association.list_response_key == "securityAssociations"


def test_security_orchestrator_00020():
    """Verify explicit attach transitions are planned and rendered in check mode."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(check_mode=True))
    current = _group("app_web", 101, attach=False)
    proposed = _group("app_web", 101, attach=True)
    instance._existing_by_identifier["app_web"] = current  # pylint: disable=protected-access

    instance.preflight([proposed])
    result = instance.flush_pending_actions(check_mode=True)

    assert result == {"attach": {"planned": True, "securityGroupNames": ["app_web"]}}


def test_security_orchestrator_00030():
    """Verify an already-satisfied attach value is not queued repeatedly."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    current = _group("app_web", 101, attach=True)
    proposed = _group("app_web", 101, attach=True)
    instance._existing_by_identifier["app_web"] = current  # pylint: disable=protected-access

    instance.preflight([proposed])

    assert instance._pending_attach == []  # pylint: disable=protected-access
    assert instance._pending_detach == []  # pylint: disable=protected-access


def test_security_orchestrator_00040():
    """Verify immutable fields are validated from cache without a per-item GET."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="merged"))
    current = _association()
    proposed = _association(contract_name="deny_web")
    instance._existing_by_identifier["web_to_app"] = current  # pylint: disable=protected-access

    with patch.object(
        SecurityAssociationOrchestrator,
        "query_one",
        side_effect=AssertionError("unexpected GET"),
    ):
        with pytest.raises(RuntimeError, match="immutable security resource field.*contract_name"):
            instance.preflight([proposed])


def test_security_orchestrator_00050():
    """Verify partial merged association config inherits cached required fields."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="merged"))
    current = _association()
    proposed = SecurityAssociationModel.from_config(
        {"name": "web_to_app", "description": "updated"},
        context={"controller_version": "4.3.1"},
    )
    instance._existing_by_identifier["web_to_app"] = current  # pylint: disable=protected-access

    instance.preflight([proposed])


@pytest.mark.parametrize(
    ("controller_version", "raises"),
    [("4.2.1.10", True), ("4.3.1", False), ("4.3(1)", False), ("unknown", True)],
)
def test_security_orchestrator_00060(controller_version, raises):
    """Verify security-group IDs remain required for 4.2/unknown creates only."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(controller_version=controller_version))
    proposed = SecurityGroupModel.from_config(
        {"name": "app_web", "vrf_names": ["vrf1"]},
        context={"controller_version": controller_version},
    )

    if raises:
        with pytest.raises(ValueError, match="missing required field.*id"):
            instance.preflight_create([proposed])
    else:
        instance.preflight_create([proposed])


def test_security_orchestrator_00070():
    """Verify cluster context reaches fabric and config-action endpoints."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())

    assert instance.fabric_context.cluster_name == "cluster-a"
    assert instance.config_save_endpoint("SITE1").path.endswith("/actions/configSave?clusterName=cluster-a")
    assert instance.switches_endpoint("SITE1").path.endswith("/switches?clusterName=cluster-a")
    assert instance.switch_deploy_endpoint("SITE1").path.endswith("/switchActions/deploy?clusterName=cluster-a")
    assert instance.deploy_global_endpoint("SITE1").path.endswith("/actions/deploy?clusterName=cluster-a&forceShowRun=true&inclAllFabricGroupsSwitches=true")


def test_security_orchestrator_00080():
    """Verify switch-scoped config actions use switchActions/deploy with switch IDs."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    switches = [{"switchId": "FDO1", "additionalData": {"configSyncStatus": "outOfSync"}}]
    actions = ConfigActions(save=True, deploy=True, type="switch", provided=True)

    with (
        patch.object(SecurityGroupOrchestrator, "_get_fabric_switches", return_value=switches),
        patch.object(SecurityGroupOrchestrator, "_request", return_value={}) as request,
    ):
        result = instance.run_config_actions(actions, ["SITE1"])

    assert result is not None
    assert result.status == "completed"
    assert request.call_count == 2
    assert request.call_args_list[0].kwargs["path"].endswith("/actions/configSave?clusterName=cluster-a")
    assert request.call_args_list[1].kwargs["path"].endswith("/switchActions/deploy?clusterName=cluster-a")
    assert request.call_args_list[1].kwargs["data"] == {"switchIds": ["FDO1"]}


def test_security_orchestrator_00090():
    """Verify global config actions use the fabric-wide deploy endpoint without a body."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    switches = [{"switchId": "FDO1", "additionalData": {"configSyncStatus": "outOfSync"}}]
    actions = ConfigActions(save=True, deploy=True, type="global", provided=True)

    with (
        patch.object(SecurityGroupOrchestrator, "_get_fabric_switches", return_value=switches),
        patch.object(SecurityGroupOrchestrator, "_request", return_value={}) as request,
    ):
        result = instance.run_config_actions(actions, ["SITE1"])

    assert result is not None
    assert result.status == "completed"
    assert request.call_count == 2
    assert "/actions/deploy?" in request.call_args_list[1].kwargs["path"]
    assert "data" not in request.call_args_list[1].kwargs


def test_security_orchestrator_00100():
    """Verify capped pages continue by metadata and cache normalized objects."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    pages = [
        {
            "securityGroups": [
                {
                    "name": "group_one",
                    "displayName": "group_one",
                    "id": 101,
                    "vrfNames": ["vrf1"],
                }
            ],
            "meta": {"counts": {"remaining": 1}, "links": {"next": "/next"}},
        },
        {
            "securityGroups": [
                {
                    "name": "group_two",
                    "displayName": "Friendly",
                    "id": 102,
                    "vrfNames": ["vrf1"],
                }
            ],
            "meta": {"counts": {"remaining": 0}},
        },
    ]

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=pages) as request,
    ):
        result = instance.query_all()

    assert [item["name"] for item in result] == ["group_one", "group_two"]
    assert "displayName" not in result[0]
    assert result[1]["displayName"] == "Friendly"
    assert instance._existing_by_identifier["group_one"].display_name is None  # pylint: disable=protected-access
    assert request.call_count == 2
    assert "offset=0&max=1000" in request.call_args_list[0].kwargs["path"]
    assert "offset=1&max=1000" in request.call_args_list[1].kwargs["path"]


def test_security_orchestrator_00110():
    """Verify pagination fails instead of looping when ND repeats a page."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    page = {
        "securityGroups": [{"name": "group_one", "id": 101, "vrfNames": ["vrf1"]}],
        "meta": {"counts": {"remaining": 1}},
    }

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=[page, page]),
        pytest.raises(RuntimeError, match="same page twice"),
    ):
        instance.query_all()


def test_security_orchestrator_00112():
    """Verify reordered duplicate pages fail as soon as pagination makes no identity progress."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    pages = [
        {
            "securityGroups": [
                {"name": "group_one", "id": 101, "vrfNames": ["vrf1"]},
                {"name": "group_two", "id": 102, "vrfNames": ["vrf1"]},
            ],
            "meta": {"counts": {"remaining": 2}},
        },
        {
            "securityGroups": [
                {"name": "group_two", "id": 102, "vrfNames": ["vrf1"]},
                {"name": "group_one", "id": 101, "vrfNames": ["vrf1"]},
            ],
            "meta": {"counts": {"remaining": 1}},
        },
    ]

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=pages) as request,
        pytest.raises(RuntimeError, match="adds no new resource identities"),
    ):
        instance.query_all()

    assert request.call_count == 2


def test_security_orchestrator_00113():
    """Verify terminal counts override the nonempty next link shown in both API specs."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    page = {
        "securityGroups": [
            {"name": "group_one", "id": 101, "vrfNames": ["vrf1"]},
            {"name": "group_two", "id": 102, "vrfNames": ["vrf1"]},
        ],
        "meta": {
            "counts": {"remaining": 0, "total": 2},
            "links": {"next": "/securityGroups?offset=2&max=2"},
        },
    }

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", return_value=page) as request,
    ):
        result = instance.query_all()

    assert [item["name"] for item in result] == ["group_one", "group_two"]
    request.assert_called_once()


def test_security_orchestrator_00114():
    """Verify known counts continue pagination when a later page omits metadata."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    pages = [
        {
            "securityGroups": [{"name": "group_one", "id": 101, "vrfNames": ["vrf1"]}],
            "meta": {"counts": {"remaining": 1, "total": 2}},
        },
        {"securityGroups": [{"name": "group_two", "id": 102, "vrfNames": ["vrf1"]}]},
    ]

    with (
        patch.object(SecurityGroupOrchestrator, "page_size", 1),
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=pages) as request,
    ):
        result = instance.query_all()

    assert [item["name"] for item in result] == ["group_one", "group_two"]
    assert request.call_count == 2


def test_security_orchestrator_001145():
    """Verify a 404 after the first resource page fails instead of returning partial state."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    first_page = {
        "securityGroups": [{"name": "group_one", "id": 101, "vrfNames": ["vrf1"]}],
        "meta": {"counts": {"remaining": 1}},
    }
    call_count = 0

    def request(**_kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return first_page
        _record_response(rest_send, {}, return_code=404)
        return {}

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=request),
        pytest.raises(RuntimeError, match="404 after earlier pages"),
    ):
        instance.query_all()

    assert call_count == 2


@pytest.mark.parametrize("value", [True, 1.2, 1.0, "1.2", "+1", " 1 "])
def test_security_orchestrator_00115(value):
    """Verify pagination counts reject booleans, floats, and non-digit strings."""
    result = {"meta": {"counts": {"remaining": value}}}

    with pytest.raises(RuntimeError, match="must be a non-negative integer"):
        SecurityGroupOrchestrator._remaining_count(result)  # pylint: disable=protected-access


@pytest.mark.parametrize(("value", "expected"), [(0, 0), (2, 2), ("0", 0), ("12", 12)])
def test_security_orchestrator_00117(value, expected):
    """Verify pagination counts accept non-negative integers and digit strings."""
    result = {"meta": {"counts": {"remaining": value}}}

    assert SecurityGroupOrchestrator._remaining_count(result) == expected  # pylint: disable=protected-access


def test_security_orchestrator_00120():
    """Verify gathered validates existence without rejecting frozen or remote fabrics."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(state="gathered"))
    context = Mock()
    context.fabric_exists.return_value = True
    instance._fabric_context = context  # pylint: disable=protected-access

    instance.validate_prerequisites()

    context.fabric_exists.assert_called_once_with()
    context.validate_for_mutation.assert_not_called()


def test_security_orchestrator_00130():
    """Verify security validation context carries the cached controller version."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(controller_version="4.3.1.7"))

    assert instance.model_validation_context() == {"controller_version": "4.3.1.7"}


def test_security_orchestrator_00140():
    """Verify an explicit display_name equal to name remains managed and idempotent."""
    config = [
        {
            "name": "group_one",
            "id": 101,
            "display_name": "group_one",
            "vrf_names": ["vrf1"],
        }
    ]
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(config=config))
    page = {
        "securityGroups": [
            {
                "name": "group_one",
                "displayName": "group_one",
                "id": 101,
                "vrfNames": ["vrf1"],
            }
        ],
        "meta": {"counts": {"remaining": 0}},
    }

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", return_value=page),
    ):
        result = instance.query_all()

    current = instance._existing_by_identifier["group_one"]  # pylint: disable=protected-access
    proposed = SecurityGroupModel.from_config(config[0], context={"controller_version": "4.3.1"})
    assert result[0]["displayName"] == "group_one"
    assert current.display_name == "group_one"
    assert current.get_diff(proposed) is True


def test_security_orchestrator_00142():
    """Verify explicit display_name tracking uses the tenant-qualified group identity."""
    config = [
        {
            "name": "group_one",
            "tenant_name": "tenantA",
            "id": 101,
            "display_name": "tenantA~group_one",
            "vrf_names": ["tenantA~vrf1"],
        }
    ]
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(config=config))
    page = {
        "securityGroups": [
            {
                "name": "tenantA~group_one",
                "tenantName": "tenantA",
                "displayName": "tenantA~group_one",
                "id": 101,
                "vrfNames": ["tenantA~vrf1"],
            }
        ],
        "meta": {"counts": {"remaining": 0}},
    }

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", return_value=page),
    ):
        result = instance.query_all()

    current = instance._existing_by_identifier["tenantA~group_one"]  # pylint: disable=protected-access
    assert result[0]["displayName"] == "tenantA~group_one"
    assert current.display_name == "tenantA~group_one"


@pytest.mark.parametrize(
    "orchestrator_class",
    [SecurityProtocolDefinitionOrchestrator, SecurityContractOrchestrator],
)
def test_security_orchestrator_00145(orchestrator_class):
    """Verify explicit display_name tracking follows case-insensitive model identities."""
    config = [{"name": "MixedCase", "display_name": "MixedCase"}]
    instance = orchestrator_class(rest_send=_rest_send(config=config))

    normalized = instance._normalize_response_item({"name": "mixedcase", "displayName": "mixedcase"})  # pylint: disable=protected-access

    assert normalized["displayName"] == "mixedcase"


def test_security_orchestrator_00150():
    """Verify total metadata advances capped pages and overlapping identities are deduplicated."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    pages = [
        {
            "securityGroups": [
                {"name": "group_one", "id": 101, "vrfNames": ["vrf1"]},
                {"name": "group_two", "id": 102, "vrfNames": ["vrf1"]},
            ],
            "meta": {"counts": {"total": 3}},
        },
        {
            "securityGroups": [
                {"name": "group_two", "id": 102, "vrfNames": ["vrf1"]},
                {"name": "group_three", "id": 103, "vrfNames": ["vrf1"]},
            ],
            "meta": {"counts": {"total": 3}},
        },
    ]

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=pages) as request,
    ):
        result = instance.query_all()

    assert [item["name"] for item in result] == [
        "group_one",
        "group_two",
        "group_three",
    ]
    assert set(instance._existing_by_identifier) == {
        "group_one",
        "group_two",
        "group_three",
    }  # pylint: disable=protected-access
    assert "offset=2&max=1000" in request.call_args_list[1].kwargs["path"]


def test_security_orchestrator_00160():
    """Verify pagination stops at an explicit maximum even when metadata never terminates."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    pages = [
        {
            "securityGroups": [{"name": "group_one", "id": 101, "vrfNames": ["vrf1"]}],
            "meta": {"counts": {"remaining": 1}},
        },
        {
            "securityGroups": [{"name": "group_two", "id": 102, "vrfNames": ["vrf1"]}],
            "meta": {"counts": {"remaining": 1}},
        },
    ]

    with (
        patch.object(SecurityGroupOrchestrator, "max_pages", 2),
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=pages),
        pytest.raises(RuntimeError, match="maximum of 2 pages"),
    ):
        instance.query_all()


def test_security_orchestrator_00170():
    """Verify an ND 4.3 generated group ID is copied from the successful 207 create envelope."""
    rest_send = _rest_send(controller_version="4.3.1")
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    proposed = SecurityGroupModel.from_config(
        {"name": "generated_id", "vrf_names": ["vrf1"]},
        context={"controller_version": "4.3.1"},
    )
    response_data = {"securityGroups": [{"securityGroupName": "generated_id", "id": 4201, "status": "success"}]}

    def request(**_kwargs):
        _record_response(rest_send, response_data)
        return response_data

    with patch.object(SecurityGroupOrchestrator, "_request", side_effect=request):
        instance.create_bulk([proposed])

    assert proposed.id == 4201
    assert [(item.name, item.id) for item in instance.accepted_upserts] == [("generated_id", 4201)]


@pytest.mark.parametrize(
    ("orchestrator_class", "response_key", "label_key"),
    [
        (
            SecurityProtocolDefinitionOrchestrator,
            "securityProtocolDefinitions",
            "protocolDefinitionName",
        ),
        (SecurityProtocolDefinitionOrchestrator, "protocols", "resourceName"),
        (SecurityContractOrchestrator, "securityContracts", "contractName"),
        (SecurityGroupOrchestrator, "securityGroups", "securityGroupName"),
        (
            SecurityAssociationOrchestrator,
            "securityAssociations",
            "securityAssociationName",
        ),
    ],
)
def test_security_orchestrator_00180(orchestrator_class, response_key, label_key):
    """Verify partial-success recovery recognizes each family's actual item label."""
    rest_send = _rest_send()
    instance = orchestrator_class(rest_send=rest_send)
    submitted = instance.model_class.model_construct(name="accepted")
    previous_response_count = rest_send.response_count
    _record_response(rest_send, {response_key: [{label_key: "accepted", "status": "success"}]})

    accepted = instance._accepted_models_from_latest_response(  # pylint: disable=protected-access
        [submitted],
        [response_key],
        previous_response_count,
    )

    assert accepted == [submitted]


@pytest.mark.parametrize("return_code", [200, 207])
def test_security_orchestrator_00190(return_code):
    """Verify mixed 2xx create records exact-success resources and reports the rejected subset."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    accepted = _group("accepted", 101, attach=True)
    rejected = _group("rejected", 102, attach=True)
    instance.preflight_create([accepted, rejected])
    response_data = {
        "securityGroups": [
            {"securityGroupName": "accepted", "status": "success"},
            {
                "securityGroupName": "rejected",
                "status": "failed",
                "message": "invalid selector",
            },
        ]
    }

    def request(**_kwargs):
        _record_response(rest_send, response_data, return_code=return_code)
        raise RuntimeError(f"mixed {return_code}")

    with (
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=request),
        pytest.raises(RuntimeError, match="accepted.*same request"),
    ):
        instance.create_bulk([accepted, rejected])

    assert [item.name for item in instance.accepted_upserts] == ["accepted"]
    assert instance._pending_attach == [
        "accepted",
        "rejected",
    ]  # pylint: disable=protected-access


@pytest.mark.parametrize("rejected_status", ["warning", "notexecuted", "unknown", None])
def test_security_orchestrator_00195(rejected_status):
    """Verify a normal itemized HTTP 200 create accepts only exact-success members."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    accepted = _group("accepted", 101)
    rejected = _group("rejected", 102)
    rejected_row = {"securityGroupName": "rejected"}
    if rejected_status is not None:
        rejected_row["status"] = rejected_status
    response_data = {
        "securityGroups": [
            {"securityGroupName": "accepted", "status": "success"},
            rejected_row,
        ]
    }

    def request(**_kwargs):
        _record_response(rest_send, response_data, return_code=200)
        return response_data

    with (
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=request),
        pytest.raises(RuntimeError, match="accepted.*same request"),
    ):
        instance.create_bulk([accepted, rejected])

    assert [item.name for item in instance.accepted_upserts] == ["accepted"]


@pytest.mark.parametrize("return_code", [200, 207])
def test_security_orchestrator_00200(return_code):
    """Verify a mixed 2xx attach does not prevent detach processing and preserves accepted detail."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    instance._pending_attach = [
        "accepted",
        "rejected",
    ]  # pylint: disable=protected-access
    instance._pending_detach = ["detach_ok"]  # pylint: disable=protected-access
    calls = []

    def request_action(_endpoint, names):
        calls.append(list(names))
        if len(calls) == 1:
            _record_response(
                rest_send,
                {
                    "securityGroups": [
                        {"securityGroupName": "accepted", "status": "success"},
                        {
                            "securityGroupName": "rejected",
                            "status": "failed",
                            "message": "invalid group",
                        },
                    ]
                },
                return_code=return_code,
            )
            raise RuntimeError("mixed attach")
        return {"securityGroups": [{"securityGroupName": "detach_ok", "status": "success"}]}

    with patch.object(SecurityGroupOrchestrator, "_request_action", side_effect=request_action):
        result = instance.flush_pending_actions()

    assert calls == [["accepted", "rejected"], ["detach_ok"]]
    assert result["attach"]["accepted"] == ["accepted"]
    assert result["detach"] == {"securityGroups": [{"securityGroupName": "detach_ok", "status": "success"}]}
    assert instance.pending_action_errors
    assert instance._pending_attach == ["rejected"]  # pylint: disable=protected-access
    assert instance._pending_detach == []  # pylint: disable=protected-access


@pytest.mark.parametrize("return_code", [200, 207])
def test_security_orchestrator_00205(return_code):
    """Verify mixed 2xx delete recovery records only exact-success resources."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    accepted = _group("accepted", 101)
    rejected = _group("rejected", 102)
    response_data = {
        "securityGroups": [
            {"securityGroupName": "accepted", "status": "success"},
            {"securityGroupName": "rejected", "status": "failed", "message": "in use"},
        ]
    }

    def request(**_kwargs):
        _record_response(rest_send, response_data, return_code=return_code)
        raise RuntimeError(f"mixed {return_code}")

    with (
        patch.object(SecurityGroupOrchestrator, "_request", side_effect=request),
        pytest.raises(RuntimeError, match="accepted.*same request"),
    ):
        instance.delete_bulk([accepted, rejected])

    assert [item.name for item in instance.accepted_deletes] == ["accepted"]


def test_security_orchestrator_00210():
    """Verify captured protocol responses tolerate empty tenant/display strings without erasing description."""
    instance = SecurityProtocolDefinitionOrchestrator(rest_send=_rest_send(state="gathered"))
    page = {
        "securityProtocolDefinitions": [
            {
                "name": "tcp_web",
                "tenantName": "",
                "displayName": "",
                "description": "",
                "matchType": "any",
                "matchItems": [
                    {
                        "matchName": "web",
                        "type": "IPv4",
                        "protocolOptions": "TCP",
                        "dstPortRange": "443",
                    }
                ],
            }
        ],
        "meta": {"counts": {"remaining": 0}},
    }

    with (
        patch.object(SecurityProtocolDefinitionOrchestrator, "validate_prerequisites"),
        patch.object(SecurityProtocolDefinitionOrchestrator, "_request", return_value=page),
    ):
        result = instance.query_all()

    assert "tenantName" not in result[0]
    assert "displayName" not in result[0]
    assert result[0]["description"] == ""


@pytest.mark.parametrize(
    "orchestrator_class",
    [
        SecurityProtocolDefinitionOrchestrator,
        SecurityContractOrchestrator,
        SecurityGroupOrchestrator,
        SecurityAssociationOrchestrator,
    ],
)
def test_security_orchestrator_00220(orchestrator_class):
    """Verify all retained get/list response families normalize empty tenant/display strings."""
    instance = orchestrator_class(rest_send=_rest_send())
    captured_item = {
        "name": "captured_resource",
        "tenantName": "",
        "displayName": "",
        "description": "",
    }

    normalized = instance._normalize_response_item(captured_item)  # pylint: disable=protected-access
    model = instance.model_class.from_response(normalized)

    assert model.tenant_name is None
    assert model.display_name is None
    assert model.description == ""


@pytest.mark.parametrize(
    "orchestrator_class",
    [
        SecurityProtocolDefinitionOrchestrator,
        SecurityContractOrchestrator,
        SecurityGroupOrchestrator,
        SecurityAssociationOrchestrator,
    ],
)
def test_security_orchestrator_00225(orchestrator_class):
    """Verify ND's terminal zero-count response is an empty inventory even when it omits the resource envelope."""
    instance = orchestrator_class(rest_send=_rest_send())
    page = {"meta": {"counts": {"remaining": 0, "total": 0}}}

    with (
        patch.object(orchestrator_class, "validate_prerequisites"),
        patch.object(orchestrator_class, "_request", return_value=page),
    ):
        result = instance.query_all()

    assert result == []


@pytest.mark.parametrize(
    ("page", "message"),
    [
        ([], "page must be an object"),
        ({}, "missing the 'securityGroups' envelope"),
        (
            {"meta": {"counts": {"remaining": 1, "total": 0}}},
            "missing the 'securityGroups' envelope",
        ),
        (
            {"meta": {"counts": {"remaining": 0, "total": 1}}},
            "missing the 'securityGroups' envelope",
        ),
        (
            {
                "meta": {
                    "counts": {"remaining": 0, "total": 0},
                    "links": {"next": "/next"},
                }
            },
            "missing the 'securityGroups' envelope",
        ),
        ({"securityGroups": {}}, "'securityGroups' must be a list"),
        ({"securityGroups": [None]}, "securityGroups\\[0\\].*must be an object"),
        ({"securityGroups": [], "meta": []}, "'meta' must be an object"),
    ],
)
def test_security_orchestrator_00230(page, message):
    """Verify list reads fail closed on malformed pages, envelopes, rows, and metadata."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", return_value=page),
        pytest.raises(RuntimeError, match=message),
    ):
        instance.query_all()


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"securityGroups": {}},
        {"securityGroups": [None]},
        {"securityGroups": [{"status": "success"}]},
        {"securityGroups": [{"securityGroupName": "other", "status": "success"}]},
    ],
)
def test_security_orchestrator_00240(data):
    """Verify partial-success recovery rejects malformed or incomplete HTTP 207 data."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    submitted = _group("one", 101)
    previous_response_count = rest_send.response_count
    _record_response(rest_send, data)

    with pytest.raises(RuntimeError, match="Malformed HTTP 207 security response"):
        instance._accepted_models_from_latest_response(  # pylint: disable=protected-access
            [submitted],
            ["securityGroups"],
            previous_response_count,
        )


@pytest.mark.parametrize("rejected_status", ["failed", "failure", "error", "warning", "unknown", None])
def test_security_orchestrator_00245(rejected_status):
    """Verify only exact success is accepted while every other status remains rejected."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    accepted = _group("accepted", 101)
    rejected = _group("rejected", 102)
    previous_response_count = rest_send.response_count
    rejected_row = {"securityGroupName": "rejected"}
    if rejected_status is not None:
        rejected_row["status"] = rejected_status
    _record_response(
        rest_send,
        {
            "securityGroups": [
                {"securityGroupName": "accepted", "status": "success"},
                rejected_row,
            ]
        },
    )

    result = instance._accepted_models_from_latest_response(  # pylint: disable=protected-access
        [accepted, rejected],
        ["securityGroups"],
        previous_response_count,
    )

    assert result == [accepted]


def test_security_orchestrator_00247():
    """Verify group response matching preserves case-sensitive identities."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    upper = _group("Web", 101)
    lower = _group("web", 102)
    previous_response_count = rest_send.response_count
    _record_response(
        rest_send,
        {
            "securityGroups": [
                {"securityGroupName": "Web", "status": "success"},
                {"securityGroupName": "web", "status": "warning"},
            ]
        },
    )

    result = instance._accepted_models_from_latest_response(  # pylint: disable=protected-access
        [upper, lower],
        ["securityGroups"],
        previous_response_count,
    )

    assert result == [upper]


def test_security_orchestrator_00250():
    """Verify CRUD omits action-owned attach while attach planning remains intact."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    current = _group("app_web", 101, attach=False)
    proposed = _group("app_web", 101, attach=True)
    created = _group("new_group", 102, attach=True)
    instance._existing_by_identifier["app_web"] = current  # pylint: disable=protected-access

    instance.preflight([proposed])
    instance.preflight_create([created])
    with patch.object(SecurityGroupOrchestrator, "_request", return_value={}) as request:
        instance.update(proposed)
        instance.create_bulk([created])

    update_payload = request.call_args_list[0].kwargs["data"]
    create_payload = request.call_args_list[1].kwargs["data"]["securityGroups"][0]
    assert "attach" not in update_payload
    assert "attach" not in create_payload
    assert instance._pending_attach == [
        "app_web",
        "new_group",
    ]  # pylint: disable=protected-access


def test_security_orchestrator_00260():
    """Verify mixed attach outcomes use prior state and retain the new-resource controller default."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    current = _group("existing", 101, attach=False)
    existing_desired = _group("existing", 101, attach=True)
    new_desired = _group("new", 102, attach=True)
    instance._existing_by_identifier["existing"] = current  # pylint: disable=protected-access
    instance._record_upserts([existing_desired, new_desired])  # pylint: disable=protected-access
    instance._pending_attach = ["existing", "new"]  # pylint: disable=protected-access

    def request_action(_endpoint, _names):
        _record_response(
            rest_send,
            {
                "securityGroups": [
                    {"securityGroupName": "existing", "status": "success"},
                    {"securityGroupName": "new", "status": "failed"},
                ]
            },
        )
        raise RuntimeError("mixed attach")

    with patch.object(SecurityGroupOrchestrator, "_request_action", side_effect=request_action):
        instance.flush_pending_actions()

    actual = {model.name: model.attach for model in instance.accepted_upserts}
    assert actual == {"existing": True, "new": True}


def test_security_orchestrator_00265():
    """Verify a failed new-resource detach reports the attached controller default."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    created = _group("new", 102, attach=False)
    instance._record_upserts([created])  # pylint: disable=protected-access
    instance._pending_detach = ["new"]  # pylint: disable=protected-access

    def request_action(_endpoint, _names):
        _record_response(
            rest_send,
            {
                "securityGroups": [
                    {"securityGroupName": "new", "status": "failed"},
                ]
            },
        )
        raise RuntimeError("mixed detach")

    with (
        patch.object(
            SecurityGroupOrchestrator,
            "query_one",
            side_effect=RuntimeError("refresh failed"),
        ),
        patch.object(SecurityGroupOrchestrator, "_request_action", side_effect=request_action),
    ):
        result = instance.flush_pending_actions()

    assert result["detach"]["failed"] is True
    assert instance.pending_action_errors
    assert instance._pending_detach == ["new"]  # pylint: disable=protected-access
    assert [(model.name, model.attach) for model in instance.accepted_upserts] == [("new", True)]


def test_security_orchestrator_00270():
    """Verify a rejected detach retains prior attachment while an accepted detach clears it."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    first_current = _group("first", 101, attach=True)
    second_current = _group("second", 102, attach=True)
    first_desired = _group("first", 101, attach=False)
    second_desired = _group("second", 102, attach=False)
    instance._existing_by_identifier.update({"first": first_current, "second": second_current})  # pylint: disable=protected-access
    instance._record_upserts([first_desired, second_desired])  # pylint: disable=protected-access
    instance._pending_detach = ["first", "second"]  # pylint: disable=protected-access

    def request_action(_endpoint, _names):
        _record_response(
            rest_send,
            {
                "securityGroups": [
                    {"securityGroupName": "first", "status": "success"},
                    {"securityGroupName": "second", "status": "failed"},
                ]
            },
        )
        raise RuntimeError("mixed detach")

    with patch.object(SecurityGroupOrchestrator, "_request_action", side_effect=request_action):
        instance.flush_pending_actions()

    actual = {model.name: model.attach for model in instance.accepted_upserts}
    assert actual == {"first": False, "second": True}


def test_security_orchestrator_00280():
    """Verify a controller-default attachment is re-read and no redundant action is sent."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    created = _group("implicit_attach", 101, attach=True)
    instance._record_upserts([created])  # pylint: disable=protected-access
    instance._pending_attach = ["implicit_attach"]  # pylint: disable=protected-access
    current = {
        "name": "implicit_attach",
        "id": 101,
        "vrfNames": ["vrf1"],
        "attach": True,
    }

    with (
        patch.object(SecurityGroupOrchestrator, "query_one", return_value=current),
        patch.object(
            SecurityGroupOrchestrator,
            "_request_action",
            side_effect=AssertionError("redundant action"),
        ),
    ):
        result = instance.flush_pending_actions()

    assert result == {"attach": {"already_satisfied": ["implicit_attach"]}}
    assert instance.pending_action_errors == ()
    assert instance._pending_attach == []  # pylint: disable=protected-access
    assert [(model.name, model.attach) for model in instance.accepted_upserts] == [("implicit_attach", True)]


def test_security_orchestrator_00290():
    """Verify an explicit non-success 207 remains rejected even if a later read would look satisfied."""
    rest_send = _rest_send()
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    created = _group("race_attach", 101, attach=True)
    instance._record_upserts([created])  # pylint: disable=protected-access
    instance._pending_attach = ["race_attach"]  # pylint: disable=protected-access
    before = {"name": "race_attach", "id": 101, "vrfNames": ["vrf1"], "attach": False}

    def request_action(_endpoint, _names):
        _record_response(
            rest_send,
            {
                "securityGroups": [
                    {
                        "securityGroupName": "race_attach",
                        "status": "failed",
                        "message": "already attached",
                    }
                ]
            },
        )
        raise RuntimeError("mixed attach")

    with (
        patch.object(SecurityGroupOrchestrator, "query_one", return_value=before) as query_one,
        patch.object(SecurityGroupOrchestrator, "_request_action", side_effect=request_action),
    ):
        result = instance.flush_pending_actions()

    assert query_one.call_count == 1
    assert result["attach"]["failed"] is True
    assert result["attach"]["accepted"] == []
    assert instance.pending_action_errors
    assert instance._pending_attach == ["race_attach"]  # pylint: disable=protected-access
    assert [(model.name, model.attach) for model in instance.accepted_upserts] == [("race_attach", False)]


def test_security_orchestrator_00300():
    """Verify generated IDs are assigned using case-sensitive group identities."""
    rest_send = _rest_send(controller_version="4.3.1")
    instance = SecurityGroupOrchestrator(rest_send=rest_send)
    upper = SecurityGroupModel.from_config(
        {"name": "Web", "vrf_names": ["vrf1"]},
        context={"controller_version": "4.3.1"},
    )
    lower = SecurityGroupModel.from_config(
        {"name": "web", "vrf_names": ["vrf1"]},
        context={"controller_version": "4.3.1"},
    )
    response_data = {
        "securityGroups": [
            {"securityGroupName": "Web", "id": 4201, "status": "success"},
            {"securityGroupName": "web", "id": 4202, "status": "success"},
        ]
    }

    def request(**_kwargs):
        _record_response(rest_send, response_data)
        return response_data

    with patch.object(SecurityGroupOrchestrator, "_request", side_effect=request):
        instance.create_bulk([upper, lower])

    assert [(model.name, model.id) for model in instance.accepted_upserts] == [
        ("Web", 4201),
        ("web", 4202),
    ]


@pytest.mark.parametrize("display_name", [None, "", "   "])
def test_security_orchestrator_00310(display_name):
    """Verify processed config with an injected null display_name does not claim display-name intent."""
    config = [
        {
            "name": "group_one",
            "id": 101,
            "display_name": display_name,
            "vrf_names": ["vrf1"],
        }
    ]
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(config=config))
    page = {
        "securityGroups": [
            {
                "name": "group_one",
                "displayName": "group_one",
                "id": 101,
                "vrfNames": ["vrf1"],
            }
        ],
        "meta": {"counts": {"remaining": 0}},
    }

    with (
        patch.object(SecurityGroupOrchestrator, "validate_prerequisites"),
        patch.object(SecurityGroupOrchestrator, "_request", return_value=page),
    ):
        result = instance.query_all()

    assert "displayName" not in result[0]
    assert instance._existing_by_identifier["group_one"].display_name is None  # pylint: disable=protected-access


def test_security_orchestrator_00320():
    """Verify immutable contract references use their case-insensitive identity semantics."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="replaced"))
    current = _association(contract_name="Allow_Web")
    proposed = _association(contract_name="allow_web")
    instance._existing_by_identifier["web_to_app"] = current  # pylint: disable=protected-access

    instance.preflight([proposed])


def test_security_orchestrator_00330():
    """Verify immutable security-group references remain case-sensitive."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="replaced"))
    current = _association(src_security_group_name="Web")
    proposed = _association(src_security_group_name="web")
    instance._existing_by_identifier["web_to_app"] = current  # pylint: disable=protected-access

    with pytest.raises(RuntimeError, match="immutable security resource field.*src_security_group_name"):
        instance.preflight([proposed])


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_security_orchestrator_00340(state):
    """Verify omitted controller-derived VRFs do not create immutable or removal differences."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state=state))
    current = _association()
    proposed = SecurityAssociationModel.from_config(
        {
            "name": "web_to_app",
            "contract_name": "allow_web",
            "src_security_group_name": "web",
            "dst_security_group_name": "app",
        },
        context={"controller_version": "4.3.1"},
    )
    instance._existing_by_identifier["web_to_app"] = current  # pylint: disable=protected-access

    instance.preflight([proposed])

    assert current.get_diff(proposed, exclude_unset=False) is True


def test_security_orchestrator_00350():
    """Verify an explicitly changed derived VRF remains an immutable association error."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="replaced"))
    current = _association()
    proposed = _association(src_vrf_name="vrf2", dst_vrf_name="vrf2")
    instance._existing_by_identifier["web_to_app"] = current  # pylint: disable=protected-access

    with pytest.raises(
        RuntimeError,
        match="immutable security resource field.*src_vrf_name.*dst_vrf_name",
    ):
        instance.preflight([proposed])


@pytest.mark.parametrize(
    ("state", "check_mode"),
    [("merged", False), ("replaced", False), ("replaced", True)],
)
def test_security_orchestrator_00360(state, check_mode):
    """Verify security-group IDs are immutable on normal and check-mode updates."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send(state=state, check_mode=check_mode))
    current = _group("app_web", 101)
    proposed = _group("app_web", 102)
    instance._existing_by_identifier["app_web"] = current  # pylint: disable=protected-access

    with pytest.raises(RuntimeError, match="immutable security resource field.*id"):
        instance.preflight([proposed])


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("resource", ["group", "association"])
def test_security_orchestrator_00370(state, resource):
    """Verify replacement omission resets a detached resource to the API attach default."""
    if resource == "group":
        instance = SecurityGroupOrchestrator(rest_send=_rest_send(state=state, check_mode=True))
        current = _group("app_web", 101, attach=False)
        proposed = _group("app_web", 101)
        expected_key = "securityGroupNames"
    else:
        instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state=state, check_mode=True))
        current = _association(attach=False)
        proposed = _association()
        expected_key = "securityAssociationNames"
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])
    result = instance.flush_pending_actions(check_mode=True)

    assert result == {
        "attach": {
            "planned": True,
            expected_key: [str(proposed.get_identifier_value())],
        }
    }


@pytest.mark.parametrize("resource", ["group", "association"])
def test_security_orchestrator_00380(resource):
    """Verify an omitted replacement attach value converges after the default is restored."""
    if resource == "group":
        instance = SecurityGroupOrchestrator(rest_send=_rest_send(state="replaced"))
        current = _group("app_web", 101, attach=True)
        proposed = _group("app_web", 101)
    else:
        instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="replaced"))
        current = _association(attach=True)
        proposed = _association()
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])

    assert instance._pending_attach == []  # pylint: disable=protected-access
    assert instance._pending_detach == []  # pylint: disable=protected-access


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("resource", ["group", "association"])
def test_security_orchestrator_00390(state, resource):
    """Verify an update reapplies explicit detach after CRUD resets attachment."""
    if resource == "group":
        instance = SecurityGroupOrchestrator(rest_send=_rest_send(state=state, check_mode=True))
        current = _group("app_web", 101, attach=False)
        current.description = "before"
        proposed = _group("app_web", 101, attach=False)
        proposed.description = "after"
        expected_key = "securityGroupNames"
    else:
        instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state=state, check_mode=True))
        current = _association(attach=False, description="before")
        proposed = _association(attach=False, description="after")
        expected_key = "securityAssociationNames"
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])
    result = instance.flush_pending_actions(check_mode=True)

    assert result == {
        "detach": {
            "planned": True,
            expected_key: [str(proposed.get_identifier_value())],
        }
    }


@pytest.mark.parametrize("resource", ["group", "association"])
def test_security_orchestrator_00400(resource):
    """Verify merged updates preserve an omitted detached attachment intent."""
    if resource == "group":
        instance = SecurityGroupOrchestrator(rest_send=_rest_send(state="merged", check_mode=True))
        current = _group("app_web", 101, attach=False)
        current.description = "before"
        proposed = SecurityGroupModel.from_config(
            {
                "name": "app_web",
                "id": 101,
                "vrf_names": ["vrf1"],
                "description": "after",
            },
            context={"controller_version": "4.3.1"},
        )
        expected_key = "securityGroupNames"
    else:
        instance = SecurityAssociationOrchestrator(rest_send=_rest_send(state="merged", check_mode=True))
        current = _association(attach=False, description="before")
        proposed = SecurityAssociationModel.from_config(
            {
                "name": "web_to_app",
                "contract_name": "allow_web",
                "src_security_group_name": "web",
                "dst_security_group_name": "app",
                "description": "after",
            },
            context={"controller_version": "4.3.1"},
        )
        expected_key = "securityAssociationNames"
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])
    result = instance.flush_pending_actions(check_mode=True)

    assert result == {
        "detach": {
            "planned": True,
            expected_key: [str(proposed.get_identifier_value())],
        }
    }


@pytest.mark.parametrize(
    ("controller_version", "tenant_name", "expected_direction"),
    [
        ("4.2.1", None, "custom"),
        ("4.2(1)", None, "custom"),
        ("4.3.1", None, "bidirectional"),
        ("unknown", None, "bidirectional"),
        (None, None, "bidirectional"),
        ("4.2.1", "TenantA", "bidirectional"),
        ("4.3.1", "TenantA", "bidirectional"),
        ("unknown", "TenantA", "bidirectional"),
    ],
)
def test_security_orchestrator_00410(controller_version, tenant_name, expected_direction):
    """Verify create defaults follow the controller release and tenant scope."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state="merged",
            check_mode=True,
            controller_version=controller_version,
        )
    )
    config = {"name": "allow_web"}
    if tenant_name is not None:
        config["tenant_name"] = tenant_name
    proposed = SecurityContractModel.from_config(config)

    instance.preflight_create([proposed])

    assert proposed.direction == expected_direction
    assert "direction" in proposed.model_fields_set
    assert proposed.to_payload()["direction"] == expected_direction


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize(
    (
        "controller_version",
        "tenant_name",
        "current_direction",
        "expected_direction",
    ),
    [
        ("4.2.1", None, "bidirectional", "custom"),
        ("4.3.1", None, "custom", "bidirectional"),
        ("unknown", None, "custom", "bidirectional"),
        ("4.2.1", "TenantA", "unidirectional", "bidirectional"),
        ("4.3.1", "TenantA", "unidirectional", "bidirectional"),
    ],
)
def test_security_orchestrator_00420(
    state,
    controller_version,
    tenant_name,
    current_direction,
    expected_direction,
):
    """Verify replacement preflight applies release/scope defaults before diffing."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state=state,
            check_mode=True,
            controller_version=controller_version,
        )
    )
    current_data = {"name": "allow_web", "direction": current_direction}
    proposed_data = {"name": "allow_web"}
    if tenant_name is not None:
        current_data["tenantName"] = tenant_name
        proposed_data["tenant_name"] = tenant_name
    current = SecurityContractModel.from_response(current_data)
    proposed = SecurityContractModel.from_config(proposed_data)
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])

    assert proposed.direction == expected_direction
    assert "direction" in proposed.model_fields_set
    assert current.get_diff(proposed, exclude_unset=False) is False


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize(
    ("controller_version", "tenant_name", "expected_direction"),
    [
        ("4.2.1", None, "custom"),
        ("4.3.1", None, "bidirectional"),
        ("unknown", None, "bidirectional"),
        ("4.2.1", "TenantA", "bidirectional"),
        ("4.3.1", "TenantA", "bidirectional"),
    ],
)
def test_security_orchestrator_00425(state, controller_version, tenant_name, expected_direction):
    """Verify replacement defaults converge without reopening an idempotent diff."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state=state,
            check_mode=True,
            controller_version=controller_version,
        )
    )
    current_data = {"name": "allow_web", "direction": expected_direction}
    proposed_data = {"name": "allow_web"}
    if tenant_name is not None:
        current_data["tenantName"] = tenant_name
        proposed_data["tenant_name"] = tenant_name
    current = SecurityContractModel.from_response(current_data)
    proposed = SecurityContractModel.from_config(proposed_data)
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])

    assert proposed.direction == expected_direction
    assert current.get_diff(proposed, exclude_unset=False) is True


@pytest.mark.parametrize(
    ("tenant_name", "current_direction"),
    [
        (None, "custom"),
        (None, "bidirectional"),
        ("TenantA", "unidirectional"),
        ("TenantA", "custom"),
    ],
)
@pytest.mark.parametrize("controller_version", ["4.2.1", "4.3.1", "unknown"])
def test_security_orchestrator_00430(controller_version, tenant_name, current_direction):
    """Verify merged omission preserves the current direction without mutating input."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state="merged",
            check_mode=True,
            controller_version=controller_version,
        )
    )
    current_data = {"name": "allow_web", "direction": current_direction}
    proposed_data = {"name": "allow_web", "description": "updated"}
    if tenant_name is not None:
        current_data["tenantName"] = tenant_name
        proposed_data["tenant_name"] = tenant_name
    current = SecurityContractModel.from_response(current_data)
    proposed = SecurityContractModel.from_config(proposed_data)
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])

    assert proposed.direction is None
    assert "direction" not in proposed.model_fields_set
    assert current.direction == current_direction
    assert current.description is None


@pytest.mark.parametrize("direction", ["bidirectional", "unidirectional"])
def test_security_orchestrator_00440(direction):
    """Verify ND 4.2 default-tenant contracts reject non-custom directions."""
    instance = SecurityContractOrchestrator(rest_send=_rest_send(controller_version="4.2.1"))
    proposed = SecurityContractModel.from_config({"name": "allow_web", "direction": direction})

    with pytest.raises(ValueError, match="default tenant on ND 4.2.*custom"):
        instance.preflight_create([proposed])


@pytest.mark.parametrize("controller_version", ["4.3.1", "unknown", None])
@pytest.mark.parametrize("direction", ["bidirectional", "unidirectional", "custom"])
def test_security_orchestrator_00445(controller_version, direction):
    """Verify schema behavior allows every default-tenant direction after ND 4.2."""
    instance = SecurityContractOrchestrator(rest_send=_rest_send(controller_version=controller_version))
    proposed = SecurityContractModel.from_config({"name": "allow_web", "direction": direction})

    instance.preflight_create([proposed])

    assert proposed.direction == direction


@pytest.mark.parametrize("controller_version", ["4.3.1", "unknown", None])
def test_security_orchestrator_00447(controller_version):
    """Verify schema behavior permits default-tenant direction transitions."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state="merged",
            check_mode=True,
            controller_version=controller_version,
        )
    )
    current = SecurityContractModel.from_response({"name": "allow_web", "direction": "bidirectional"})
    proposed = SecurityContractModel.from_config({"name": "allow_web", "direction": "unidirectional"})
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])


@pytest.mark.parametrize("controller_version", ["4.2.1", "4.3.1", "unknown", None])
def test_security_orchestrator_00450(controller_version):
    """Verify new tenant-scoped contracts reject custom direction on every release."""
    instance = SecurityContractOrchestrator(rest_send=_rest_send(controller_version=controller_version))
    proposed = SecurityContractModel.from_config({"name": "allow_web", "tenant_name": "TenantA", "direction": "custom"})

    with pytest.raises(ValueError, match="tenant-scoped.*direction='bidirectional'"):
        instance.preflight_create([proposed])


@pytest.mark.parametrize(
    ("controller_version", "tenant_name", "legacy_direction"),
    [
        ("4.2.1", None, "bidirectional"),
        ("4.2.1", None, "unidirectional"),
        ("4.2.1", "TenantA", "custom"),
        ("4.3.1", "TenantA", "custom"),
        ("unknown", "TenantA", "custom"),
    ],
)
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_security_orchestrator_00460(state, controller_version, tenant_name, legacy_direction):
    """Verify exact legacy direction replay allows metadata-only updates."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state=state,
            check_mode=True,
            controller_version=controller_version,
        )
    )
    current_data = {
        "name": "allow_web",
        "direction": legacy_direction,
        "description": "before",
    }
    proposed_data = {
        "name": "allow_web",
        "direction": legacy_direction,
        "description": "after",
    }
    if tenant_name is not None:
        current_data["tenantName"] = tenant_name
        proposed_data["tenant_name"] = tenant_name
    current = SecurityContractModel.from_response(current_data)
    proposed = SecurityContractModel.from_config(proposed_data)
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    instance.preflight([proposed])


@pytest.mark.parametrize(
    (
        "controller_version",
        "tenant_name",
        "current_direction",
        "proposed_direction",
    ),
    [
        ("4.2.1", None, "custom", "bidirectional"),
        ("4.2.1", None, "custom", "unidirectional"),
        ("4.2.1", "TenantA", "bidirectional", "custom"),
        ("4.3.1", "TenantA", "bidirectional", "custom"),
        ("unknown", "TenantA", "bidirectional", "custom"),
    ],
)
def test_security_orchestrator_00470(controller_version, tenant_name, current_direction, proposed_direction):
    """Verify updates cannot introduce an invalid direction/scope combination."""
    instance = SecurityContractOrchestrator(
        rest_send=_rest_send(
            state="merged",
            check_mode=True,
            controller_version=controller_version,
        )
    )
    current_data = {"name": "allow_web", "direction": current_direction}
    proposed_data = {"name": "allow_web", "direction": proposed_direction}
    if tenant_name is not None:
        current_data["tenantName"] = tenant_name
        proposed_data["tenant_name"] = tenant_name
    current = SecurityContractModel.from_response(current_data)
    proposed = SecurityContractModel.from_config(proposed_data)
    instance._existing_by_identifier[proposed.get_identifier_value()] = current  # pylint: disable=protected-access

    with pytest.raises(ValueError, match="unsupported"):
        instance.preflight([proposed])
