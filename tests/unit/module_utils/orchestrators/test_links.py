# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the nd_manage_links strategies and orchestrator helpers.

Covers strategy-driven endpoint query-param population with URL encoding for
both link scopes and the bulk per-item failure guard.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.links import NDLinkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.manage_link import ManageLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.one_manage_link import OneManageLinkStrategy

# ---------------------------------------------------------------------------
# Strategy -> endpoint path building (URL encoded)
# ---------------------------------------------------------------------------


def test_manage_read_path_encodes_params():
    strategy = ManageLinkStrategy(fabric_name="fab a", cluster_name="cl&1", ticket_id="CHG 9")
    endpoint = strategy.links_get_cls()
    strategy.configure_read(endpoint)
    path = endpoint.path
    assert path.startswith("/api/v1/manage/links?")
    assert "fabricName=fab%20a" in path
    assert "clusterName=cl%261" in path
    assert "ticketId=CHG%209" in path
    assert " " not in path and "&cl&1" not in path  # nothing left raw


def test_manage_mutation_paths_encode_cluster_and_ticket():
    strategy = ManageLinkStrategy(fabric_name="fab1", cluster_name="c x", ticket_id="t&1")
    post = strategy.links_post_cls()
    strategy.configure_mutation(post)
    assert "clusterName=c%20x" in post.path and "ticketId=t%261" in post.path

    remove = strategy.link_actions_remove_post_cls()
    strategy.configure_mutation(remove)
    assert post.path.split("?")[0].endswith("/links")
    assert remove.path.split("?")[0].endswith("/linkActions/remove")


def test_manage_put_path_includes_link_id_before_query():
    strategy = ManageLinkStrategy(fabric_name="fab1", ticket_id="t1")
    put = strategy.link_put_cls()
    put.link_uuid = "LINK-123"
    strategy.configure_mutation(put)
    assert put.path.startswith("/api/v1/manage/links/LINK-123?")
    assert "ticketId=t1" in put.path


def test_one_manage_read_path_encodes_cluster_filters():
    strategy = OneManageLinkStrategy(fabric_name="fab1", ticket_id="CHG&7")
    endpoint = strategy.links_get_cls()
    strategy.configure_read(endpoint, src_cluster_name="c+a", dst_cluster_name="c b")
    path = endpoint.path
    assert "fabricName=fab1" in path
    assert "srcClusterName=c%2Ba" in path
    assert "dstClusterName=c%20b" in path


def test_one_manage_mutation_uses_ticket_id_only():
    strategy = OneManageLinkStrategy(fabric_name="fab1", cluster_name="ignored", ticket_id="CHG&7")
    post = strategy.links_post_cls()
    strategy.configure_mutation(post)
    assert "ticketId=CHG%267" in post.path
    assert "clusterName" not in post.path  # cluster identity is in the payload for one_manage


def test_empty_params_produce_bare_path():
    strategy = ManageLinkStrategy(fabric_name=None)
    endpoint = strategy.links_post_cls()
    strategy.configure_mutation(endpoint)
    assert endpoint.path == "/api/v1/manage/links"  # no trailing '?'


# ---------------------------------------------------------------------------
# Bulk per-item failure guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response,should_raise",
    [
        ({"links": [{"linkId": "a", "status": "success"}]}, False),
        ({"links": [{"linkId": "a"}]}, False),
        ([], False),
        ("not-a-dict", False),
        ({"links": [{"linkId": "a", "status": "failure"}]}, True),
        ({"items": [{"id": "b", "success": False}]}, True),
        ({"results": [{"uuid": "c", "error": "boom"}]}, True),
        ({"failed": [{"linkId": "d", "message": "nope"}]}, True),
        ({"links": [{"linkId": "a", "status": "success"}, {"linkId": "e", "status": "failed"}]}, True),
    ],
)
def test_raise_on_bulk_failures(response, should_raise):
    if should_raise:
        with pytest.raises(Exception):
            NDLinkOrchestrator._raise_on_bulk_failures(response, "create")
    else:
        NDLinkOrchestrator._raise_on_bulk_failures(response, "create")


def test_bulk_failure_message_includes_id_and_reason():
    with pytest.raises(Exception) as exc:
        NDLinkOrchestrator._raise_on_bulk_failures({"links": [{"linkId": "L9", "status": "failure", "message": "bad mtu"}]}, "create")
    text = str(exc.value)
    assert "L9" in text and "bad mtu" in text


# ---------------------------------------------------------------------------
# prepare_config_data must not mutate the caller's config (module.params),
# or resolved switch_name/switch_id leak into the invocation echo.
# ---------------------------------------------------------------------------


class _FakeSwitch:
    def __init__(self, switch_id, hostname):
        self.switch_id = switch_id
        self.hostname = hostname


class _FakeIndex:
    def __init__(self, by_ip_map=None, by_id_map=None, switches=None):
        self._by_ip = by_ip_map or {}
        self._by_id = by_id_map or {}
        self.switches = switches or list({switch.switch_id: switch for switch in [*self._by_ip.values(), *self._by_id.values()]}.values())

    def by_ip(self):
        return self._by_ip

    def by_id(self):
        return self._by_id


def _orchestrator():
    from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

    return NDLinkOrchestrator(rest_send=RestSend({"check_mode": False}), strategy=ManageLinkStrategy(fabric_name="f"))


def test_prepare_config_data_backfills_on_copy_not_input():
    orch = _orchestrator()
    # Pre-seed the fabric index cache so no controller call is made.
    orch._switch_index_by_fabric["f"] = _FakeIndex({"1.1.1.1": _FakeSwitch("SID1", "host1")})
    raw = [{"src_fabric_name": "f", "src_switch_ip": "1.1.1.1", "dst_fabric_name": "f", "dst_switch_ip": "1.1.1.1"}]

    result = orch.prepare_config_data(raw)

    # Input (module.params) is untouched, nothing leaks into the invocation echo.
    assert "src_switch_name" not in raw[0]
    assert "src_switch_id" not in raw[0]
    # The returned copy carries the resolved identity used to build the proposed collection.
    assert result is not raw
    assert result[0]["src_switch_name"] == "host1"
    assert result[0]["src_switch_id"] == "SID1"


def test_prepare_config_data_accepts_consistent_mixed_switch_selectors():
    switch = _FakeSwitch("SID1", "leaf1")
    orch = _orchestrator()
    orch._switch_index_by_fabric["f"] = _FakeIndex(by_ip_map={"1.1.1.1": switch}, by_id_map={"SID1": switch})
    raw = [
        {
            "src_fabric_name": "f",
            "src_switch_id": "SID1",
            "src_switch_ip": "1.1.1.1",
            "src_switch_name": "leaf1",
            "dst_fabric_name": "f",
            "dst_switch_id": "SID1",
        }
    ]

    result = orch.prepare_config_data(raw)

    assert result[0]["src_switch_id"] == "SID1"
    assert result[0]["src_switch_name"] == "leaf1"


def test_prepare_config_data_rejects_inconsistent_mixed_switch_selectors():
    first = _FakeSwitch("SID1", "leaf1")
    second = _FakeSwitch("SID2", "leaf2")
    orch = _orchestrator()
    orch._switch_index_by_fabric["f"] = _FakeIndex(by_ip_map={"2.2.2.2": second}, by_id_map={"SID1": first})
    raw = [
        {
            "src_fabric_name": "f",
            "src_switch_id": "SID1",
            "src_switch_ip": "2.2.2.2",
            "dst_fabric_name": "f",
            "dst_switch_id": "SID1",
        }
    ]

    with pytest.raises(Exception, match="do not resolve to the same switch"):
        orch.prepare_config_data(raw)


# ---------------------------------------------------------------------------
# preflight: policy-transition validation runs in both check and normal mode
# ---------------------------------------------------------------------------


def _link_model(policy_type, template_inputs=None):
    return NDLinkModel.from_config(
        {
            "src_fabric_name": "f",
            "dst_fabric_name": "f",
            "src_switch_name": "leaf1",
            "dst_switch_name": "spine1",
            "src_interface_name": "Ethernet1/1",
            "dst_interface_name": "Ethernet1/1",
            "config_data": {"policy_type": policy_type, "template_inputs": template_inputs or {}},
        },
        context={"state": "merged"},
    )


def test_preflight_rejects_policy_transition():
    """A cross-policy update (numbered -> unnumbered) is rejected in preflight, which
    the state machine runs in BOTH modes, so check mode cannot approve a change that
    normal mode rejects."""
    orch = _orchestrator()
    proposed = _link_model("unnumbered")
    object.__setattr__(orch, "_existing_by_key", {proposed.get_identifier_value(): "numbered"})
    with pytest.raises(Exception, match="Cannot change policy_type"):
        orch.preflight([proposed])


def test_preflight_allows_realized_preprovision():
    """Reapplying a preprovision declaration over an ND-realized numbered link is
    persistent intent, not a policy change, so preflight lets it through."""
    orch = _orchestrator()
    proposed = _link_model("preprovision", {"src_interface_description": "planned"})
    object.__setattr__(orch, "_existing_by_key", {proposed.get_identifier_value(): "numbered"})
    orch.preflight([proposed])  # must not raise


def test_is_policy_type_change_false_for_realized_preprovision():
    """The realized preprovision->numbered case is explicitly not treated as a
    policy change by the guard."""
    orch = _orchestrator()
    proposed = _link_model("preprovision")
    object.__setattr__(orch, "_existing_by_key", {proposed.get_identifier_value(): "numbered"})
    assert orch._is_policy_type_change(proposed) is False


def _link_response(link_id):
    return {
        "linkId": link_id,
        "srcFabricName": "f",
        "dstFabricName": "f",
        "srcSwitchName": "leaf1",
        "dstSwitchName": "spine1",
        "srcInterfaceName": "Ethernet1/1",
        "dstInterfaceName": "Ethernet1/1",
        "configData": {"policyType": "numbered", "templateInputs": {}},
    }


def test_duplicate_endpoint_cache_rejects_ambiguous_update_and_delete():
    orch = _orchestrator()
    proposed = _link_model("numbered")
    orch._build_caches([_link_response("L1"), _link_response("L2")])

    with pytest.raises(ValueError, match=r"linkIds: L1, L2"):
        orch._resolve_link_id(proposed, action="update")
    with pytest.raises(ValueError, match=r"linkIds: L1, L2"):
        orch._resolve_link_id(proposed, action="delete")
    with pytest.raises(ValueError, match=r"linkIds: L1, L2"):
        orch.preflight_delete([proposed])


def test_duplicate_endpoint_cache_blocks_authoritative_override():
    orch = _orchestrator()
    orch.rest_send.params["state"] = "overridden"
    orch._build_caches([_link_response("L1"), _link_response("L2")])

    with pytest.raises(ValueError, match="Cannot override link scope"):
        orch.preflight([_link_model("numbered")])


def test_create_bulk_passes_create_operation_type(monkeypatch):
    observed = {}

    def fake_post_bulk(self, endpoint, items, operation_type):
        observed["operation_type"] = operation_type
        return {"links": [{"status": "success"}]}

    monkeypatch.setattr(NDLinkOrchestrator, "_post_bulk", fake_post_bulk)
    _orchestrator().create_bulk([_link_model("numbered")])

    assert observed["operation_type"] == OperationType.CREATE


def test_update_passes_update_operation_type(monkeypatch):
    observed = {}
    orch = _orchestrator()
    model = _link_model("numbered")
    key = model.get_identifier_value()
    object.__setattr__(orch, "_link_id_map", {key: "L1"})
    object.__setattr__(orch, "_link_ids_by_key", {key: ["L1"]})

    def fake_request(self, path, verb, data=None, not_found_ok=False, operation_type=OperationType.QUERY):
        observed["operation_type"] = operation_type
        return {}

    monkeypatch.setattr(NDLinkOrchestrator, "_request", fake_request)
    orch.update(model)

    assert observed["operation_type"] == OperationType.UPDATE


def test_delete_bulk_passes_delete_operation_type(monkeypatch):
    observed = {}
    orch = _orchestrator()
    model = _link_model("numbered")
    key = model.get_identifier_value()
    object.__setattr__(orch, "_link_id_map", {key: "L1"})
    object.__setattr__(orch, "_link_ids_by_key", {key: ["L1"]})

    def fake_post_bulk(self, endpoint, items, operation_type):
        observed["items"] = items
        observed["operation_type"] = operation_type
        return {"links": [{"status": "success"}]}

    monkeypatch.setattr(NDLinkOrchestrator, "_post_bulk", fake_post_bulk)
    orch.delete_bulk([model])

    assert observed == {"items": ["L1"], "operation_type": OperationType.DELETE}
