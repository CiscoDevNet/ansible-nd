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
