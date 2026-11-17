# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Canonicalize proven children in mixed parent/child controller preview batches."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_interface_group_deploy_confirmation import (
    DEPLOY,
    ENTRYPOINTS,
    PREVIEW,
    _build,
    _deploy_body,
    _payload,
    _preview_body,
    _response,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator

LOWERCASE_CHILDREN = {
    ("SN1", "port-channel201"),
    ("SN1", "ethernet1/32"),
    ("SN2", "port-channel202"),
    ("SN2", "ethernet1/33"),
}
CANONICAL_CHILDREN = {
    ("SN1", "Port-channel201"),
    ("SN1", "Ethernet1/32"),
    ("SN2", "Port-channel202"),
    ("SN2", "Ethernet1/33"),
}
ORDINARY_TARGETS = {("SN1", "Ethernet1/20"), ("SN2", "Port-channel104")}
PARENT_CLI = {
    "SN1": "interface port-channel201\ninterface ethernet1/32\n",
    "SN2": "interface port-channel202\ninterface ethernet1/33\n",
}


def _mixed_parent_child_preview_endpoint(targets, *, reject_canonical=None):
    """Model the live mixed-batch failure without asserting universal case sensitivity.

    A standalone lowercase port-channel preview succeeds on the observed ND;
    lowercase port-channels overlapping their vPC parent in one request can
    fail to retrieve running configuration. Canonical mixed requests succeed.
    Ethernet-only spelling variants also succeed. Parent CLI still establishes
    exact owner/channel/member proof before generated children are previewed.
    """
    orchestrator, sender = _build([], targets=targets)
    orchestrator._vpc_peer_cache = {"SN1": "SN2", "SN2": "SN1"}
    ordinary = targets - {("SN1", "vPC201")}

    def responses():
        yield _response(DEPLOY, _deploy_body(LOWERCASE_CHILDREN | ordinary))
        while True:
            assert sender.path == PREVIEW
            rows = []
            mixed_parent = any(item["interfaceName"] == "vPC201" for item in sender.payload["interfaces"])
            for item in sender.payload["interfaces"]:
                serial, name = item["switchId"], item["interfaceName"]
                if name == "vPC201":
                    # One logical preview expands to both switch-scoped parents.
                    for owner in ("SN1", "SN2"):
                        row = _preview_body({(owner, name)})["configurationDiffs"][0]
                        row["combinedConfigs"].append({"configType": "expected", "lines": 2, "config": PARENT_CLI[owner]})
                        rows.append(row)
                    continue
                row = _preview_body({(serial, name)})["configurationDiffs"][0]
                overlapping_lowercase_po = mixed_parent and name.startswith("port-channel")
                if overlapping_lowercase_po or (serial, name) == reject_canonical:
                    row.update(status="failed", message="Failed to retrieve running configuration")
                rows.append(row)
            yield _response(PREVIEW, {"configurationDiffs": rows})

    sender.gen = ResponseGenerator(responses())
    return orchestrator, sender


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("ordinary", [set(), ORDINARY_TARGETS], ids=["vpc-only", "mixed-ordinary-targets"])
def test_lowercase_proven_children_use_canonical_names_in_mixed_parent_preview(entrypoint, ordinary):
    """Canonical spelling must not alter asymmetric IDs, owners or ordinary targets."""
    submitted = {("SN1", "vPC201")} | ordinary
    orchestrator, sender = _mixed_parent_child_preview_endpoint(submitted)

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, PREVIEW]
    assert sender.calls[0]["payload"] == _payload(submitted)
    assert sender.calls[1]["payload"] == _payload({("SN1", "vPC201")} | {pair for pair in ordinary if pair[1].startswith("Port-channel")})
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1
    final_rows = sender.calls[-1]["payload"]["interfaces"]
    final_targets = {(item["switchId"], item["interfaceName"]) for item in final_rows}
    assert final_targets == submitted | CANONICAL_CHILDREN
    assert len(final_rows) == len(final_targets)
    assert ("SN1", "Port-channel201") in final_targets
    assert ("SN2", "Port-channel202") in final_targets
    assert ("SN1", "Port-channel202") not in final_targets
    assert ("SN2", "Port-channel201") not in final_targets


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_failed_canonical_child_preview_does_not_confirm_or_redeploy(entrypoint):
    """Correct wire spelling must never turn a genuine failed child row into proof."""
    submitted = {("SN1", "vPC201")}
    orchestrator, sender = _mixed_parent_child_preview_endpoint(submitted, reject_canonical=("SN1", "Port-channel201"))

    with pytest.raises(RuntimeError, match="preview status.*port-channel201.*is not success"):
        getattr(orchestrator, entrypoint)()

    assert orchestrator._pending_interfaces == submitted
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, PREVIEW]
    assert sender.calls[-1]["payload"] == _payload(submitted | CANONICAL_CHILDREN)
    if entrypoint == "deploy_pending":
        assert orchestrator.deploy_accepted_mutations() == {"interfaces": [], "switches": []}
        assert len(sender.calls) == 3


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_exact_deploy_success_keeps_original_request_and_no_preview(entrypoint):
    """The wire-name correction belongs only to preview, after ambiguous evidence."""
    submitted = {("SN1", "vPC201")} | ORDINARY_TARGETS
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body(submitted))], targets=submitted)

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    assert sender.calls[0]["payload"] == _payload(submitted)
