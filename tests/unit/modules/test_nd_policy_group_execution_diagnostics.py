# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Private execution identities must not change public policy-group errors."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group as module_code
from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_direct_id import (
    Controller,
    GROUP_ID,
    config,
    group,
    invoke as invoke,
)


class DiagnosticController(Controller):
    def __init__(self, records, *, error_detail="diagnostic controller rejection"):
        super().__init__(records)
        self.error_detail = error_detail

    def request(self, verb, path, payload):
        if verb == "PUT":
            self.calls.append((verb, path, deepcopy(payload)))
            return {"RETURN_CODE": 400, "METHOD": verb, "REQUEST_PATH": path, "MESSAGE": "OK", "DATA": {"code": 400, "message": self.error_detail}}
        return super().request(verb, path, payload)


def present(message, entries, groups):
    formatter = getattr(module_code, "_format_execution_error", None)
    return message if formatter is None else formatter(message, entries, groups)


@pytest.mark.parametrize("selector", ["id", "pair", "policy_id"])
def test_rejected_update_retains_exact_public_composite_prefix(invoke, selector):
    description = "unique diagnostic group"
    controller = DiagnosticController([group(description=description)])
    entry = config(priority=600)
    if selector != "id":
        entry.update(name="feature_enable", description=description)
    if selector == "policy_id":
        entry["policy_id"] = GROUP_ID

    result = invoke(controller, [entry])

    expected = (
        f"Failed to update {(description, 'feature_enable')}: "
        f"Update policy group failed for {description!r}: "
        "Request failed (400): OK - ND Error 400: diagnostic controller rejection"
    )
    assert result["failed"] is True
    assert result["msg"] == expected
    assert "execution_key" not in result["msg"]
    assert len(controller.writes("PUT")) == 1
    assert controller.writes("PUT")[0][1].endswith("/" + GROUP_ID)
    assert controller.groups[GROUP_ID]["priority"] == 500


def test_duplicate_same_id_proposals_keep_legacy_initialization_label(invoke):
    description = "same target twice"
    controller = Controller([group(description=description)])

    result = invoke(controller, [config(priority=600), config(priority=700)])

    assert result["failed"] is True
    assert result["msg"] == f"Initialization failed: Item with identifier {(description, 'feature_enable')} already exists. Use replace() to update"
    assert controller.writes() == []


def test_ordinary_duplicate_creates_keep_public_preflight_error(invoke):
    controller = Controller()
    description = "new duplicate target"
    entry = config(name="feature_enable", description=description)

    result = invoke(controller, [entry, deepcopy(entry)])

    assert result["failed"] is True
    assert result["msg"] == (
        "config[1]: Duplicate (description, name) combination found: "
        f"description='{description}', name='feature_enable'. "
        "First occurrence at config[0]. Each policy group must be uniquely identified within the config."
    )
    assert controller.calls == []


def test_private_create_key_is_rendered_as_legacy_collection_error():
    entries = [{"name": "feature_enable", "description": "unresolved framework create"}] * 2
    orchestrator = getattr(module_code, "_PolicyGroupExecutionOrchestrator", module_code.PolicyGroupOrchestrator)
    model_class = orchestrator.model_fields["model_class"].default if "model_class" in orchestrator.model_fields else orchestrator.model_class
    collection = NDConfigCollection(model_class=model_class)
    collection.add(model_class.from_config(entries[0]))

    with pytest.raises(ValueError) as caught:
        collection.add(model_class.from_config(entries[1]))

    message = present("Initialization failed: " + str(caught.value), entries, [])
    assert message == "Initialization failed: Item with identifier ('unresolved framework create', 'feature_enable') already exists. Use replace() to update"


def test_planning_rejection_keeps_public_prefix_and_original_detail(invoke, monkeypatch):
    description = "planning diagnostic group"
    detail = f"merge detail stays {('policy_id', GROUP_ID)}"
    controller = Controller([group(description=description)])

    def reject_merge(self, other):
        raise ValueError(detail)

    monkeypatch.setattr(module_code.PolicyGroupCreate, "merge", reject_merge)
    result = invoke(controller, [config(priority=600)])

    assert result["failed"] is True
    assert result["msg"] == f"Failed to process {(description, 'feature_enable')}: {detail}"
    assert controller.writes() == []


@pytest.mark.parametrize("selector", ["id", "pair"])
def test_tuple_like_user_description_and_controller_detail_remain_verbatim(invoke, selector):
    internal_id = str(("policy_id", GROUP_ID))
    internal_create = str(("create", "plain description", "feature_enable"))
    description = f"user text {internal_id}; {internal_create}"
    detail = f"controller text {internal_id}; {internal_create}; execution_key is literal text"
    controller = DiagnosticController([group(description=description)], error_detail=detail)
    entry = config(priority=600)
    if selector == "pair":
        entry.update(name="feature_enable", description=description)

    result = invoke(controller, [entry])

    assert result["failed"] is True
    assert result["msg"] == (
        f"Failed to update {(description, 'feature_enable')}: "
        f"Update policy group failed for {description!r}: Request failed (400): OK - ND Error 400: {detail}"
    )
    assert controller.writes("PUT")[0][2]["description"] == description


def test_unrecognized_controller_only_message_is_not_rewritten():
    message = f"Controller says {('policy_id', GROUP_ID)} already exists; preserve verbatim"
    assert present(message, [{"name": "feature_enable", "description": "public", "policy_id": GROUP_ID}], [group(description="public")]) == message


@pytest.mark.parametrize("description_case", ["null", "missing", "empty"])
def test_anonymous_template_delete_uses_exact_controller_id(invoke, description_case):
    current = group(description=None if description_case == "null" else "")
    if description_case == "missing":
        current.pop("description")
    controller = Controller([current])

    result = invoke(controller, [{"name": "feature_enable"}], state="deleted")

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.groups == {}
    assert [call[2] for call in controller.writes() if call[1].endswith("/markDelete")] == [{"policyIds": [GROUP_ID]}]
    assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == [GROUP_ID]
