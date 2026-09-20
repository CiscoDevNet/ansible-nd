# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `ManageFabricGroupMembersOrchestrator`.

Covers surface resolution (which of the Manage and OneManage APIs owns the fabric group),
the validation that stops a member identity from disagreeing with the resolved surface, and
the per-surface request shapes for querying, adding and removing members.

Every orchestrator call resolves the surface first, so each test's response generator starts
with the Manage fabric GET followed by the OneManage probe.

Scope: methods defined in manage_fabric_group_members.py and the surfaces it selects.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_group_member_surfaces import ManageSurface, OneManageSurface
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_members import ManageFabricGroupMembersOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

# Every negative answer the OneManage probe was observed to give. None of them is fatal:
# Manage keeps serving fabric groups regardless of whether OneManage can be reached.
PROBE_NEGATIVES = [
    "probe_not_found",
    "probe_single_cluster",
    "probe_mcfg_fabric_not_found",
    "probe_local_login_domain",
    "probe_server_error",
]


def responses_members(key: str):
    """Load fixture data for test_manage_fabric_group_members tests."""
    return load_fixture("test_manage_fabric_group_members")[key]


def _build_rest_send(gen_responses: ResponseGenerator, config: list | None = None) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params = {"check_mode": False, "fabric_name": "GROUP1", "config": config or []}
    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _orchestrator(*fixture_keys: str, config: list | None = None, results: Results | None = None) -> ManageFabricGroupMembersOrchestrator:
    """Build an orchestrator whose sender replays `fixture_keys` in order."""

    def responses():
        for key in fixture_keys:
            yield responses_members(key)

    rest_send = _build_rest_send(ResponseGenerator(responses()), config=config)
    return ManageFabricGroupMembersOrchestrator(rest_send=rest_send, results=results)


def _manage(*fixture_keys: str, config: list | None = None, results: Results | None = None) -> ManageFabricGroupMembersOrchestrator:
    """Build an orchestrator that resolves to the Manage surface, then replays `fixture_keys`.

    Resolution asks OneManage first, then falls back to Manage for existence and category.
    """
    return _orchestrator("probe_mcfg_fabric_not_found", "manage_fabric_group", *fixture_keys, config=config, results=results)


def _onemanage(*fixture_keys: str, config: list | None = None) -> ManageFabricGroupMembersOrchestrator:
    """Build an orchestrator that resolves to the OneManage surface, then replays `fixture_keys`.

    A group OneManage claims needs no Manage call at all.
    """
    return _orchestrator("probe_multicluster", *fixture_keys, config=config)


def test_manage_fabric_group_members_init() -> None:
    """Orchestrator instantiates and exposes the expected ClassVars."""
    with does_not_raise():
        instance = _orchestrator()

    assert instance.model_class is FabricGroupMemberModel
    # ND accepts exactly one member per request on both surfaces, so there is no bulk path.
    assert instance.supports_bulk_create is False
    assert instance.supports_bulk_delete is False


def test_manage_fabric_group_members_fabric_name() -> None:
    """fabric_name resolves from rest_send.params (regression: base does not define it)."""
    assert _orchestrator().fabric_name == "GROUP1"


# --------------------------------------------------------------------------- surface resolution


def test_manage_fabric_group_members_resolves_manage_surface() -> None:
    """A group OneManage does not claim is served by the Manage API."""
    instance = _manage()

    assert instance.surface is ManageSurface
    # Cached: a second access must not consume another response.
    assert instance.surface is ManageSurface


def test_manage_fabric_group_members_resolves_onemanage_surface() -> None:
    """A group OneManage reports as multiClusterFabricGroup is served by the OneManage API."""
    instance = _onemanage()

    assert instance.surface is OneManageSurface
    assert instance.surface_note is None


def test_manage_fabric_group_members_unknown_fabric_group_fails() -> None:
    """A fabric_name the controller does not know fails before any member call.

    The members endpoint cannot catch this: it answers 500 "Failed to check fabric type" for
    an unknown name, so the run would otherwise die on an opaque server error.
    """
    instance = _orchestrator("probe_single_cluster", "manage_fabric_missing")

    with pytest.raises(ValueError, match="was not found through the ND Manage API"):
        _ = instance.surface


def test_manage_fabric_group_members_empty_multicluster_group_resolves_to_onemanage() -> None:
    """An empty multi-cluster fabric group still resolves, even though Manage 404s it.

    Manage stops reporting a multi-cluster fabric group once it holds no member on the local
    cluster, which is precisely the state the group is in before its first member is added.
    Asking Manage first would therefore reject the one operation the module exists to perform.
    """
    instance = _orchestrator("probe_multicluster", "onemanage_members_empty")

    assert instance.surface is OneManageSurface
    assert instance.query_all() == []


def test_manage_fabric_group_members_fabric_that_is_not_a_group_fails() -> None:
    """Pointing the module at a fabric rather than a group fails with a focused message.

    A fabric's members endpoint answers 200 with an empty list, so without the category check
    the run would silently report no members and then try to add one.
    """
    instance = _orchestrator("probe_single_cluster", "manage_fabric_plain")

    with pytest.raises(ValueError, match="is a fabric, not a fabric group"):
        _ = instance.surface


@pytest.mark.parametrize("probe_fixture", PROBE_NEGATIVES)
def test_manage_fabric_group_members_probe_negative_selects_manage(probe_fixture: str) -> None:
    """Every observed probe failure selects Manage and records why.

    The status code varies with the reason -- 400 on a single-cluster controller, 400 for a
    single-cluster group on a multi-cluster controller, 500 for a session that did not use the
    multi-cluster login domain -- so the decision cannot be made by classifying the code.
    """
    instance = _orchestrator(probe_fixture, "manage_fabric_group")

    assert instance.surface is ManageSurface
    assert "Manage API" in instance.surface_note


def test_manage_fabric_group_members_probe_does_not_consume_the_retry_window() -> None:
    """The probe must make a single attempt and leave the caller's timeout untouched.

    ``RestSend`` retries a retryable failure for ``timeout`` seconds every ``send_interval``
    seconds, and the 500 a federated controller returns to a local-domain session is
    retryable. Without collapsing the window the probe stalls every task for five minutes
    before acting on an answer it already had.
    """
    instance = _orchestrator("probe_local_login_domain", "manage_fabric_group")
    instance.rest_send.timeout = 300

    assert instance.surface is ManageSurface
    assert instance.rest_send.timeout == 300


def test_manage_fabric_group_members_probe_failure_is_not_recorded_as_failed() -> None:
    """The probe's expected failure must not land in Results as a failed API call.

    ``format_with_verbosity`` promotes an aggregated Results failure into module-level
    ``failed`` at verbosity 2 and above, so registering the probe made every successful run
    against a single-cluster fabric group report failure under ``-vv``.
    """
    results = Results()
    results.state = "merged"
    results.check_mode = False
    instance = _orchestrator("probe_single_cluster", "manage_fabric_group", results=results)

    assert instance.surface is ManageSurface
    assert True not in results.failed


# ------------------------------------------------------------------------- config validation


def test_manage_fabric_group_members_requires_cluster_name_on_onemanage() -> None:
    """A multi-cluster member without cluster_name is rejected before it reaches ND.

    OneManage answers a member lacking ``clusterName`` with an unexplained HTTP 500, and the
    member would never match what ND stores because its identity is (clusterName, name).
    """
    instance = _onemanage(config=[{"member_name": "member-fabric-1", "cluster_name": "cluster-a"}, {"member_name": "member-fabric-2"}])

    with pytest.raises(ValueError, match="'cluster_name' is required"):
        _ = instance.surface


def test_manage_fabric_group_members_rejects_cluster_name_on_manage() -> None:
    """cluster_name against a group OneManage did not claim is rejected, with both fixes offered.

    Manage accepts a ``clusterName`` and silently drops it, so the proposed member could never
    match the stored one: it would look absent on every run, be re-added, and fail the second
    run with "already assigned to Fabric Group".
    """
    instance = _manage(config=[{"member_name": "member-fabric-1", "cluster_name": "cluster-a"}])

    with pytest.raises(ValueError, match="multi-cluster login domain"):
        _ = instance.surface


# ------------------------------------------------------------------------------------ query


def test_manage_fabric_group_members_query_all() -> None:
    """query_all GETs the Manage members endpoint and unwraps the 'fabrics' array."""
    instance = _manage("members_ok")

    with does_not_raise():
        result = instance.query_all()

    assert instance.rest_send.verb == HttpVerbEnum.GET.value
    assert instance.rest_send.path.endswith("/manage/fabrics/GROUP1/members")
    assert [member["name"] for member in result] == ["member-fabric-1", "member-fabric-2"]


def test_manage_fabric_group_members_query_all_empty() -> None:
    """query_all returns an empty list when the group has no members."""
    assert _manage("members_empty").query_all() == []


def test_manage_fabric_group_members_onemanage_query_all() -> None:
    """query_all routes to the OneManage members endpoint for a multi-cluster fabric group."""
    instance = _onemanage("onemanage_members_ok")

    with does_not_raise():
        result = instance.query_all()

    assert instance.rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/members")
    assert [(member["clusterName"], member["name"]) for member in result] == [
        ("cluster-a", "member-fabric-1"),
        ("cluster-b", "member-fabric-2"),
    ]


def test_manage_fabric_group_members_query_one_found() -> None:
    """query_one returns the matching member dict by name."""
    result = _manage("members_ok").query_one(FabricGroupMemberModel(member_name="member-fabric-2"))

    assert result is not None
    assert result["name"] == "member-fabric-2"


def test_manage_fabric_group_members_query_one_missing() -> None:
    """query_one returns None when the member is absent."""
    assert _manage("members_ok").query_one(FabricGroupMemberModel(member_name="not-a-member")) is None


# ------------------------------------------------------------------------------------ write


def test_manage_fabric_group_members_create_sends_single_member_envelope() -> None:
    """A Manage add wraps exactly one member in a members[] array.

    ND rejects a two-member body with "Only one member fabric can be added at a time", so the
    array the Manage schema advertises can never hold more than one element.
    """
    instance = _manage("add_members_success")

    with does_not_raise():
        instance.create(FabricGroupMemberModel(member_name="member-fabric-1"))

    assert instance.rest_send.verb == HttpVerbEnum.POST.value
    assert instance.rest_send.path.endswith("/manage/fabrics/GROUP1/actions/addMembers")
    assert instance.rest_send.committed_payload == {"members": [{"name": "member-fabric-1"}]}


def test_manage_fabric_group_members_delete_sends_single_member_envelope() -> None:
    """A Manage remove uses the same one-element members[] envelope."""
    instance = _manage("remove_members_success")

    with does_not_raise():
        instance.delete(FabricGroupMemberModel(member_name="member-fabric-1"))

    assert instance.rest_send.verb == HttpVerbEnum.POST.value
    assert instance.rest_send.path.endswith("/manage/fabrics/GROUP1/actions/removeMembers")
    assert instance.rest_send.committed_payload == {"members": [{"name": "member-fabric-1"}]}


def test_manage_fabric_group_members_onemanage_create_sends_flat_body() -> None:
    """A OneManage add sends a flat clusterName/name object, not a members[] wrapper.

    The Manage envelope is rejected with HTTP 500, as is a member without clusterName.
    """
    instance = _onemanage("onemanage_add_success", config=[{"member_name": "member-fabric-1", "cluster_name": "cluster-a"}])

    with does_not_raise():
        instance.create(FabricGroupMemberModel(member_name="member-fabric-1", cluster_name="cluster-a"))

    assert instance.rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/addMembers")
    assert instance.rest_send.committed_payload == {"name": "member-fabric-1", "clusterName": "cluster-a"}


def test_manage_fabric_group_members_onemanage_delete_sends_flat_body() -> None:
    """A OneManage remove uses the same flat single-member object."""
    instance = _onemanage("onemanage_remove_success", config=[{"member_name": "member-fabric-1", "cluster_name": "cluster-a"}])

    with does_not_raise():
        instance.delete(FabricGroupMemberModel(member_name="member-fabric-1", cluster_name="cluster-a"))

    assert instance.rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/removeMembers")
    assert instance.rest_send.committed_payload == {"name": "member-fabric-1", "clusterName": "cluster-a"}


def test_manage_fabric_group_members_manage_refusal_names_the_login_domain() -> None:
    """ND's "managed by OneManage" refusal becomes the one instruction that fixes the run.

    This is the case the probe cannot pre-empt: from a session that did not use the
    multi-cluster login domain, OneManage is unreachable, Manage reads the group's members
    happily, and only the write reveals that the group is multi-cluster.
    """
    instance = _manage("add_members_onemanage_refused")

    with pytest.raises(Exception, match="multi-cluster login domain"):
        instance.create(FabricGroupMemberModel(member_name="member-fabric-1"))


def test_manage_fabric_group_members_update_is_rejected() -> None:
    """Membership has no updatable attribute, so update must never reach the API.

    The base implementation would POST to addMembers with the member name substituted into the
    fabric path; this guard exists so that cannot happen if the diff engine ever changes.
    """
    instance = _manage()

    with pytest.raises(Exception, match="cannot be updated in place"):
        instance.update(FabricGroupMemberModel(member_name="member-fabric-1"))


# --------------------------------------------------------------------------- config actions


def test_manage_fabric_group_members_deleted_with_empty_config_removes_nothing() -> None:
    """``state: deleted`` is scoped to the members listed in ``config``, never "remove all".

    An empty ``config`` is a no-op even when the group has members. This matches every other
    module in the collection, all of which document ``deleted`` as removing the resources
    "specified in the configuration", and it means a templated list that resolves to empty
    cannot silently empty a fabric group.
    """
    orchestrator = _manage("members_ok")
    module = MockAnsibleModule()
    module.check_mode = False
    module.params = {"state": "deleted", "config": [], "output_level": "normal", "fabric_name": "GROUP1"}

    state_machine = NDStateMachine(module=module, model_orchestrator=orchestrator)
    state_machine.manage_state()

    assert len(state_machine.before) == 2
    assert len(state_machine.removed) == 0
    assert len(state_machine.existing) == 2


def test_manage_fabric_group_members_config_save_manage() -> None:
    """config_save routes to the Manage configSave endpoint for a single-cluster fabric group."""
    instance = _manage("config_save_success")

    with does_not_raise():
        instance.config_save("GROUP1")

    assert instance.rest_send.verb == HttpVerbEnum.POST.value
    assert instance.rest_send.path.endswith("/manage/fabrics/GROUP1/actions/configSave")


def test_manage_fabric_group_members_config_save_onemanage() -> None:
    """config_save routes to the OneManage configSave endpoint for a multi-cluster fabric group."""
    instance = _onemanage("config_save_success")

    with does_not_raise():
        instance.config_save("GROUP1")

    assert instance.rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/configSave")


def test_manage_fabric_group_members_deploy_global_onemanage() -> None:
    """deploy_global routes to the OneManage deploy endpoint for a multi-cluster fabric group."""
    instance = _onemanage("deploy_success")

    with does_not_raise():
        instance.deploy_global("GROUP1")

    assert instance.rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/deploy")


def test_manage_fabric_group_members_deploy_global_manage_includes_member_switches() -> None:
    """A Manage global deploy must request the fabric group's member-fabric switches.

    The Manage deploy API defaults ``inclAllFabricGroupsSwitches`` to ``false``, which would
    leave member fabrics undeployed despite the module documenting group-wide deployment.
    """
    instance = _manage("deploy_success")

    with does_not_raise():
        instance.deploy_global("GROUP1")

    assert "inclAllFabricGroupsSwitches=true" in instance.rest_send.path


def test_manage_fabric_group_members_deploy_switch_manage() -> None:
    """A switch-scoped deploy queries Manage switches and deploys only out-of-sync serials."""
    instance = _manage("switches_out_of_sync", "switch_deploy_success")

    with does_not_raise():
        instance.deploy_switch_ids("GROUP1", instance.resolve_switch_deploy_targets("GROUP1"))

    assert instance.rest_send.path.endswith("/manage/fabrics/GROUP1/switchActions/deploy")
    assert instance.rest_send.committed_payload == {"switchIds": ["SN-DRIFT"]}


def test_manage_fabric_group_members_deploy_switch_onemanage() -> None:
    """A switch-scoped deploy routes to the OneManage switches and switchActions endpoints."""
    instance = _onemanage("switches_out_of_sync", "switch_deploy_success")

    with does_not_raise():
        instance.deploy_switch_ids("GROUP1", instance.resolve_switch_deploy_targets("GROUP1"))

    assert instance.rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/switchActions/deploy")
    assert instance.rest_send.committed_payload == {"switchIds": ["SN-DRIFT"]}
