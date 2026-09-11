# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `ManageFabricGroupMembersOrchestrator`.

Verifies the orchestrator drives RestSend correctly: fabric_name resolution from
params, query_all unwrapping the 'fabrics' array, query_one name matching, and
bulk add/remove building the {"members": [{"name": ...}]} payload from the model.

Scope: methods defined in manage_fabric_group_members.py only.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_members import ManageFabricGroupMembersOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


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


def test_manage_fabric_group_members_init() -> None:
    """Orchestrator instantiates and exposes expected ClassVars and rest_send."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))

    with does_not_raise():
        instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    assert instance.model_class is FabricGroupMemberModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance.rest_send is rest_send


def test_manage_fabric_group_members_fabric_name() -> None:
    """fabric_name resolves from rest_send.params (regression: base does not define it)."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    assert instance.fabric_name == "GROUP1"


def test_manage_fabric_group_members_query_all() -> None:
    """query_all GETs the members endpoint and unwraps the 'fabrics' array."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("members_ok")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert rest_send.verb == HttpVerbEnum.GET.value
    assert rest_send.path.endswith("/fabrics/GROUP1/members")
    assert [m["name"] for m in result] == ["member-fabric-1", "member-fabric-2"]


def test_manage_fabric_group_members_query_all_empty() -> None:
    """query_all returns an empty list when the group has no members."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("members_empty")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    assert instance.query_all() == []


def test_manage_fabric_group_members_query_one_found() -> None:
    """query_one returns the matching member dict by name."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("members_ok")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    model = FabricGroupMemberModel(member_name="member-fabric-2")

    result = instance.query_one(model)
    assert result is not None
    assert result["name"] == "member-fabric-2"


def test_manage_fabric_group_members_query_one_missing() -> None:
    """query_one returns None when the member is absent."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("members_ok")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    model = FabricGroupMemberModel(member_name="not-a-member")

    assert instance.query_one(model) is None


def test_manage_fabric_group_members_create_bulk() -> None:
    """create_bulk POSTs addMembers with a model-built {'members': [{'name': ...}]} payload."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("add_members_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    models = [FabricGroupMemberModel(member_name="member-fabric-1"), FabricGroupMemberModel(member_name="member-fabric-2")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/fabrics/GROUP1/actions/addMembers")
    body = rest_send.committed_payload
    assert body == {"members": [{"name": "member-fabric-1"}, {"name": "member-fabric-2"}]}


def test_manage_fabric_group_members_delete_bulk() -> None:
    """delete_bulk POSTs removeMembers with a model-built {'members': [{'name': ...}]} payload."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("remove_members_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    models = [FabricGroupMemberModel(member_name="member-fabric-1")]

    with does_not_raise():
        instance.delete_bulk(models)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/fabrics/GROUP1/actions/removeMembers")
    assert rest_send.committed_payload == {"members": [{"name": "member-fabric-1"}]}


def test_manage_fabric_group_members_create_delegates_to_bulk() -> None:
    """create() routes a single member through the bulk add endpoint."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("add_members_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.create(FabricGroupMemberModel(member_name="member-fabric-1"))

    assert rest_send.path.endswith("/fabrics/GROUP1/actions/addMembers")
    assert rest_send.committed_payload == {"members": [{"name": "member-fabric-1"}]}


def test_manage_fabric_group_members_delete_delegates_to_bulk() -> None:
    """delete() routes a single member through the bulk remove endpoint."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("remove_members_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.delete(FabricGroupMemberModel(member_name="member-fabric-1"))

    assert rest_send.path.endswith("/fabrics/GROUP1/actions/removeMembers")
    assert rest_send.committed_payload == {"members": [{"name": "member-fabric-1"}]}


def test_manage_fabric_group_members_multicluster_detection() -> None:
    """A OneManage 'multiClusterFabricGroup' probe flags the orchestrator as multi-cluster (cached)."""

    def responses():
        yield responses_members("probe_multicluster")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    assert instance.is_multicluster is True
    # Cached: a second access must not consume another response.
    assert instance.is_multicluster is True


def test_manage_fabric_group_members_multicluster_query_all() -> None:
    """query_all routes to the OneManage members endpoint when the parent is multi-cluster."""

    def responses():
        yield responses_members("probe_multicluster")
        yield responses_members("onemanage_members_ok")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert rest_send.verb == HttpVerbEnum.GET.value
    assert rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/members")
    assert [m["name"] for m in result] == ["member-fabric-1", "member-fabric-2"]


def test_manage_fabric_group_members_multicluster_create_bulk() -> None:
    """create_bulk routes to the OneManage addMembers endpoint and includes clusterName per member."""

    def responses():
        yield responses_members("probe_multicluster")
        yield responses_members("onemanage_add_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    models = [FabricGroupMemberModel(member_name="member-fabric-1", cluster_name="cluster-a")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/addMembers")
    assert rest_send.committed_payload == {"members": [{"name": "member-fabric-1", "clusterName": "cluster-a"}]}


def test_manage_fabric_group_members_multicluster_delete_bulk() -> None:
    """delete_bulk routes to the OneManage removeMembers endpoint and includes clusterName per member."""

    def responses():
        yield responses_members("probe_multicluster")
        yield responses_members("onemanage_remove_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    models = [FabricGroupMemberModel(member_name="member-fabric-1", cluster_name="cluster-a")]

    with does_not_raise():
        instance.delete_bulk(models)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/removeMembers")
    assert rest_send.committed_payload == {"members": [{"name": "member-fabric-1", "clusterName": "cluster-a"}]}


def test_manage_fabric_group_members_config_save_manage() -> None:
    """config_save routes to the Manage configSave endpoint for a plain fabric group."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("config_save_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.config_save("GROUP1")

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/manage/fabrics/GROUP1/actions/configSave")


def test_manage_fabric_group_members_config_save_multicluster() -> None:
    """config_save routes to the OneManage configSave endpoint for a multi-cluster fabric group."""

    def responses():
        yield responses_members("probe_multicluster")
        yield responses_members("config_save_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.config_save("GROUP1")

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/configSave")


def test_manage_fabric_group_members_config_deploy_global_multicluster() -> None:
    """config_deploy(global) routes to the OneManage deploy endpoint for a multi-cluster fabric group."""

    def responses():
        yield responses_members("probe_multicluster")
        yield responses_members("deploy_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.config_deploy("GROUP1", deploy_type="global")

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/actions/deploy")


def test_manage_fabric_group_members_config_deploy_switch_manage() -> None:
    """config_deploy(switch) queries Manage switches and deploys only out-of-sync serials."""

    def responses():
        yield responses_members("probe_fabric_group")
        yield responses_members("switches_out_of_sync")
        yield responses_members("switch_deploy_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.config_deploy("GROUP1", deploy_type="switch")

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/manage/fabrics/GROUP1/switchActions/deploy")
    assert rest_send.committed_payload == {"switchIds": ["SN-DRIFT"]}


def test_manage_fabric_group_members_config_deploy_switch_multicluster() -> None:
    """config_deploy(switch) routes to the OneManage switches + switchActions endpoints for MCFG."""

    def responses():
        yield responses_members("probe_multicluster")
        yield responses_members("switches_out_of_sync")
        yield responses_members("switch_deploy_success")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.config_deploy("GROUP1", deploy_type="switch")

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/oneManage/manage/fabrics/GROUP1/switchActions/deploy")
    assert rest_send.committed_payload == {"switchIds": ["SN-DRIFT"]}
