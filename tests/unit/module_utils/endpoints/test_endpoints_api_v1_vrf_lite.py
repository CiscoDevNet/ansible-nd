# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpFabricSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpFabricVrfsGet,
    EpFabricVrfsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_attachments import (
    EpFabricVrfsAttachmentsGet,
    EpFabricVrfsAttachmentsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_deployments import (
    EpFabricVrfsDeploymentsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_switches import (
    EpFabricVrfsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_resource_manager_reserve_id import (
    EpResourceManagerReserveIdPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)


def test_endpoints_api_v1_vrf_lite_00100_top_down_vrfs_paths():
    endpoint_get = EpFabricVrfsGet(fabric_name="Fab A")
    endpoint_post = EpFabricVrfsPost(fabric_name="Fab A")

    assert endpoint_get.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs"
    assert endpoint_get.verb == HttpVerbEnum.GET
    assert endpoint_post.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs"
    assert endpoint_post.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_vrf_lite_00200_top_down_attachments_paths():
    endpoint_get = EpFabricVrfsAttachmentsGet(
        fabric_name="Fab A",
        vrf_names="BLUE,RED",
    )
    endpoint_post = EpFabricVrfsAttachmentsPost(fabric_name="Fab A")

    assert endpoint_get.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/attachments?vrf-names=BLUE%2CRED"
    assert endpoint_get.verb == HttpVerbEnum.GET
    assert endpoint_post.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/attachments"
    assert endpoint_post.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_vrf_lite_00300_top_down_switches_deploy_and_reserve_paths():
    endpoint_switches = EpFabricVrfsSwitchesGet(
        fabric_name="Fab A",
        vrf_names="BLUE",
        serial_numbers="SN1",
    )
    endpoint_deploy = EpFabricVrfsDeploymentsPost(fabric_name="Fab A")
    endpoint_reserve = EpResourceManagerReserveIdPost()

    assert endpoint_switches.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/switches?vrf-names=BLUE&serial-numbers=SN1"
    assert endpoint_switches.verb == HttpVerbEnum.GET
    assert endpoint_deploy.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/deployments"
    assert endpoint_deploy.verb == HttpVerbEnum.POST
    assert endpoint_reserve.path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/resource-manager/reserve-id"
    assert endpoint_reserve.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_vrf_lite_00400_manage_paths():
    endpoint_switches = EpFabricSwitchesGet(fabric_name="Fab A")
    endpoint_save = EpFabricConfigSavePost(fabric_name="Fab A")
    endpoint_deploy = EpFabricDeployPost(fabric_name="Fab A")

    assert endpoint_switches.path == "/api/v1/manage/fabrics/Fab%20A/switches"
    assert endpoint_switches.verb == HttpVerbEnum.GET
    assert endpoint_save.path == "/api/v1/manage/fabrics/Fab%20A/actions/configSave"
    assert endpoint_save.verb == HttpVerbEnum.POST
    assert endpoint_deploy.path == "/api/v1/manage/fabrics/Fab%20A/actions/deploy?forceShowRun=true"
    assert endpoint_deploy.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_vrf_lite_00500_runtime_endpoints_use_endpoint_models():
    assert VrfLiteEndpoints.vrfs("Fab A") == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs"
    assert (
        VrfLiteEndpoints.vrf_attachments_query("Fab A", "BLUE,RED")
        == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/attachments?vrf-names=BLUE%2CRED"
    )
    assert VrfLiteEndpoints.vrf_attachments_post("Fab A") == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/attachments"
    assert VrfLiteEndpoints.vrf_deployments("Fab A") == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/deployments"
    assert (
        VrfLiteEndpoints.vrf_switch("Fab A", "BLUE", "SN1")
        == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/switches?vrf-names=BLUE&serial-numbers=SN1"
    )
    assert VrfLiteEndpoints.reserve_id() == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/resource-manager/reserve-id"
    assert VrfLiteEndpoints.fabric_switches("Fab A") == "/api/v1/manage/fabrics/Fab%20A/switches"
    assert VrfLiteEndpoints.config_save("Fab A") == "/api/v1/manage/fabrics/Fab%20A/actions/configSave"
    assert VrfLiteEndpoints.config_deploy("Fab A") == "/api/v1/manage/fabrics/Fab%20A/actions/deploy?forceShowRun=true"
