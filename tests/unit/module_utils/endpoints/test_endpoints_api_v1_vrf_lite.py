# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)


def test_endpoints_api_v1_vrf_lite_00100_runtime_endpoints_use_develop_manage_paths():
    assert VrfLiteEndpoints.vrfs("Fab A") == "/api/v1/manage/fabrics/Fab%20A/vrfs"
    assert (
        VrfLiteEndpoints.vrf_attachments_query("Fab A", "BLUE,RED")
        == "/api/v1/manage/fabrics/Fab%20A/vrfs/attachments?vrf-names=BLUE%2CRED"
    )
    assert VrfLiteEndpoints.vrf_attachments_post("Fab A") == "/api/v1/manage/fabrics/Fab%20A/vrfs/attachments"
    assert VrfLiteEndpoints.vrf_deployments("Fab A") == "/api/v1/manage/fabrics/Fab%20A/vrfs/deployments"
    assert (
        VrfLiteEndpoints.vrf_switch("Fab A", "BLUE", "SN1")
        == "/api/v1/manage/fabrics/Fab%20A/vrfs/switches?vrf-names=BLUE&serial-numbers=SN1"
    )
    assert VrfLiteEndpoints.reserve_id("Fab A") == "/api/v1/manage/fabrics/Fab%20A/resource-manager/reserve-id"
    assert VrfLiteEndpoints.fabric_switches("Fab A") == "/api/v1/manage/fabrics/Fab%20A/switches"
    assert VrfLiteEndpoints.config_save("Fab A") == "/api/v1/manage/fabrics/Fab%20A/actions/configSave"
    assert VrfLiteEndpoints.config_deploy("Fab A") == "/api/v1/manage/fabrics/Fab%20A/actions/deploy?forceShowRun=true"
