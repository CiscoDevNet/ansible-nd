# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)


def test_endpoints_api_v1_vrf_lite_00100_runtime_endpoints_use_required_api_contracts():
    # Legacy top-down paths are hand-built in this module and percent-encode the
    # fabric name, so a spaced name exercises that encoding.
    assert (
        VrfLiteEndpoints.vrf_attachments_query("Fab A", "BLUE,GREEN")
        == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/attachments?vrf-names=BLUE,GREEN"
    )
    assert VrfLiteEndpoints.vrf_attachments_post("Fab A") == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/attachments"
    assert (
        VrfLiteEndpoints.vrf_switch("Fab A", "BLUE", "SN1,SN2")
        == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/Fab%20A/vrfs/switches?vrf-names=BLUE&serial-numbers=SN1,SN2"
    )
    assert VrfLiteEndpoints.reserve_id("Fab A") == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/resource-manager/reserve-id"

    # Manage-API paths delegate to the canonical endpoint models, which own their
    # own path formatting; assert the contract with a plain fabric name.
    assert VrfLiteEndpoints.vrfs("FABRIC1") == "/api/v1/manage/fabrics/FABRIC1/vrfs"
    assert VrfLiteEndpoints.vrf_deployments("FABRIC1") == "/api/v1/manage/fabrics/FABRIC1/vrfActions/deploy"
    assert VrfLiteEndpoints.config_save("FABRIC1") == "/api/v1/manage/fabrics/FABRIC1/actions/configSave"
