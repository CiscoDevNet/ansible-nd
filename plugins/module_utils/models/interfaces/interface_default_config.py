# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Default interface configuration for normalizing physical ethernet interfaces on Nexus Dashboard.

Physical ethernet interfaces cannot be deleted — neither `interfaceActions/remove`, `interfaceActions/normalize`
with accessHost config, nor the per-interface `DELETE` endpoint works. However, `interfaceActions/normalize`
DOES work when the payload uses the ND `int_trunk_host` config template with `policyType: "trunkHost"` and
`mode: "trunk"`. This resets the interface to the fabric default trunk host configuration.

`InterfaceDefaultConfig` provides the default `int_trunk_host` template values as a Pydantic model.
The `to_normalize_payload()` class method builds the full `interfaceActions/normalize` request body
from a list of `(interface_name, switch_id)` pairs.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class InterfaceDefaultPolicyModel(NDNestedModel):
    """
    # Summary

    Default policy values from the ND `int_trunk_host` config template. These values represent the fabric default
    configuration for a physical ethernet interface.

    ## Raises

    None
    """

    access_vlan: int = Field(default=1, alias="accessVlan")
    allowed_vlans: str = Field(default="none", alias="allowedVlans")
    admin_state: bool = Field(default=True, alias="adminState")
    bpdu_guard: str = Field(default="default", alias="bpduGuard")
    bpdu_filter: str = Field(default="default", alias="bpduFilter")
    cdp: bool = Field(default=True)
    config_template: str = Field(default="int_trunk_host", alias="configTemplate")
    debounce_timer: int = Field(default=100, alias="debounceTimer")
    duplex_mode: str = Field(default="auto", alias="duplexMode")
    error_detection_acl: bool = Field(default=True, alias="errorDetectionAcl")
    extra_config: str = Field(default="", alias="extraConfig")
    fec: str = Field(default="auto")
    link_type: str = Field(default="auto", alias="linkType")
    mode: str = Field(default="trunk")
    monitor: bool = Field(default=False)
    mtu: str = Field(default="jumbo")
    negotiate_auto: bool = Field(default=True, alias="negotiateAuto")
    netflow: bool = Field(default=False)
    orphan_port: bool = Field(default=False, alias="orphanPort")
    pfc: bool = Field(default=False)
    policy_type: str = Field(default="trunkHost", alias="policyType")
    port_type_edge_trunk: bool = Field(default=True, alias="portTypeEdgeTrunk")
    qos: bool = Field(default=False)
    speed: str = Field(default="auto")
    storm_control: bool = Field(default=False, alias="stormControl")
    storm_control_action: str = Field(default="default", alias="stormControlAction")
    vlan_mapping: bool = Field(default=False, alias="vlanMapping")


class InterfaceDefaultNetworkOSModel(NDNestedModel):
    """
    # Summary

    Default networkOS wrapper for the `int_trunk_host` config template.

    ## Raises

    None
    """

    network_os_type: str = Field(default="nx-os", alias="networkOSType")
    policy: InterfaceDefaultPolicyModel = Field(default_factory=InterfaceDefaultPolicyModel)


class InterfaceDefaultConfigDataModel(NDNestedModel):
    """
    # Summary

    Default configData wrapper for the `int_trunk_host` config template.

    ## Raises

    None
    """

    mode: str = Field(default="trunk")
    network_os: InterfaceDefaultNetworkOSModel = Field(default_factory=InterfaceDefaultNetworkOSModel, alias="networkOS")


class InterfaceDefaultConfig(NDNestedModel):
    """
    # Summary

    Default interface configuration model for normalizing physical ethernet interfaces to their fabric default state
    via the `interfaceActions/normalize` API.

    Uses the ND `int_trunk_host` config template defaults. After normalization, the interface has `policyType: "trunkHost"`
    which removes it from the accessHost (and other type-specific) filters in `query_all()`.

    Use `to_normalize_payload()` to build the full request body for `interfaceActions/normalize`.

    ## Raises

    None
    """

    interface_type: str = Field(default="ethernet", alias="interfaceType")
    config_data: InterfaceDefaultConfigDataModel = Field(default_factory=InterfaceDefaultConfigDataModel, alias="configData")

    PAYLOAD_FIELDS: ClassVar[list[str]] = []

    @classmethod
    def to_normalize_payload(cls, switch_interfaces: list[tuple[str, str]]) -> dict:
        """
        # Summary

        Build the full `interfaceActions/normalize` request body from a list of `(interface_name, switch_id)` pairs.

        ## Raises

        None
        """
        instance = cls()
        payload = instance.to_payload()
        payload["switchInterfaces"] = [{"interfaceName": name, "switchId": switch_id} for name, switch_id in switch_interfaces]
        return payload
