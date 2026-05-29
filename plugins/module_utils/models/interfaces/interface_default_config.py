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

    Field selection is constrained by what ND will actually reset on `interfaceActions/normalize`. A field that is
    not present in the body is left at its prior on-the-wire value (silent drop), so every trunk-host policy field
    that a user might have set via `state: merged` must also appear here with a sentinel that ND interprets as
    "no configuration". Lab-verified on ND 4.2.1 (S1_LE1 Ethernet1/41) for the following classes of fields:

    - String name pointers (`qos_policy`, `queuing_policy`, `netflow_monitor`, `netflow_sampler`): `""` clears.
    - Storm-control numeric levels and PPS counters: `0` / `0.0` clears (and is the natural off-state when
      `storm_control` is false).

    Three fields could NOT be reset via normalize because ND's create/update validator rejects 0 / null on them:
    `bandwidth`, `debounce_linkup_timer`, `inherit_bandwidth`. Users who set these via `state: merged` must
    explicitly clear them via `state: merged` again or `state: replaced` — `state: deleted` will leave them at
    the prior non-default value.

    `vlan_mapping_entries` is deferred until lab-verified on a hardware testbed (N9Kv rejects the parent
    `vlan_mapping` config with HTTP 400, so the wire shape cannot be probed here).

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
    description: str = Field(default="")
    duplex_mode: str = Field(default="auto", alias="duplexMode")
    error_detection_acl: bool = Field(default=True, alias="errorDetectionAcl")
    extra_config: str = Field(default="", alias="extraConfig")
    fec: str = Field(default="auto")
    link_type: str = Field(default="auto", alias="linkType")
    mode: str = Field(default="trunk")
    monitor: bool = Field(default=False)
    mtu: str = Field(default="jumbo")
    native_vlan: int = Field(default=1, alias="nativeVlan")
    negotiate_auto: bool = Field(default=True, alias="negotiateAuto")
    netflow: bool = Field(default=False)
    netflow_monitor: str = Field(default="", alias="netflowMonitor")
    netflow_sampler: str = Field(default="", alias="netflowSampler")
    orphan_port: bool = Field(default=False, alias="orphanPort")
    pfc: bool = Field(default=False)
    policy_type: str = Field(default="trunkHost", alias="policyType")
    port_type_edge_trunk: bool = Field(default=True, alias="portTypeEdgeTrunk")
    qos: bool = Field(default=False)
    qos_policy: str = Field(default="", alias="qosPolicy")
    queuing_policy: str = Field(default="", alias="queuingPolicy")
    speed: str = Field(default="auto")
    storm_control: bool = Field(default=False, alias="stormControl")
    storm_control_action: str = Field(default="default", alias="stormControlAction")
    storm_control_broadcast_level: float = Field(default=0.0, alias="stormControlBroadcastLevel")
    storm_control_broadcast_level_pps: int = Field(default=0, alias="stormControlBroadcastLevelPps")
    storm_control_multicast_level: float = Field(default=0.0, alias="stormControlMulticastLevel")
    storm_control_multicast_level_pps: int = Field(default=0, alias="stormControlMulticastLevelPps")
    storm_control_unicast_level: float = Field(default=0.0, alias="stormControlUnicastLevel")
    storm_control_unicast_level_pps: int = Field(default=0, alias="stormControlUnicastLevelPps")
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

    # Trunk-host policy fields the `interfaceActions/normalize` endpoint cannot reset. ND's create/update validator
    # rejects 0 and null for each of these (HTTP 400), and omitting them leaves the prior wire value in place. Orchestrators
    # use this set to detect when `state: deleted` must fall back to the per-interface PUT-as-replace path via
    # `to_reset_payload()`. Lab-verified on ND 4.2.1 (S1_LE1 Ethernet1/41, 2026-05-29).
    UNRESETTABLE_FIELDS: ClassVar[set[str]] = {"bandwidth", "debounceLinkupTimer", "inheritBandwidth"}

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

    @classmethod
    def to_reset_payload(cls, interface_name: str, switch_id: str) -> dict:
        """
        # Summary

        Build the per-interface PUT request body that fully resets an ethernet interface, including the Class C fields
        (`bandwidth`, `debounceLinkupTimer`, `inheritBandwidth`) that the normalize endpoint cannot clear.

        PUT to `/api/v1/manage/fabrics/{fabric}/switches/{sn}/interfaces/{name}` is a true replace: omitted fields fall
        back to ND's schema defaults for the declared `policyType`, so a body containing only `adminState: true` and
        `policyType: "trunkHost"` is sufficient to land the interface in the same logical state as the normalize template
        — minus the persisted Class C fields, which clear to null. Lab-verified on ND 4.2.1.

        ## Raises

        None
        """
        return {
            "configData": {
                "mode": "trunk",
                "networkOS": {
                    "networkOSType": "nx-os",
                    "policy": {"adminState": True, "policyType": "trunkHost"},
                },
            },
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "switchId": switch_id,
        }
