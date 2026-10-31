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

import ipaddress
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import EthernetTrunkHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

RETAIN_AUTO_NEGOTIATION_CONFIG = "negotiate auto"
ROUTED_SIBLING_RESET_FIELDS = frozenset({"ip", "prefix", "routingTag", "ipRedirects", "pimSparse", "vrfInterface"})


def has_typed_routed_sibling_residue(config_data: dict) -> bool:
    """Select a corrective PUT for known routed echoes on a current NX trunk.

    These fields are never evidence of an already-default interface. ND may
    retain them after normalize even though the current policy is trunkHost.
    Unknown fields/containers and unqualified value forms grant no exception.
    Nullable routed schema fields and an empty routing tag still select a
    correction; they are not dropped or treated as successful reset evidence.
    """
    # Exact controller/receipt types are part of the validation contract.
    # pylint: disable=unidiomatic-typecheck
    if not isinstance(config_data, dict) or set(config_data) != {"mode", "networkOS"} or config_data.get("mode") != "trunk":
        return False
    network = config_data.get("networkOS")
    if not isinstance(network, dict) or set(network) != {"networkOSType", "policy"} or network.get("networkOSType") != "nx-os":
        return False
    policy = network.get("policy")
    if not isinstance(policy, dict) or policy.get("policyType") != "trunkHost":
        return False
    residue = set(policy) & ROUTED_SIBLING_RESET_FIELDS
    if not residue:
        return False
    known = {field.alias or name for name, field in EthernetTrunkHostPolicyModel.model_fields.items()}
    known.update(InterfaceDefaultPolicyModel().model_dump(by_alias=True))
    if set(policy) - known - ROUTED_SIBLING_RESET_FIELDS - {"ptp"}:
        return False
    if "ip" in residue and policy["ip"] is not None:
        address = policy["ip"]
        if not isinstance(address, str):
            return False
        try:
            if str(ipaddress.IPv4Address(address)) != address:
                return False
        except ipaddress.AddressValueError:
            return False
    for field, minimum, maximum in (("prefix", 1, 31), ("routingTag", 0, 4294967295)):
        if field not in residue:
            continue
        value = policy[field]
        if value is None or field == "routingTag" and value == "":
            continue
        if type(value) is int:
            number = value
        elif isinstance(value, str) and len(value) <= 10 and value.isascii() and value.isdecimal():
            number = int(value)
            if str(number) != value:
                return False
        else:
            return False
        if not minimum <= number <= maximum:
            return False
    # A BGW routed default-VRF interface can retain this exact sibling echo
    # after normalize. It must select replacement, never count as reset.
    # No nondefault, null, empty or differently typed VRF value is qualified.
    if "vrfInterface" in residue and policy["vrfInterface"] != "default":
        return False
    return all(
        policy[field] is None or type(policy[field]) is bool or isinstance(policy[field], str) and policy[field] in {"false", "true"}
        for field in residue & {"ipRedirects", "pimSparse"}
    )


def has_retained_reset_auto_negotiation(config_data: dict) -> bool:
    """Recognize only the redundant positive negotiation command at NX-OS reset defaults.

    This is deliberately not an arbitrary extraConfig exception. Automatic
    speed and enabled negotiation must both be explicit controller intent.
    The callers still validate every other policy field against reset defaults.
    """
    network = config_data.get("networkOS") or {}
    if not isinstance(network, dict):
        return False
    policy = network.get("policy") or {}
    if not isinstance(policy, dict):
        return False
    return (
        config_data.get("mode") == "trunk"
        and network.get("networkOSType") == "nx-os"
        and policy.get("policyType") == "trunkHost"
        and policy.get("speed") == "auto"
        and policy.get("negotiateAuto") is True
        and policy.get("extraConfig") == RETAIN_AUTO_NEGOTIATION_CONFIG
    )


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
    Storm-control numeric thresholds are omitted from reset defaults. ND 4.3.1
    generates real zero-level commands even when `stormControl` is false, so
    zero is not an unconfigured sentinel. An existing threshold selects the
    minimal PUT-as-replace reset instead of a normalize that could retain it.

    Three other fields cannot be reset via normalize because ND's create/update
    validator rejects 0 / null: `bandwidth`, `debounce_linkup_timer` and
    `inherit_bandwidth`. A delete with these fields also selects PUT-as-replace.

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
    # `""` is the template default and what ND 4.2.1 needs to clear a description: 4.2.1 leaves any field the normalize body omits
    # untouched. ND 4.3.1 enforces the spec's `interfaceDescription` minLength 1 (HTTP 400 "minimum string length is 1") but resets
    # an omitted field, so `to_normalize_payload(omit_description=True)` drops the key for it. Lab-verified on both, 2026-09-11.
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
    storm_control_broadcast_level: float | None = Field(default=None, alias="stormControlBroadcastLevel")
    storm_control_broadcast_level_pps: int | None = Field(default=None, alias="stormControlBroadcastLevelPps")
    storm_control_multicast_level: float | None = Field(default=None, alias="stormControlMulticastLevel")
    storm_control_multicast_level_pps: int | None = Field(default=None, alias="stormControlMulticastLevelPps")
    storm_control_unicast_level: float | None = Field(default=None, alias="stormControlUnicastLevel")
    storm_control_unicast_level_pps: int | None = Field(default=None, alias="stormControlUnicastLevelPps")
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

    # TODO(4.2.1) normalize-unresettable-policy-fields
    # Trunk-host policy fields the `interfaceActions/normalize` endpoint cannot reset. ND's create/update validator
    # rejects 0 and null for each of these (HTTP 400), and omitting them leaves the prior wire value in place. Orchestrators
    # use this set to detect when `state: deleted` must fall back to the per-interface PUT-as-replace path via
    # `to_reset_payload()`. Lab-verified on ND 4.2.1 (S1_LE1 Ethernet1/41, 2026-05-29).
    UNRESETTABLE_FIELDS: ClassVar[set[str]] = {"bandwidth", "debounceLinkupTimer", "inheritBandwidth"}
    # Unlike a nullable absent value, an explicit zero emits real storm CLI.
    # All existing non-null rates therefore need the replacement reset path.
    STORM_THRESHOLD_FIELDS: ClassVar[frozenset[str]] = frozenset(
        "stormControl" + traffic + suffix for traffic in ("Broadcast", "Multicast", "Unicast") for suffix in ("Level", "LevelPps")
    )

    @classmethod
    def to_normalize_payload(
        cls,
        switch_interfaces: list[tuple[str, str]],
        omit_description: bool = False,
        retain_auto_negotiation: bool = False,
    ) -> dict:
        """
        # Summary

        Build the full `interfaceActions/normalize` request body from a list of `(interface_name, switch_id)` pairs.

        With `omit_description` the `description` key is dropped from the policy: ND 4.3.1 rejects the template's empty string
        (`interfaceDescription` is minLength 1 in the spec) yet resets an omitted field, while ND 4.2.1 accepts the empty string and
        needs it, since it leaves an omitted field untouched. `EthernetBaseOrchestrator._normalize_interfaces` sends the template
        body first and switches to `omit_description=True` for the rest of the run when the controller answers with that rejection.

        ## Raises

        None
        """
        instance = cls()
        payload = instance.to_payload()
        if retain_auto_negotiation:
            payload["configData"]["networkOS"]["policy"]["extraConfig"] = RETAIN_AUTO_NEGOTIATION_CONFIG
        if omit_description:
            payload["configData"]["networkOS"]["policy"].pop("description", None)
        payload["switchInterfaces"] = [{"interfaceName": name, "switchId": switch_id} for name, switch_id in switch_interfaces]
        return payload

    @classmethod
    def to_reset_payload(cls, interface_name: str, switch_id: str, retain_auto_negotiation: bool = False) -> dict:
        """
        # Summary

        Build the per-interface PUT request body that fully resets an ethernet interface, including the Class C fields
        (`bandwidth`, `debounceLinkupTimer`, `inheritBandwidth`) that the normalize endpoint cannot clear.

        PUT to `/api/v1/manage/fabrics/{fabric}/switches/{sn}/interfaces/{name}` is a true replace: omitted fields fall
        back to ND's schema defaults for the declared `policyType`, so a body containing only `adminState: true`,
        `policyType: "trunkHost"` and the template-required `allowedVlans: "none"` is sufficient to land the interface in the
        same logical state as the normalize template — minus the persisted Class C fields, which clear to null. Lab-verified on
        ND 4.2.1 and 4.3.1.

        ## Raises

        None
        """
        payload = {
            "configData": {
                "mode": "trunk",
                "networkOS": {
                    "networkOSType": "nx-os",
                    # TODO(4.3.1) ethernet-create-required-fields-431
                    # ND 4.3.1 rejects this PUT without `allowedVlans` ("Validation failed for following fields: [allowedVlans]",
                    # lab-verified 2026-09-14 on S3_BG1 Ethernet1/48) where 4.2.1 defaulted it. Sourced from the trunkHost policy
                    # model's `payload_defaults` (issue #564) so the reset body and the create body share one table.
                    "policy": {"adminState": True, "policyType": "trunkHost", **EthernetTrunkHostPolicyModel.payload_defaults},
                },
            },
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "switchId": switch_id,
        }
        if retain_auto_negotiation:
            payload["configData"]["networkOS"]["policy"].update(
                {
                    "speed": "auto",
                    "negotiateAuto": True,
                    "extraConfig": RETAIN_AUTO_NEGOTIATION_CONFIG,
                }
            )
        return payload
