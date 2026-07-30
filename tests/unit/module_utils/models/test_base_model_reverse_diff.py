# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `NDBaseModel.get_diff` reverse pass (issue #410).

For `replaced`/`overridden` states the state machine calls `get_diff(..., exclude_unset=False)`; a proposed
item that merely *removed* a field relative to existing device config must classify as a difference so the
full-payload PUT (which clears omitted fields on ND 4.2.1) is issued. The reverse pass is scoped to payload
shape -- fields in `exclude_from_diff` or `payload_exclude_fields` never count as removals -- and normalizes
ND-echoed empty markers (`""`, `[]`, `{}`) to absent so idempotent runs stay idempotent.

The `merged` path (`exclude_unset=True`) is unaffected: omitted fields mean "leave untouched" there.
"""

# pylint: disable=line-too-long

from __future__ import annotations

from typing import ClassVar, Literal

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import EthernetAccessPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import EthernetTrunkHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel, LoopbackPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import PortChannelAccessPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import PortChannelTrunkHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import SubinterfaceManagedPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import AccessVpcHostInterfaceModel, AccessVpcHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_trunk_host_interface import TrunkVpcHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user.local_user import LocalUserModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel, VxlanEbgpManagementModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

SWITCH_IP = "192.0.2.10"
INTERFACE_NAME = "loopback10"


def nd_loopback_response(policy_fields: dict) -> dict:
    """Build an ND-shaped loopback GET response dict carrying the given aliased policy fields."""
    policy = {"policyType": "loopback"}
    policy.update(policy_fields)
    return {"switchIp": SWITCH_IP, "interfaceName": INTERFACE_NAME, "configData": {"networkOS": {"policy": policy}}}


def loopback_config(policy_fields: dict) -> dict:
    """Build an Ansible-shaped proposed loopback config dict carrying the given snake_case policy fields."""
    return {"switch_ip": SWITCH_IP, "interface_name": INTERFACE_NAME, "config_data": {"network_os": {"policy": policy_fields}}}


def test_base_model_reverse_diff_00100() -> None:
    """
    # Summary

    A removal-only proposed item is a difference on the replaced/overridden path: existing carries a nested policy
    field the proposed config omits, so `get_diff(exclude_unset=False)` must report a change (issue #410).

    ## Test

    - An existing model is built from an ND response whose policy carries `adminState` and `description`.
    - A proposed model is built from config carrying only `admin_state` (description intentionally omitted).
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    - utils.has_removals()
    """
    existing = LoopbackInterfaceModel.from_response(nd_loopback_response({"adminState": True, "description": "stale description"}))
    proposed = LoopbackInterfaceModel.from_config(loopback_config({"admin_state": True}))
    assert existing.get_diff(proposed, exclude_unset=False) is False


def test_base_model_reverse_diff_00110() -> None:
    """
    # Summary

    The same removal-only proposed item is NOT a difference on the merged path: omitted fields mean "leave
    untouched" under `merged`, so the reverse pass must not run when `exclude_unset=True`.

    ## Test

    - The identical existing/proposed pair from `test_base_model_reverse_diff_00100`.
    - `get_diff(proposed, exclude_unset=True)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = LoopbackInterfaceModel.from_response(nd_loopback_response({"adminState": True, "description": "stale description"}))
    proposed = LoopbackInterfaceModel.from_config(loopback_config({"admin_state": True}))
    assert existing.get_diff(proposed, exclude_unset=True) is True


def test_base_model_reverse_diff_00120() -> None:
    """
    # Summary

    No false positives: proposed config re-stating the full existing device state remains `no_diff` on the
    replaced/overridden path, so idempotent runs stay idempotent.

    ## Test

    - An existing model is built from an ND response whose policy carries `adminState` and `description`.
    - A proposed model is built from config re-stating both fields with the same values.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    existing = LoopbackInterfaceModel.from_response(nd_loopback_response({"adminState": True, "description": "kept"}))
    proposed = LoopbackInterfaceModel.from_config(loopback_config({"admin_state": True, "description": "kept"}))
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00130() -> None:
    """
    # Summary

    ND-echoed empty markers normalize to absent: an existing policy field echoed as `""` does not force a
    difference when the proposed config omits it (generalizes the PrefixListModel description precedent).

    ## Test

    - An existing model is built from an ND response whose policy carries `adminState` and `extraConfig: ""`.
    - A proposed model is built from config carrying only `admin_state`.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - utils.has_removals()
    """
    existing = LoopbackInterfaceModel.from_response(nd_loopback_response({"adminState": True, "extraConfig": ""}))
    proposed = LoopbackInterfaceModel.from_config(loopback_config({"admin_state": True}))
    assert existing.get_diff(proposed, exclude_unset=False) is True


class _ScopedModel(NDBaseModel):
    """Minimal model exercising the reverse-pass scoping metadata (`exclude_from_diff`, `payload_exclude_fields`)."""

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    exclude_from_diff: ClassVar[set[str]] = {"oper_status"}
    payload_exclude_fields: ClassVar[set[str]] = {"serial"}

    name: str = Field(alias="name")
    serial: str | None = Field(default=None, alias="serial")
    oper_status: str | None = Field(default=None, alias="operStatus")
    description: str | None = Field(default=None, alias="description")


def test_base_model_reverse_diff_00200() -> None:
    """
    # Summary

    Server-populated fields are outside the reverse pass: existing-side values in `exclude_from_diff` or
    `payload_exclude_fields` absent from proposed do NOT count as removals (they are not expressible in the
    PUT payload, so their presence cannot mean a pending reset).

    ## Test

    - An existing model carries `serial` (payload-excluded) and `oper_status` (diff-excluded) but no user field.
    - A proposed model carries only the identifier.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = _ScopedModel.from_response({"name": "item1", "serial": "FDO12345", "operStatus": "up"})
    proposed = _ScopedModel.from_config({"name": "item1"})
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00210() -> None:
    """
    # Summary

    A user-settable payload field on the same model DOES trigger the reverse pass, proving the scoping in
    `test_base_model_reverse_diff_00200` is the exclusion sets and not an accidental no-op.

    ## Test

    - The existing model additionally carries `description`, which is in neither exclusion set.
    - The proposed model still carries only the identifier.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = _ScopedModel.from_response({"name": "item1", "serial": "FDO12345", "operStatus": "up", "description": "stale"})
    proposed = _ScopedModel.from_config({"name": "item1"})
    assert existing.get_diff(proposed, exclude_unset=False) is False


class _DefaultsPolicyModel(NDNestedModel):
    """Nested policy model declaring ND-template defaults for the reverse pass (issue #410 default-echo normalization)."""

    reverse_diff_defaults: ClassVar[dict] = {"mtu": "jumbo", "cdp": True}

    admin_state: bool | None = Field(default=None, alias="adminState")
    mtu: str | None = Field(default=None, alias="mtu")
    cdp: bool | None = Field(default=None, alias="cdp")
    description: str | None = Field(default=None, alias="description")


class _DefaultsModel(NDBaseModel):
    """Top-level model carrying a nested policy, exercising recursive reverse-pass default normalization."""

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    reverse_diff_defaults: ClassVar[dict] = {"tier": "gold"}

    name: str = Field(alias="name")
    tier: str | None = Field(default=None, alias="tier")
    policy: _DefaultsPolicyModel | None = Field(default=None, alias="policy")


def test_base_model_reverse_diff_00300() -> None:
    """
    # Summary

    An existing-side value equal to its declared `reverse_diff_defaults` entry normalizes to absent: ND echoes
    template defaults for every unset field (lab-verified on 4.2.1), so a default-valued echo omitted from the
    proposed config must NOT count as a removal, keeping replaced/overridden runs idempotent.

    ## Test

    - The existing model carries top-level `tier: "gold"` (the declared default) and nothing else the proposed omits.
    - The proposed model carries only the identifier.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = _DefaultsModel.from_response({"name": "item1", "tier": "gold"})
    proposed = _DefaultsModel.from_config({"name": "item1"})
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00310() -> None:
    """
    # Summary

    An existing-side value that DIFFERS from its declared default still counts as a removal: the full-payload PUT
    would revert it to the template default, which is a real device change.

    ## Test

    - The existing model carries top-level `tier: "silver"` (not the declared `"gold"` default).
    - The proposed model carries only the identifier.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = _DefaultsModel.from_response({"name": "item1", "tier": "silver"})
    proposed = _DefaultsModel.from_config({"name": "item1"})
    assert existing.get_diff(proposed, exclude_unset=False) is False


def test_base_model_reverse_diff_00320() -> None:
    """
    # Summary

    Default normalization recurses into nested models using each nested model's own `reverse_diff_defaults`:
    a nested policy echoing only template defaults does not force a difference, while a non-default nested value
    (or a default-less field like `description`) still does.

    ## Test

    - Existing carries a nested policy `{adminState: true, mtu: "jumbo", cdp: true}`; proposed re-states only
      `admin_state`. Both declared defaults normalize away -> no difference.
    - Existing with nested `mtu: "default"` (non-default) -> difference.
    - Existing with nested `description` (no declared default) -> difference.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    proposed = _DefaultsModel.from_config({"name": "item1", "policy": {"admin_state": True}})

    existing = _DefaultsModel.from_response({"name": "item1", "policy": {"adminState": True, "mtu": "jumbo", "cdp": True}})
    assert existing.get_diff(proposed, exclude_unset=False) is True

    existing = _DefaultsModel.from_response({"name": "item1", "policy": {"adminState": True, "mtu": "default"}})
    assert existing.get_diff(proposed, exclude_unset=False) is False

    existing = _DefaultsModel.from_response({"name": "item1", "policy": {"adminState": True, "description": "stale"}})
    assert existing.get_diff(proposed, exclude_unset=False) is False


# The full trunkHost policy echo observed on ND 4.2.1 (SITE1, S1_TOR1 Ethernet1/10) after an admin_state-only PUT:
# ND echoes the schema-declared int_trunk_host template default for every unset field. Hard-coded (not derived from
# the model's table) so an accidental table edit fails this test.
ND_421_TRUNK_HOST_DEFAULT_ECHO = {
    "adminState": True,
    "allowedVlans": "none",
    "bpduFilter": "default",
    "bpduGuard": "default",
    "cdp": True,
    "debounceTimer": 100,
    "duplexMode": "auto",
    "errorDetectionAcl": True,
    "fec": "auto",
    "linkType": "auto",
    "monitor": False,
    "mtu": "jumbo",
    "negotiateAuto": True,
    "netflow": False,
    "orphanPort": False,
    "pfc": False,
    "policyType": "trunkHost",
    "portTypeEdgeTrunk": True,
    "ptp": False,
    "qos": False,
    "speed": "auto",
    "stormControl": False,
    "stormControlAction": "default",
    "vlanMapping": False,
}


def test_base_model_reverse_diff_00400() -> None:
    """
    # Summary

    The lab-observed ND 4.2.1 trunkHost default echo does not break replaced/overridden idempotency: an existing
    policy carrying the full template-default echo, against proposed config re-stating only `admin_state`, is
    `no_diff` (issue #410 lab verification, S1_TOR1 Ethernet1/10).

    ## Test

    - An existing `EthernetTrunkHostPolicyModel` is built from the verbatim ND echo captured in the lab.
    - A proposed model is built from config carrying only `admin_state: true`.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = EthernetTrunkHostPolicyModel.from_response(ND_421_TRUNK_HOST_DEFAULT_ECHO)
    proposed = EthernetTrunkHostPolicyModel.from_config({"admin_state": True})
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00410() -> None:
    """
    # Summary

    A non-default value inside the same echo still triggers the reverse pass: existing `mtu: "default"` (the
    template default is `"jumbo"`) omitted from proposed config means the full-payload PUT would revert it.

    ## Test

    - The lab echo with `mtu` flipped to `"default"`.
    - The same admin_state-only proposed model.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    echo = dict(ND_421_TRUNK_HOST_DEFAULT_ECHO)
    echo["mtu"] = "default"
    existing = EthernetTrunkHostPolicyModel.from_response(echo)
    proposed = EthernetTrunkHostPolicyModel.from_config({"admin_state": True})
    assert existing.get_diff(proposed, exclude_unset=False) is False


def test_base_model_reverse_diff_00420() -> None:
    """
    # Summary

    A user-created loopback echoes ND-injected `routeMapTag: 12345` (the intLoopbackTemplate default, lab-verified
    on 4.2.1) even though the user never sent it -- it must not break replaced/overridden idempotency, while a
    non-default `routeMapTag` must still trigger the reverse pass.

    ## Test

    - An existing `LoopbackPolicyModel` built from the lab-observed echo (adminState/description/ip/routeMapTag).
    - Proposed config re-stating admin_state/description/ip but omitting `route_map_tag`: `no_diff`.
    - The same echo with `routeMapTag: 54321`: difference detected.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    echo = {"adminState": True, "description": "issue-410 probe", "ip": "10.99.205.1", "policyType": "loopback", "routeMapTag": 12345}
    proposed = LoopbackPolicyModel.from_config({"admin_state": True, "description": "issue-410 probe", "ip": "10.99.205.1"})
    existing = LoopbackPolicyModel.from_response(echo)
    assert existing.get_diff(proposed, exclude_unset=False) is True

    echo["routeMapTag"] = 54321
    existing = LoopbackPolicyModel.from_response(echo)
    assert existing.get_diff(proposed, exclude_unset=False) is False


# Every Gen-3 interface policy model carrying a schema-sourced reverse_diff_defaults table. The echo for each is
# derived from the model's own table (the invariant under test: echo == declared defaults -> normalized), with the
# non-empty assertion preventing a trivially passing empty table.
POLICY_MODELS_WITH_DEFAULTS = [
    LoopbackPolicyModel,
    EthernetAccessPolicyModel,
    EthernetTrunkHostPolicyModel,
    PortChannelAccessPolicyModel,
    PortChannelTrunkHostPolicyModel,
    AccessVpcHostPolicyModel,
    TrunkVpcHostPolicyModel,
    SviPolicyModel,
    SubinterfaceManagedPolicyModel,
]


@pytest.mark.parametrize("policy_cls", POLICY_MODELS_WITH_DEFAULTS)
def test_base_model_reverse_diff_00430(policy_cls) -> None:
    """
    # Summary

    Every interface policy model declares a non-empty schema-sourced `reverse_diff_defaults` table, and an existing
    policy echoing exactly those defaults diffs clean against an admin_state-only proposed config on the
    replaced/overridden path.

    ## Test

    - The model's `reverse_diff_defaults` is non-empty (schema-sourced from the ND 4.2.1 OpenAPI template).
    - An existing model built from an echo of exactly those defaults (plus the policyType discriminator).
    - `get_diff(proposed_admin_state_only, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    assert policy_cls.reverse_diff_defaults, f"{policy_cls.__name__} must declare a schema-sourced reverse_diff_defaults table"
    policy_type = policy_cls.model_fields["policy_type"].default
    echo = {"policyType": getattr(policy_type, "value", policy_type), **policy_cls.reverse_diff_defaults}
    existing = policy_cls.from_response(echo)
    proposed = policy_cls.from_config({"admin_state": True})
    assert existing.get_diff(proposed, exclude_unset=False) is True


# --- 005xx: server-populated existing-side data the proposed config can never express ---


VPC_ACCESS_RESPONSE = {
    "switchIp": "192.168.1.1",
    "interfaceName": "vpc100",
    "interfaceType": "vpc",
    "configData": {
        "mode": "access",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "accessVpcHost",
                "peerSwitchId": "FDOPEER0001",
                "adminState": True,
                "accessVlan": 10,
                "peer1PortChannelId": 100,
                "peer2PortChannelId": 100,
                "lacpRate": "fast",
            },
        },
    },
}

VPC_ACCESS_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "vpc100",
    "config_data": {
        "network_os": {
            "policy": {
                "admin_state": True,
                "access_vlan": 10,
                "peer1_port_channel_id": 100,
                "peer2_port_channel_id": 100,
                "lacp_rate": "fast",
            },
        },
    },
}


def test_base_model_reverse_diff_00500() -> None:
    """
    # Summary

    ND echoes the orchestrator-injected `peerSwitchId` inside the vPC policy block; a proposed config restating every
    user-settable field identically must stay `no_diff` on the replaced/overridden path even though it can never
    express `peer_switch_id` (not in the argspec; injected only at payload-build time).

    ## Test

    - An existing `AccessVpcHostInterfaceModel` built from a 4.2.1-wire-shaped response carrying `peerSwitchId`.
    - A proposed model built from config restating every user-settable field with identical values.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = AccessVpcHostInterfaceModel.from_response(VPC_ACCESS_RESPONSE)
    proposed = AccessVpcHostInterfaceModel.from_config(VPC_ACCESS_CONFIG)
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00510() -> None:
    """
    # Summary

    The trunk vPC policy model carries the same orchestrator-injected `peerSwitchId` echo as the access variant and
    must likewise stay `no_diff` when the proposed config restates all user-settable fields.

    ## Test

    - An existing `TrunkVpcHostPolicyModel` built from an echo carrying `peerSwitchId` and `adminState`.
    - A proposed model built from config carrying only `admin_state`.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = TrunkVpcHostPolicyModel.from_response({"policyType": "trunkVpcHost", "peerSwitchId": "FDOPEER0001", "adminState": True})
    proposed = TrunkVpcHostPolicyModel.from_config({"admin_state": True})
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00520() -> None:
    """
    # Summary

    A genuine removal must still be detected on vPC models once `peerSwitchId` is excluded: existing carries a
    user-settable field (`accessVlan`) the proposed config omits, so the reverse pass must report a difference.

    ## Test

    - The existing model from `test_base_model_reverse_diff_00500` (carries `accessVlan` and `peerSwitchId`).
    - A proposed model built from the same config minus `access_vlan`.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - utils.has_removals()
    """
    existing = AccessVpcHostInterfaceModel.from_response(VPC_ACCESS_RESPONSE)
    config = {
        "switch_ip": "192.168.1.1",
        "interface_name": "vpc100",
        "config_data": {
            "network_os": {
                "policy": {
                    "admin_state": True,
                    "peer1_port_channel_id": 100,
                    "peer2_port_channel_id": 100,
                    "lacp_rate": "fast",
                },
            },
        },
    }
    proposed = AccessVpcHostInterfaceModel.from_config(config)
    assert existing.get_diff(proposed, exclude_unset=False) is False


def test_base_model_reverse_diff_00530() -> None:
    """
    # Summary

    Fabric models use `extra="allow"`, so ND GET responses populate undeclared keys on the existing side; those extras
    can never appear in proposed config (argspec-validated) and must not count as removals on the replaced path.

    ## Test

    - An existing `FabricEbgpModel` carrying a top-level extra key (`metadata`) and a nested management extra key.
    - A proposed model built from the same declared fields with no extras.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = FabricEbgpModel(
        fabric_name="F1",
        management=VxlanEbgpManagementModel(bgp_asn="65001", **{"someServerField": "x"}),
        **{"metadata": {"uuid": "abc-123"}},
    )
    proposed = FabricEbgpModel(fabric_name="F1", management=VxlanEbgpManagementModel(bgp_asn="65001"))
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00540() -> None:
    """
    # Summary

    ND echoes `xLaunch=false`, `reuseLimitation=0`, and `timeIntervalLimitation=0` for a local user created without
    those options (lab-verified; the module's integration tests assert these `before` values). A proposed config
    omitting them must stay `no_diff` on the replaced path -- `False`/`0` are not "effectively empty", so this
    normalization must come from the model's `reverse_diff_defaults` table.

    ## Test

    - An existing `LocalUserModel` built from a response echoing the three falsy defaults.
    - A proposed model built from config carrying only `login_id`.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = LocalUserModel.from_response({"loginID": "jdoe", "xLaunch": False, "reuseLimitation": 0, "timeIntervalLimitation": 0})
    proposed = LocalUserModel.from_config({"login_id": "jdoe"})
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00550() -> None:
    """
    # Summary

    A genuine pending reset must still be detected for local users: existing has `xLaunch=true` (non-default), the
    proposed config omits `remote_user_authorization`, so the full-payload PUT would reset it and the reverse pass
    must report a difference.

    ## Test

    - An existing `LocalUserModel` built from a response echoing `xLaunch=true`.
    - A proposed model built from config carrying only `login_id`.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - utils.has_removals()
    """
    existing = LocalUserModel.from_response({"loginID": "jdoe", "xLaunch": True})
    proposed = LocalUserModel.from_config({"login_id": "jdoe"})
    assert existing.get_diff(proposed, exclude_unset=False) is False


# The ND-injected `ptp` echo observed on port-channel policy GETs (deviation: interface-get-undocumented-ptp-field).
# `ptp` is a declared field on PortChannelTrunkHostPolicyModel, so unlike the sibling models (where the injected key
# lands in `model_extra` and is scrubbed as an extra) it survives `from_response` and must be stripped explicitly.
PORT_CHANNEL_TRUNK_HOST_PTP_ECHO = {
    "policyType": "trunkPoHost",
    "adminState": True,
    "allowedVlans": "100-110",
    "ports": ["Ethernet1/1", "Ethernet1/2"],
}

PORT_CHANNEL_TRUNK_HOST_PTP_CONFIG = {
    "admin_state": True,
    "allowed_vlans": "100-110",
    "ports": ["Ethernet1/1", "Ethernet1/2"],
}


def test_base_model_reverse_diff_00560() -> None:
    """
    # Summary

    ND injects `ptp: false` into port-channel trunkPoHost policy GETs even though `intPortChannelTrunkHostTemplate`
    declares no `ptp` property (deviation: interface-get-undocumented-ptp-field). Because `ptp` is a declared field
    on `PortChannelTrunkHostPolicyModel`, the echo survives `from_response`; a proposed config omitting `ptp` must
    still be `no_diff` on the replaced/overridden path (PR #422 review finding).

    ## Test

    - An existing `PortChannelTrunkHostPolicyModel` built from a response carrying the injected `ptp: false`.
    - A proposed model re-stating the configured fields but omitting `ptp`.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = PortChannelTrunkHostPolicyModel.from_response({**PORT_CHANNEL_TRUNK_HOST_PTP_ECHO, "ptp": False})
    proposed = PortChannelTrunkHostPolicyModel.from_config(dict(PORT_CHANNEL_TRUNK_HOST_PTP_CONFIG))
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00570() -> None:
    """
    # Summary

    After a fabric-PTP deploy, ND rewrites the injected `ptp` to `true` fabric-wide on ALL existing physical and
    port-channel records, even on interfaces with no PTP configuration (deviation:
    interface-get-undocumented-ptp-field). The strip must therefore be value-independent (`reverse_diff_exclude`,
    not a `reverse_diff_defaults` entry of `False`) so idempotency also holds against the `true` rewrite.

    ## Test

    - An existing `PortChannelTrunkHostPolicyModel` built from a response carrying the rewritten `ptp: true`.
    - A proposed model re-stating the configured fields but omitting `ptp`.
    - `get_diff(proposed, exclude_unset=False)` is `True` (no difference).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = PortChannelTrunkHostPolicyModel.from_response({**PORT_CHANNEL_TRUNK_HOST_PTP_ECHO, "ptp": True})
    proposed = PortChannelTrunkHostPolicyModel.from_config(dict(PORT_CHANNEL_TRUNK_HOST_PTP_CONFIG))
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_base_model_reverse_diff_00580() -> None:
    """
    # Summary

    The `ptp` strip is reverse-pass-only: a user-set `ptp` that differs from the existing-side echo must still be
    detected by the forward diff, so explicit PTP configuration keeps working.

    ## Test

    - An existing `PortChannelTrunkHostPolicyModel` built from a response carrying `ptp: false`.
    - A proposed model explicitly setting `ptp: true`.
    - `get_diff(proposed, exclude_unset=False)` is `False` (difference detected).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_diff_dict()
    """
    existing = PortChannelTrunkHostPolicyModel.from_response({**PORT_CHANNEL_TRUNK_HOST_PTP_ECHO, "ptp": False})
    proposed = PortChannelTrunkHostPolicyModel.from_config({**PORT_CHANNEL_TRUNK_HOST_PTP_CONFIG, "ptp": True})
    assert existing.get_diff(proposed, exclude_unset=False) is False


# --- 006xx: efficiency contract -- the reverse pass reuses the forward dumps ---


def test_base_model_reverse_diff_00600(monkeypatch) -> None:
    """
    # Summary

    The replaced/overridden no-diff path performs exactly one `model_dump` per side: the reverse pass derives its
    payload-scoped dicts from the already-computed forward dumps instead of re-dumping both models. Guards the
    PR #422 review's efficiency finding against regression -- a second dump per side doubles classification cost
    for every no-diff item in a `query_all` inventory.

    ## Test

    - `NDBaseModel.model_dump` is wrapped with a call counter.
    - `get_diff(proposed, exclude_unset=False)` runs on an idempotent loopback pair (the reverse pass executes).
    - `no_diff` is reported and exactly 2 dumps are observed (one per side).

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_diff_dict()
    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = LoopbackInterfaceModel.from_response(nd_loopback_response({"adminState": True, "description": "kept"}))
    proposed = LoopbackInterfaceModel.from_config(loopback_config({"admin_state": True, "description": "kept"}))

    calls = {"count": 0}
    original_model_dump = NDBaseModel.model_dump

    def counting_model_dump(self, *args, **kwargs):
        calls["count"] += 1
        return original_model_dump(self, *args, **kwargs)

    monkeypatch.setattr(NDBaseModel, "model_dump", counting_model_dump)
    assert existing.get_diff(proposed, exclude_unset=False) is True
    assert calls["count"] == 2, f"expected 2 model dumps (one per side), observed {calls['count']}"


def test_base_model_reverse_diff_00610() -> None:
    """
    # Summary

    `to_reverse_diff_dict` called standalone still yields the payload-scoped, scrubbed dict: top-level
    `payload_exclude_fields` are absent (by alias), and `reverse_diff_defaults` matches are stripped, identical to
    the dict `get_diff` derives internally.

    ## Test

    - A loopback model built from a response carrying `switchIp` (payload-excluded) and default-echo fields.
    - `to_reverse_diff_dict()` omits `switchIp`, omits table-default matches, keeps non-default values.

    ## Classes and Methods

    - NDBaseModel.to_reverse_diff_dict()
    """
    existing = LoopbackInterfaceModel.from_response(nd_loopback_response({"adminState": True, "description": "kept", "routeMapTag": 12345}))
    data = existing.to_reverse_diff_dict()
    assert "switchIp" not in data
    policy = data["configData"]["networkOS"]["policy"]
    assert "adminState" not in policy  # reverse_diff_defaults: adminState True stripped
    assert "routeMapTag" not in policy  # reverse_diff_defaults: "12345" (dumped form) stripped
    assert policy["description"] == "kept"
