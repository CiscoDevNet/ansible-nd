# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the shared storm-control percentage/pps mutual-exclusion validator (issue #351).

Exercises `StormControlMutexMixin` as applied to all six interface policy models: a config that sets both the
percentage level and the pps level for the same traffic class must be rejected, while setting only one (or putting
the percentage and pps on different classes) is accepted.

Also exercises the response-to-diff-to-merge lifecycle at the top-level interface model layer (PR #360 review):
explicitly selecting one variant of a pair in proposed config must count an existing counterpart as a difference
and clear it during merge, and a dual-valued ND echo must survive unrelated merges untouched.
"""

# pylint: disable=line-too-long
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument

from __future__ import annotations

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import (
    EthernetAccessInterfaceModel,
    EthernetAccessPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceModel,
    EthernetTrunkHostPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessInterfaceModel,
    PortChannelAccessPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceModel,
    PortChannelTrunkHostPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
    AccessVpcHostInterfaceModel,
    AccessVpcHostPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_trunk_host_interface import (
    TrunkVpcHostInterfaceModel,
    TrunkVpcHostPolicyModel,
)
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# Every interface policy model that carries the paired storm-control fields.
POLICY_MODELS = [
    EthernetAccessPolicyModel,
    EthernetTrunkHostPolicyModel,
    PortChannelAccessPolicyModel,
    PortChannelTrunkHostPolicyModel,
    AccessVpcHostPolicyModel,
    TrunkVpcHostPolicyModel,
]

# (label, percentage attribute, pps attribute) per storm-control traffic class.
CLASS_FIELDS = [
    ("broadcast", "storm_control_broadcast_level", "storm_control_broadcast_level_pps"),
    ("multicast", "storm_control_multicast_level", "storm_control_multicast_level_pps"),
    ("unicast", "storm_control_unicast_level", "storm_control_unicast_level_pps"),
]

PCT = 50.0
PPS = 1000


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
@pytest.mark.parametrize("label,pct_attr,pps_attr", CLASS_FIELDS)
def test_storm_control_mutex_00100(model_cls, label, pct_attr, pps_attr) -> None:
    """
    # Summary

    Setting both the percentage and pps level for the same storm-control class is rejected.

    ## Test

    - A policy model is constructed with both `storm_control_<class>_level` and `storm_control_<class>_level_pps` set.
    - A `ValidationError` is raised naming the offending traffic class.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with pytest.raises(ValidationError, match=label):
        model_cls(**{pct_attr: PCT, pps_attr: PPS})


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
@pytest.mark.parametrize("label,pct_attr,pps_attr", CLASS_FIELDS)
def test_storm_control_mutex_00110(model_cls, label, pct_attr, pps_attr) -> None:
    """
    # Summary

    Setting only the percentage, or only the pps, for a class is accepted.

    ## Test

    - The model is constructed with just the percentage level set, then just the pps level set.
    - Neither construction raises.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with does_not_raise():
        model_cls(**{pct_attr: PCT})
    with does_not_raise():
        model_cls(**{pps_attr: PPS})


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
def test_storm_control_mutex_00120(model_cls) -> None:
    """
    # Summary

    A policy with no storm-control levels set is accepted (the validator is a no-op when nothing conflicts).

    ## Test

    - The model is constructed with no storm-control fields.
    - Construction does not raise.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with does_not_raise():
        model_cls()


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
def test_storm_control_mutex_00130(model_cls) -> None:
    """
    # Summary

    A percentage on one class and a pps on a different class do not conflict (the check is per-class).

    ## Test

    - The model is constructed with `storm_control_broadcast_level` and `storm_control_multicast_level_pps` set.
    - Construction does not raise.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with does_not_raise():
        model_cls(storm_control_broadcast_level=PCT, storm_control_multicast_level_pps=PPS)


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
def test_storm_control_mutex_00140(model_cls) -> None:
    """
    # Summary

    When more than one class conflicts, the error names every offending class.

    ## Test

    - The model is constructed with both percentage and pps set for broadcast and for unicast.
    - A `ValidationError` is raised naming both `broadcast` and `unicast`.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with pytest.raises(ValidationError, match=r"broadcast, unicast"):
        model_cls(
            storm_control_broadcast_level=PCT,
            storm_control_broadcast_level_pps=PPS,
            storm_control_unicast_level=PCT,
            storm_control_unicast_level_pps=PPS,
        )


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
@pytest.mark.parametrize("label,pct_attr,pps_attr", CLASS_FIELDS)
def test_storm_control_mutex_00150(model_cls, label, pct_attr, pps_attr) -> None:
    """
    # Summary

    User/proposed config parsed via `from_config()` rejects both-set-for-one-class (the write path fails fast).

    ## Test

    - A policy model is built from an Ansible config dict setting both the percentage and pps level for one class.
    - A `ValidationError` is raised naming the offending traffic class.

    ## Classes and Methods

    - NDBaseModel.from_config()
    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with pytest.raises(ValidationError, match=label):
        model_cls.from_config({pct_attr: PCT, pps_attr: PPS})


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
@pytest.mark.parametrize("label,pct_attr,pps_attr", CLASS_FIELDS)
def test_storm_control_mutex_00160(model_cls, label, pct_attr, pps_attr) -> None:
    """
    # Summary

    An ND response parsed via `from_response()` accepts both values for one class and preserves them (the read path
    stays permissive). ND accepts and echoes both the percentage and pps on GET (issue #351), so an existing device
    in that state must be parseable for `query`/`gathered`/`diff` to report and remediate it.

    ## Test

    - A policy model is built from an ND response dict (aliased keys) setting both the percentage and pps level for one class.
    - Construction does not raise, and both values round-trip onto the model.

    ## Classes and Methods

    - NDBaseModel.from_response()
    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    pct_alias = model_cls.model_fields[pct_attr].alias
    pps_alias = model_cls.model_fields[pps_attr].alias
    with does_not_raise():
        instance = model_cls.from_response({pct_alias: PCT, pps_alias: PPS})
    assert getattr(instance, pct_attr) == PCT
    assert getattr(instance, pps_attr) == PPS


# --- Top-level response-to-diff-to-merge lifecycle (PR #360 review) ---

SWITCH_IP = "192.0.2.10"

# (top-level interface model, policy model, ND-canonical interface name) for every interface family that carries
# the paired storm-control fields.
INTERFACE_MODELS = [
    (EthernetAccessInterfaceModel, EthernetAccessPolicyModel, "Ethernet1/1"),
    (EthernetTrunkHostInterfaceModel, EthernetTrunkHostPolicyModel, "Ethernet1/1"),
    (PortChannelAccessInterfaceModel, PortChannelAccessPolicyModel, "port-channel501"),
    (PortChannelTrunkHostInterfaceModel, PortChannelTrunkHostPolicyModel, "port-channel501"),
    (AccessVpcHostInterfaceModel, AccessVpcHostPolicyModel, "vpc100"),
    (TrunkVpcHostInterfaceModel, TrunkVpcHostPolicyModel, "vpc100"),
]

PCT_ALIAS = "stormControlBroadcastLevel"
PPS_ALIAS = "stormControlBroadcastLevelPps"
PCT_ATTR = "storm_control_broadcast_level"
PPS_ATTR = "storm_control_broadcast_level_pps"


def nd_interface_response(policy_cls, interface_name, policy_fields):
    """Build an ND-shaped interface GET response dict carrying the given aliased policy fields."""
    policy_type = policy_cls.model_fields["policy_type"].default
    policy = {"policyType": getattr(policy_type, "value", policy_type)}
    policy.update(policy_fields)
    return {"switchIp": SWITCH_IP, "interfaceName": interface_name, "configData": {"networkOS": {"policy": policy}}}


def proposed_config(interface_name, policy_fields):
    """Build an Ansible-shaped proposed config dict carrying the given snake_case policy fields."""
    return {"switch_ip": SWITCH_IP, "interface_name": interface_name, "config_data": {"network_os": {"policy": policy_fields}}}


def policy_of(instance):
    """Return the nested policy model of a top-level interface model instance."""
    return instance.config_data.network_os.policy


def test_storm_control_mutex_00170() -> None:
    """
    # Summary

    A physical ethernet trunkHost interface response carrying both the percentage and pps level for one class is
    parseable via the top-level `from_response()` (issue #351 regression, PR #360 review). ND 4.2.1.10 and 4.3.1.75
    accept and echo this exact state, so query/gathered/diff initialization (and therefore every state, including
    `deleted`) must be able to construct the model.

    ## Test

    - `EthernetTrunkHostInterfaceModel.from_response()` is called with an ND-shaped payload carrying both
      `stormControlBroadcastLevel` and `stormControlBroadcastLevelPps`.
    - Construction does not raise, and both values round-trip onto the nested policy model.

    ## Classes and Methods

    - NDBaseModel.from_response()
    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    response = {
        "switchIp": SWITCH_IP,
        "interfaceName": "Ethernet1/1",
        "configData": {
            "networkOS": {
                "policy": {
                    "policyType": "trunkHost",
                    "stormControlBroadcastLevel": 42.5,
                    "stormControlBroadcastLevelPps": 12345,
                }
            }
        },
    }
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel.from_response(response)
    assert policy_of(instance).storm_control_broadcast_level == 42.5
    assert policy_of(instance).storm_control_broadcast_level_pps == 12345


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00200(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    `state: merged` can switch a storm-control class from percentage to pps: the diff reports a change and the merge
    clears the percentage before assigning the pps, so the merged model never holds both (PR #360 review).

    ## Test

    - An existing model is built from an ND response carrying a percentage-only broadcast level.
    - A proposed model is built from config carrying a pps-only broadcast level.
    - `get_diff(exclude_unset=True)` reports a difference.
    - `merge()` does not raise; the merged policy has the percentage cleared and the pps set.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - StormControlMutexMixin.merge()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PCT_ALIAS: PCT}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {PPS_ATTR: PPS}))
    assert existing.get_diff(proposed, exclude_unset=True) is False
    with does_not_raise():
        merged = existing.merge(proposed)
    assert getattr(policy_of(merged), PCT_ATTR) is None
    assert getattr(policy_of(merged), PPS_ATTR) == PPS


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00210(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    `state: merged` can switch a storm-control class from pps to percentage: the diff reports a change and the merge
    clears the pps before assigning the percentage (PR #360 review).

    ## Test

    - An existing model is built from an ND response carrying a pps-only broadcast level.
    - A proposed model is built from config carrying a percentage-only broadcast level.
    - `get_diff(exclude_unset=True)` reports a difference.
    - `merge()` does not raise; the merged policy has the pps cleared and the percentage set.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - StormControlMutexMixin.merge()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PPS_ALIAS: PPS}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {PCT_ATTR: PCT}))
    assert existing.get_diff(proposed, exclude_unset=True) is False
    with does_not_raise():
        merged = existing.merge(proposed)
    assert getattr(policy_of(merged), PPS_ATTR) is None
    assert getattr(policy_of(merged), PCT_ATTR) == PCT


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00220(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    A dual-valued ND echo (issue #351) plus proposed config matching the existing pps is a difference, not `no_diff`:
    explicitly selecting the pps variant must clear the stale percentage even when the pps value already matches
    (PR #360 review). The one-way subset comparison alone would miss this.

    ## Test

    - An existing model is built from an ND response carrying both the percentage and pps broadcast levels.
    - A proposed model is built from config carrying the same pps value that ND already echoes.
    - `get_diff(exclude_unset=True)` reports a difference.
    - `merge()` does not raise; the merged policy has the percentage cleared and the pps preserved.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.merge_would_change()
    - StormControlMutexMixin.merge()
    - StormControlMutexMixin.merge_would_change()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PCT_ALIAS: PCT, PPS_ALIAS: PPS}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {PPS_ATTR: PPS}))
    assert existing.get_diff(proposed, exclude_unset=True) is False
    with does_not_raise():
        merged = existing.merge(proposed)
    assert getattr(policy_of(merged), PCT_ATTR) is None
    assert getattr(policy_of(merged), PPS_ATTR) == PPS


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00230(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    A dual-valued ND echo plus proposed config changing the pps value merges cleanly: the percentage is cleared and
    the pps updated (PR #360 review).

    ## Test

    - An existing model is built from an ND response carrying both the percentage and pps broadcast levels.
    - A proposed model is built from config carrying a different pps value.
    - `get_diff(exclude_unset=True)` reports a difference.
    - `merge()` does not raise; the merged policy has the percentage cleared and the new pps value set.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - StormControlMutexMixin.merge()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PCT_ALIAS: PCT, PPS_ALIAS: PPS}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {PPS_ATTR: 2000}))
    assert existing.get_diff(proposed, exclude_unset=True) is False
    with does_not_raise():
        merged = existing.merge(proposed)
    assert getattr(policy_of(merged), PCT_ATTR) is None
    assert getattr(policy_of(merged), PPS_ATTR) == 2000


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00240(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    An unrelated merged update against a dual-valued ND echo succeeds and leaves the storm-control state untouched:
    the user expressed no storm-control intent, so the merge must not raise on (or silently alter) the echoed pair
    (PR #360 review).

    ## Test

    - An existing model is built from an ND response carrying both the percentage and pps broadcast levels.
    - A proposed model is built from config setting only `admin_state`.
    - `merge()` does not raise; `admin_state` is updated and both storm-control values are preserved.

    ## Classes and Methods

    - StormControlMutexMixin.merge()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PCT_ALIAS: PCT, PPS_ALIAS: PPS}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {"admin_state": True}))
    with does_not_raise():
        merged = existing.merge(proposed)
    assert policy_of(merged).admin_state is True
    assert getattr(policy_of(merged), PCT_ATTR) == PCT
    assert getattr(policy_of(merged), PPS_ATTR) == PPS


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00250(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    Counterpart clearing is scoped per traffic class: selecting a pps for multicast clears nothing on broadcast, and a
    dual-valued broadcast echo survives the merge untouched (PR #360 review).

    ## Test

    - An existing model is built from an ND response carrying both broadcast levels (percentage and pps).
    - A proposed model is built from config carrying a multicast pps level only.
    - `merge()` does not raise; the broadcast pair is preserved and the multicast pps is set.

    ## Classes and Methods

    - StormControlMutexMixin.merge()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PCT_ALIAS: PCT, PPS_ALIAS: PPS}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {"storm_control_multicast_level_pps": PPS}))
    with does_not_raise():
        merged = existing.merge(proposed)
    assert getattr(policy_of(merged), PCT_ATTR) == PCT
    assert getattr(policy_of(merged), PPS_ATTR) == PPS
    assert policy_of(merged).storm_control_multicast_level_pps == PPS
    assert policy_of(merged).storm_control_multicast_level is None


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00260(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    No false positives: proposed config re-stating the variant the device already uses (same value, no counterpart
    set) remains `no_diff`, so idempotent runs stay idempotent (PR #360 review).

    ## Test

    - An existing model is built from an ND response carrying a percentage-only broadcast level.
    - A proposed model is built from config carrying the same percentage value.
    - `get_diff(exclude_unset=True)` reports no difference.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.merge_would_change()
    - StormControlMutexMixin.merge_would_change()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {PCT_ALIAS: PCT}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {PCT_ATTR: PCT}))
    assert existing.get_diff(proposed, exclude_unset=True) is True


@pytest.mark.parametrize("interface_cls,policy_cls,interface_name", INTERFACE_MODELS)
def test_storm_control_mutex_00270(interface_cls, policy_cls, interface_name) -> None:
    """
    # Summary

    `state: replaced`/`overridden` detect storm-control removal (issue #410): proposed config that omits an existing
    storm-control level entirely must classify as a difference on the `exclude_unset=False` path, so the full-payload
    PUT that clears the level (lab-verified on ND 4.2.1 in PR #360) is issued.

    ## Test

    - An existing model is built from an ND response carrying `adminState` plus a percentage-only broadcast level.
    - A proposed model is built from config re-stating `admin_state` only (no storm-control intent), so the forward
      subset comparison alone would classify `no_diff`.
    - `get_diff(exclude_unset=False)` reports a difference.

    ## Classes and Methods

    - NDBaseModel.get_diff()
    - NDBaseModel.to_reverse_diff_dict()
    - utils.has_removals()
    """
    existing = interface_cls.from_response(nd_interface_response(policy_cls, interface_name, {"adminState": True, PCT_ALIAS: PCT}))
    proposed = interface_cls.from_config(proposed_config(interface_name, {"admin_state": True}))
    assert existing.get_diff(proposed, exclude_unset=False) is False
