"""Compare native Network attachment intent without cosmetic alias differences."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager


def _attachment(interfaces=None, options=None):
    return {
        "networkName": "nacprep_20261028_trunk",
        "switchId": "99TRB2TMZYJ",
        "vlanId": 191,
        "attach": True,
        "instanceValues": {"sviEnabled": True} if options is None else options,
        "extraConfig": "",
        "interfaces": [{"interfaceRange": "Port-channel61", "mode": "trunk", "nativeVlan": False}] if interfaces is None else interfaces,
    }


@pytest.mark.parametrize("name", ["Port-channel61", "port-channel61", "Po61", "po61"])
def test_native_instance_alias_and_known_port_channel_spellings_are_equivalent(name):
    current = _attachment()
    desired = _attachment([{"interfaceRange": name, "mode": "trunk"}], {"svi_enabled": True})
    assert not NetworkAttachmentManager._attachment_changed(current, desired)


@pytest.mark.parametrize("name", ["Ethernet1/46", "ethernet1/46", "Eth1/46", "ETH1/46"])
def test_known_ethernet_spellings_are_equivalent(name):
    current = _attachment([{"interfaceRange": "Ethernet1/46", "mode": "trunk", "nativeVlan": False}])
    desired = _attachment([{"interfaceRange": name, "mode": "trunk"}], {"svi_enabled": True})
    assert not NetworkAttachmentManager._attachment_changed(current, desired)


@pytest.mark.parametrize(
    "options",
    [
        {"svi_enabled": False},
        {"svi_enabled": True, "futureOption": False},
        {"sviEnabled": True, "dpu_secure": False},
        {"sviEnabled": True, "svi_enabled": False},
    ],
)
def test_genuine_unknown_default_or_conflicting_option_changes_remain_visible(options):
    assert NetworkAttachmentManager._attachment_changed(_attachment(), _attachment(options=options))


def test_all_official_option_aliases_normalize_without_adding_model_defaults():
    current = _attachment(options={"sviEnabled": True, "dpuSecure": False, "dpuAffinity": "none", "switchRouteTargetImport": ["1:2"], "isActive": True})
    desired = _attachment(options={"svi_enabled": True, "dpu_secure": False, "dpu_affinity": "none", "switch_route_target_import": ["1:2"], "is_active": True})
    assert not NetworkAttachmentManager._attachment_changed(current, desired)
    assert NetworkAttachmentManager._attachment_changed(_attachment(options={}), _attachment(options={"dpu_secure": False}))


@pytest.mark.parametrize("field,value", [("interfaceRange", "Ethernet1/47"), ("mode", "access"), ("nativeVlan", True), ("interfaceGroupName", "GROUP")])
def test_actual_port_or_attachment_mode_differences_remain_visible(field, value):
    current = _attachment()
    desired = deepcopy(current)
    desired["interfaces"][0][field] = value
    assert NetworkAttachmentManager._attachment_changed(current, desired)


def test_customer_vlan_and_unknown_option_content_remain_visible():
    current = _attachment(options={"sviEnabled": True, "futureOption": {"flag": False}})
    desired = deepcopy(current)
    desired["instanceValues"]["futureOption"]["flag"] = True
    assert NetworkAttachmentManager._attachment_changed(current, desired)
    desired = deepcopy(current)
    desired["interfaces"][0]["mapping"] = {"mappingType": "single", "customerVlan": 101}
    assert NetworkAttachmentManager._attachment_changed(current, desired)


def test_unrecognized_interface_and_option_names_are_not_broadly_case_folded():
    current = _attachment([{"interfaceRange": "CustomInterface61", "mode": "trunk"}], {"sviEnabled": True, "customOption": False})
    desired = deepcopy(current)
    desired["interfaces"][0]["interfaceRange"] = "custominterface61"
    assert NetworkAttachmentManager._attachment_changed(current, desired)
    desired = deepcopy(current)
    desired["instanceValues"] = {"svi_enabled": True, "customoption": False}
    assert NetworkAttachmentManager._attachment_changed(current, desired)


def _c13_active_attachments():
    # Relevant fields copied from the pinned C13 overlay.json API observation.
    targets = [
        ("access", "9FF8AWWMKLN", 192, None, "access"),
        ("access", "99TRB2TMZYJ", 192, "Port-channel62", "access"),
        ("trunk", "9FF8AWWMKLN", 191, None, "trunk"),
        ("trunk", "99TRB2TMZYJ", 191, "Port-channel61", "trunk"),
        ("converted_trunk", "9FF8AWWMKLN", 196, "Ethernet1/43", "trunk"),
        ("converted_trunk", "99TRB2TMZYJ", 196, None, "trunk"),
        ("vpc_trunk", "9FH9LQIB51G", 193, "Port-channel61", "trunk"),
        ("vpc_trunk", "9RB62ZJYAL0", 193, "Port-channel61", "trunk"),
        ("converted_access", "9FF8AWWMKLN", 197, "Ethernet1/44", "access"),
        ("converted_access", "99TRB2TMZYJ", 197, None, "access"),
        ("shared", "9FF8AWWMKLN", 195, None, "trunk"),
        ("shared", "99TRB2TMZYJ", 195, "Port-channel61", "trunk"),
        ("vpc_access", "9FH9LQIB51G", 194, "Port-channel62", "access"),
        ("vpc_access", "9RB62ZJYAL0", 194, "Port-channel62", "access"),
    ]
    rows = []
    for name, switch_id, vlan, port, mode in targets:
        interfaces = [{"interfaceRange": port, "mode": mode, **({"nativeVlan": False} if mode == "trunk" else {})}] if port else []
        row = _attachment(interfaces)
        row.update(networkName="nacprep_20261028_" + name, switchId=switch_id, vlanId=vlan)
        rows.append(row)
    return rows


def test_c13_to_c14_only_real_network_move_changes_one_of_fourteen_attachments():
    current = _c13_active_attachments()
    desired = deepcopy(current)
    for row in desired:
        row["instanceValues"] = {"svi_enabled": True}
        for interface in row["interfaces"]:
            interface["interfaceRange"] = interface["interfaceRange"].lower()
    assert not any(NetworkAttachmentManager._attachment_changed(have, want) for have, want in zip(current, desired))
    desired[3]["interfaces"] = [{"interfaceRange": "Ethernet1/46", "mode": "trunk", "nativeVlan": False}]
    assert [i for i, (have, want) in enumerate(zip(current, desired)) if NetworkAttachmentManager._attachment_changed(have, want)] == [3]


def test_post_c14_old_port_channel_retained_alongside_new_ethernet_is_still_changed():
    # C14's actual response retained Po61 as well as the newly requested E1/46.
    current = _attachment(
        [{"interfaceRange": "Ethernet1/46", "mode": "trunk", "nativeVlan": False}, {"interfaceRange": "Port-channel61", "mode": "trunk", "nativeVlan": False}]
    )
    desired = _attachment([{"interfaceRange": "Eth1/46", "mode": "trunk"}], {"svi_enabled": True})
    before = deepcopy((current, desired))
    assert NetworkAttachmentManager._attachment_changed(current, desired)
    assert (current, desired) == before
