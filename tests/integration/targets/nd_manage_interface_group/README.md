# Interface Groups integration tests

## Run

Configure `tests/integration/inventory.networking`, then run from the collection
repository:

```shell
ansible-test integration nd_manage_interface_group \
  --inventory tests/integration/inventory.networking
```

## Prerequisites

- A writable ND fabric with two reserved leaf switches.
- Unused Ethernet interfaces, port-channel IDs, Network IDs, and VLAN IDs for
  the test fixtures.
- The Nexus Dashboard connection and Interface Groups test variables in
  `tests/integration/inventory.networking`.

### vPC

Disable vPC tests when a vPC testbed is unavailable:

```ini
nd_test_interface_group_vpc_flow_enabled=false
```

To enable them, provide two reserved leaves, their serial numbers and management
IPs, one unused Ethernet member on each leaf, and an unused vPC ID. The suite
creates and removes the vPC pair and vPC interface by default.

```ini
nd_test_interface_group_vpc_flow_enabled=true
nd_test_switch_id=<primary leaf serial>
nd_test_interface_group_secondary_switch_id=<secondary leaf serial>
nd_test_interface_group_vpc_primary_switch_ip=<primary leaf management IP>
nd_test_interface_group_secondary_switch_ip=<secondary leaf management IP>
nd_test_interface_group_vpc_peer1_member=Ethernet1/8
nd_test_interface_group_vpc_peer2_member=Ethernet1/8
nd_test_interface_group_vpc_id=200
```

### Ethernet custom

Disable Ethernet-custom tests when no custom template is available:

```ini
nd_test_interface_group_ethernet_custom_flow_enabled=false
```

To enable them, provide one unused Ethernet interface and the name of an
existing user-defined Ethernet shared-policy template:

```ini
nd_test_interface_group_ethernet_custom_flow_enabled=true
nd_test_interface_group_ethernet_custom=Ethernet1/20
nd_test_interface_group_custom_template=<template name>
```

If no suitable template exists, open **Manage > Templates** in ND, duplicate
`int_shared_trunk_host`, give the duplicate a unique name, save it, and use that
name for `nd_test_interface_group_custom_template`.

For a template with different inputs, also provide:

```ini
nd_test_interface_group_custom_extra_config_key=<free-form input key>
nd_test_interface_group_custom_template_config=<complete native input dictionary>
```
