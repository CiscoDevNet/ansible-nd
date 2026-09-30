#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_svi
version_added: "2.0.0"
short_description: Manage SVI (svi, iosXeSvi, iosXeSviShutNoShut) interfaces on Cisco Nexus Dashboard
description:
- Manage SVI (switched virtual) interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, and deleting SVI interface configurations on switches within a fabric.
- Supports NX-OS (C(svi)) and IOS-XE (C(iosXeSvi), C(iosXeSviShutNoShut)) SVIs; select the platform with
  O(config[].config_data.network_os.network_os_type).
- Each config item targets a single SVI identified by O(config[].interface_name) (e.g. C(vlan333)).
- Configure multiple SVIs in one task by listing multiple config items.
author:
- Allen Robel (@allenrobel)
options:
  fabric_name:
    description:
    - The name of the fabric containing the target switches.
    type: str
    required: true
  config:
    description:
    - The list of SVI interfaces to configure.
    - Each item specifies the target switch, the interface name, and the policy configuration.
    - Multiple SVIs and multiple switches can be configured in a single task by listing additional items.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage the SVI interface.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_name:
        description:
        - The name of the SVI interface, in the form C(vlan<id>) (e.g. C(vlan333)).
        - A bare VLAN ID (e.g. C(333)) or a mixed-case prefix (e.g. C(Vlan333), C(VLAN333)) is also accepted and normalized to the C(vlan<id>) form.
        - Each SVI is L3 and must have its own item with its own L3 settings (IP, VRF, HSRP, ...).
        type: str
        required: true
      config_data:
        description:
        - The configuration data for this SVI, following the ND API structure.
        type: dict
        suboptions:
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
              network_os_type:
                description:
                - The network OS (platform) type of the target switch. This is a discriminator that determines which
                  policy templates are applicable.
                - Use V(nx-os) for Nexus switches and V(ios-xe) for Catalyst IOS-XE switches.
                type: str
                default: nx-os
                choices: [ nx-os, ios-xe ]
              policy:
                description:
                - The policy configuration for the SVI.
                - The policy fields present depend on O(config[].config_data.network_os.policy.policy_type).
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - The SVI policy template to apply. This is a discriminator that determines which of the remaining
                      C(policy) suboptions are applicable.
                    - Optional. When omitted it is derived from O(config[].config_data.network_os.network_os_type),
                      V(svi) for C(nx-os) and V(iosXeSvi) for C(ios-xe).
                    - V(iosXeSviShutNoShut) is the IOS-XE admin-state-only template; it accepts only
                      O(config[].config_data.network_os.policy.admin_state).
                    type: str
                    choices: [ svi, iosXeSvi, iosXeSviShutNoShut ]
                  admin_state:
                    description:
                    - The administrative state of the interface.
                    - It defaults to C(true) when unset during creation.
                    - Applies to all policy_type values.
                    type: bool
                  description:
                    description:
                    - The description of the interface.
                    - Maximum 254 characters for C(svi), 1-200 characters for C(iosXeSvi).
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    type: str
                  mtu:
                    description:
                    - The MTU setting for the interface.
                    - Valid range is 68-9216.
                    - Applies when policy_type is C(svi).
                    type: int
                  ip:
                    description:
                    - The IPv4 address of the SVI.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    - For C(iosXeSvi), must be a bare IPv4 address without a prefix length.
                    type: str
                  prefix:
                    description:
                    - The IPv4 netmask length used with O(config[].config_data.network_os.policy.ip).
                    - Valid range is 1-31.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    type: int
                  ipv6:
                    description:
                    - The IPv6 address of the SVI.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    - For C(iosXeSvi), must be a bare IPv6 address without a prefix length.
                    type: str
                  prefixv6:
                    description:
                    - The IPv6 netmask length used with O(config[].config_data.network_os.policy.ipv6).
                    - Valid range is 1-127.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    type: int
                  ip_redirects:
                    description:
                    - Disable both IPv4/IPv6 redirects on the interface.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    type: bool
                  vrf_interface:
                    description:
                    - The VRF the SVI is bound to.
                    - Use V(default) for the default VRF.
                    - Applies when policy_type is C(svi) or C(iosXeSvi).
                    type: str
                  routing_tag:
                    description:
                    - Routing tag associated with the interface IP address.
                    - Applies when policy_type is C(svi).
                    type: str
                  pim_sparse:
                    description:
                    - Enable PIM sparse-mode on the interface.
                    - Applies when policy_type is C(svi).
                    type: bool
                  pim_dr_priority:
                    description:
                    - Priority for PIM DR election on the interface.
                    - Valid range is 1-4294967295.
                    - The controller applies a default of C(1) when unset.
                    - Applies when policy_type is C(svi).
                    type: int
                  hsrp:
                    description:
                    - Enable HSRP on the interface.
                    - When V(true), the other C(hsrp_*) and C(preempt)/C(mac) fields take effect.
                    - No HSRP sub-options are strictly required; the controller applies defaults for any
                      left unset (e.g. C(hsrp_group) and C(hsrp_version) default to C(1)).
                    - Applies when policy_type is C(svi).
                    type: bool
                  hsrp_vip:
                    description:
                    - HSRP IPv4 virtual IP address; must match on active/standby devices.
                    - Applies when policy_type is C(svi).
                    type: str
                  hsrp_vipv6:
                    description:
                    - HSRP IPv6 virtual IP address; must match on active/standby devices.
                    - Applies when policy_type is C(svi).
                    type: str
                  hsrp_group:
                    description:
                    - HSRP group number.
                    - Valid range is 0-4095.
                    - The controller applies a default of C(1) when unset.
                    - Applies when policy_type is C(svi).
                    type: int
                  hsrp_groupv6:
                    description:
                    - HSRP IPv6 group number.
                    - If unset, the IPv4 group number is reused for IPv6.
                    - Valid range is 0-4095.
                    - Applies when policy_type is C(svi).
                    type: int
                  hsrp_version:
                    description:
                    - HSRP protocol version.
                    - The controller applies a default of C(1) when unset.
                    - Applies when policy_type is C(svi).
                    type: int
                    choices: [1, 2]
                  hsrp_priority:
                    description:
                    - HSRP priority value used for active/standby election.
                    - Valid range is 0-255.
                    - Applies when policy_type is C(svi).
                    type: int
                  preempt:
                    description:
                    - Enable HSRP preemption (overthrow lower-priority active routers).
                    - Applies when policy_type is C(svi).
                    type: bool
                  mac:
                    description:
                    - HSRP virtual MAC address override.
                    - Applies when policy_type is C(svi).
                    type: str
                  dhcp_server_address1:
                    description:
                    - Primary DHCP relay server IP address.
                    - Applies when policy_type is C(svi).
                    type: str
                  dhcp_server_address2:
                    description:
                    - Secondary DHCP relay server IP address.
                    - Applies when policy_type is C(svi).
                    type: str
                  dhcp_server_address3:
                    description:
                    - Tertiary DHCP relay server IP address.
                    - Applies when policy_type is C(svi).
                    type: str
                  vrf_dhcp1:
                    description:
                    - VRF used to reach DHCP server 1.
                    - Use V(default) for the default VRF; leave blank to use the interface VRF.
                    - Applies when policy_type is C(svi).
                    type: str
                  vrf_dhcp2:
                    description:
                    - VRF used to reach DHCP server 2.
                    - Use V(default) for the default VRF; leave blank to use the interface VRF.
                    - Applies when policy_type is C(svi).
                    type: str
                  vrf_dhcp3:
                    description:
                    - VRF used to reach DHCP server 3.
                    - Use V(default) for the default VRF; leave blank to use the interface VRF.
                    - Applies when policy_type is C(svi).
                    type: str
                  advertise_subnet_in_underlay:
                    description:
                    - Advertise the SVI subnet into the underlay routing protocol.
                    - Applies when policy_type is C(svi).
                    type: bool
                  netflow:
                    description:
                    - Whether netflow is enabled on the interface.
                    - Applies when policy_type is C(svi).
                    type: bool
                  netflow_monitor:
                    description:
                    - Layer 3 netflow monitor name.
                    - Required when O(config[].config_data.network_os.policy.netflow=true).
                    - Applies when policy_type is C(svi).
                    type: str
                  netflow_sampler:
                    description:
                    - Netflow sampler name (applicable to N7K only).
                    - Applies when policy_type is C(svi).
                    type: str
                  vlan_name:
                    description:
                    - The name of the VLAN.
                    - Maximum 128 characters.
                    - Applies when policy_type is C(iosXeSvi).
                    type: str
                  dhcp_servers:
                    description:
                    - DHCP relay servers for the SVI, one entry per server.
                    - Replaces the C(dhcp_server_address1-3) and C(vrf_dhcp1-3) options of the NX-OS template.
                    - Applies when policy_type is C(iosXeSvi).
                    type: list
                    elements: dict
                    suboptions:
                      server_ip_address:
                        description:
                        - The DHCP relay server IPv4 address, as a bare address without a prefix length.
                        type: str
                        required: true
                      server_vrf:
                        description:
                        - The VRF used to reach the server.
                        - Use V(default) or V(global) for the global routing table and V(Mgmt-Vrf) for the management VRF.
                        - Must be 1 to 32 characters.
                        type: str
                        required: true
  config_actions:
    description:
    - Controls deploy behavior after interface mutations are complete.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy interface changes after mutations are complete.
        - When V(true), all queued interface changes are deployed in a single bulk API call at the end of module
          execution via the C(interfaceActions/deploy) API. Only the interfaces modified by this task are deployed.
        - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
        - When V(true) and the module fails after the controller has already accepted a subset of the requested changes, that
          accepted subset is still deployed and is named in the failure message, so a failed task does not leave accepted
          changes staged but undeployed.
        - Setting O(config_actions.deploy=false) is useful when batching changes across multiple interface tasks before a single deploy.
        - Deployment is opt-in. Set O(config_actions.deploy=true) explicitly to push changes to switches.
        type: bool
        default: false
  state:
    description:
    - The desired state of the network resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new resources and update existing ones as defined in your configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the resources specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The resources on ND will be modified to exactly match the configuration.
      Any SVI managed by this module that exists on ND but is not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the specified SVIs via the C(interfaceActions/remove) API followed by a deploy.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module supports both NX-OS and IOS-XE managed SVI interfaces (interface_type C(svi), mode C(managed)), selected via
  O(config[].config_data.network_os.network_os_type).
- This module manages the C(svi) (NX-OS) and C(iosXeSvi) / C(iosXeSviShutNoShut) (IOS-XE) policy templates. SVIs carrying
  any other policy type (e.g. the fabric-provisioned C(vpcBackupSvi) / C(underlaySvi)) are never read or modified by this module.
- Other NX-OS SVI policy types (e.g. policyType C(vpcBackupSvi) for fabric/underlay SVIs with OSPF, ISIS, BFD, and
  replication-mode options) are not yet exposed and will be added as separate variants in a follow-up release.
"""

EXAMPLES = r"""
- name: Create three SVI interfaces, each with its own L3 settings
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
              description: Tenant SVI 333
      - switch_ip: 192.168.1.1
        interface_name: vlan334
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.100.1
              prefix: 24
              description: Tenant SVI 334
      - switch_ip: 192.168.1.1
        interface_name: vlan335
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.101.1
              prefix: 24
              description: Tenant SVI 335
    config_actions:
      deploy: true
    state: merged
  register: result

- name: Create IOS-XE SVIs on a Catalyst leaf (a full iosXeSvi and an admin-state-only iosXeSviShutNoShut)
  cisco.nd.nd_interface_svi:
    fabric_name: CAMPUS1
    config:
      - switch_ip: 192.168.12.181
        interface_name: vlan980
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              admin_state: true
              description: Catalyst campus SVI 980
              vlan_name: campus-980
              ip: 10.99.80.1
              prefix: 24
              ipv6: 2001:db8:80::1
              prefixv6: 64
              dhcp_servers:
                - server_ip_address: 10.10.10.10
                  server_vrf: default
      - switch_ip: 192.168.12.181
        interface_name: vlan981
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeSviShutNoShut
              admin_state: false
    config_actions:
      deploy: true
    state: merged

- name: Create SVIs across multiple switches
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
      - switch_ip: 192.168.1.2
        interface_name: vlan333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.2
              prefix: 24
    config_actions:
      deploy: true
    state: merged

- name: Replace the configuration of specific SVIs
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.10
              prefix: 24
              description: Reprovisioned tenant SVI 333
    config_actions:
      deploy: true
    state: replaced

# state=overridden is fabric-wide: every SVI in the fabric that is managed by this module and is NOT
# listed below is deleted. An empty config list deletes ALL such SVIs in the fabric. Use with caution.
- name: Enforce SVIs fabric-wide, deleting all others managed by this module
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
              description: SVI to keep; all other SVIs deleted
    config_actions:
      deploy: true
    state: overridden

- name: Delete SVI interfaces
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan333
      - switch_ip: 192.168.1.1
        interface_name: vlan334
    config_actions:
      deploy: true
    state: deleted

- name: Stage SVI changes without deploying (for batching)
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
    config_actions:
      deploy: false
    state: merged

- name: Create an SVI with HSRP enabled
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan500
        config_data:
          network_os:
            policy:
              admin_state: true
              vrf_interface: tenant_a
              ip: 10.99.5.1
              prefix: 24
              hsrp: true
              hsrp_group: 5
              hsrp_version: 2
              hsrp_vip: 10.99.5.254
              hsrp_priority: 110
              preempt: true
              mac: "0000.0c07.ac05"
    config_actions:
      deploy: true
    state: merged

- name: Create an SVI with HSRP configured via extra_config (raw CLI)
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan10
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 192.0.2.2
              prefix: 24
              extra_config: |
                hsrp 1
                  preempt
                  priority 110
                  authentication md5 key-chain hsrp-keys
                  track 1 decrement 20
    config_actions:
      deploy: true
    state: merged

- name: Create an SVI with DHCP relay servers
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vlan600
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.6.1
              prefix: 24
              vrf_interface: tenant_b
              dhcp_server_address1: 10.10.10.10
              vrf_dhcp1: shared_services
              dhcp_server_address2: 10.10.10.11
              vrf_dhcp2: shared_services
    config_actions:
      deploy: true
    state: merged
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, the fabric configuration.
  returned: always
  type: bool
  sample: true
output_level:
  description: The output verbosity level in effect for the run, echoing the O(output_level) parameter.
  returned: always
  type: str
  sample: normal
before:
  description:
  - The existing configuration of the targeted interfaces before the module ran, structured the same as the O(config) parameter.
  - An empty list when no matching interface configuration existed.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: vlan333
    config_data:
      network_os:
        policy:
          admin_state: true
          ip: 10.99.99.1
          prefix: 24
after:
  description:
  - The configuration of the targeted interfaces after the module ran, structured the same as the O(config) parameter.
  - In check mode, the configuration that would result had the module run outside of check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: vlan333
    config_data:
      network_os:
        policy:
          admin_state: true
          ip: 10.99.99.1
          prefix: 25
diff:
  description: The per-interface difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: vlan333
    config_data:
      network_os:
        policy:
          prefix: 25
proposed:
  description: The configuration the module proposed to apply, before reconciliation with the controller.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: vlan333
    config_data:
      network_os:
        policy:
          prefix: 25
logs:
  description: Internal diagnostic log messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample:
  - "Querying existing SVI interface configuration"
msg:
  description: A human-readable error message, present only when the module fails.
  returned: on failure
  type: str
  sample: "Configuration error: ..."
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_interface_svi` Ansible module. Initializes the `NDStateMachine` with
    `SviInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(SviInterfaceModel.get_argument_spec())
    argument_spec.update(config_actions_spec(include=("deploy",)))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_svi")
    module_log.debug(
        "config items=%d switches=%d",
        len(module.params["config"]),
        len({item.get("switch_ip") for item in module.params["config"]}),
    )

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=SviInterfaceOrchestrator,
        )
        # Narrow type from NDBaseOrchestrator to NDBaseInterfaceOrchestrator so that
        # interface-specific attributes (deploy, remove_pending, deploy_pending) are
        # visible to Pylance and validated at runtime.
        if not isinstance(nd_state_machine.model_orchestrator, NDBaseInterfaceOrchestrator):
            raise AssertionError(f"Expected NDBaseInterfaceOrchestrator, got {type(nd_state_machine.model_orchestrator)}")
        deploy = nd_state_machine.model_orchestrator.apply_config_actions(module.params)

        module_log.debug(
            "manage_state begin state=%s check_mode=%s deploy=%s",
            module.params.get("state"),
            module.check_mode,
            deploy,
        )
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")

        # Execute all queued bulk operations
        if not module.check_mode:
            nd_state_machine.model_orchestrator.remove_pending()
            nd_state_machine.model_orchestrator.deploy_pending()

        module.exit_json(**nd_state_machine.output.format())

    except Exception as e:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, nd_state_machine, e)


if __name__ == "__main__":
    main()
