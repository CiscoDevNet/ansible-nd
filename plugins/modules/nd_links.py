#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: nd_links
version_added: "1.0.0"
short_description: Manages links on Cisco Nexus Dashboard.
description:
- Manages network links between switches on Cisco Nexus Dashboard.
- Supports both single-cluster and multi-cluster (One Manage) scopes.
- Supports bulk operations for efficient creation and deletion.
- Auto-detects scope from config, or use O(link_scope) to override.
author:
- Shreyas Srish (@shrsr)
options:
  fabric_name:
    description:
    - Name of the fabric. Required for querying links.
    type: str
    required: true
  link_scope:
    description:
    - Which API scope to use for link operations.
    - V(auto) auto-detects based on the presence of cluster fields in config.
    - V(manage) uses the single-cluster scope (6-field identity).
    - V(one_manage) uses the multi-cluster scope (8-field identity including cluster names).
    type: str
    choices: [ auto, manage, one_manage ]
    default: auto
  cluster_name:
    description:
    - Target cluster name for multi-cluster operations.
    - Only used when O(link_scope=one_manage) or auto-detected.
    type: str
  ticket_id:
    description:
    - Change Control Ticket Id for multi-cluster operations.
    - Only used when O(link_scope=one_manage) or auto-detected.
    type: str
  config:
    description:
    - A list of link configurations to manage.
    type: list
    elements: dict
    required: true
  state:
    description:
    - The desired state of the link resources.
    type: str
    choices: [ merged, replaced, overridden, deleted ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create multi-cluster links (bulk)
  cisco.nd.nd_links:
    fabric_name: fab1
    config:
      - src_cluster_name: cluster-191
        dst_cluster_name: cluster-187
        src_fabric_name: fab2
        dst_fabric_name: fab1
        src_switch_name: v1-bgw2
        dst_switch_name: v1-bgw1
        src_interface_name: Ethernet1/12
        dst_interface_name: Ethernet1/12
        link_type: multi_cluster_planned_link
        config_data:
          policy_type: multisiteUnderlay
          template_inputs:
            src_ebgp_asn: "200"
            dst_ebgp_asn: "100"
            src_ip_address_mask: "30.30.30.10/31"
            dst_ip_address: "30.30.30.11"
            link_mtu: 9216
    state: merged

- name: Create single-cluster fabric links
  cisco.nd.nd_links:
    fabric_name: fab1
    config:
      - src_fabric_name: fab1
        dst_fabric_name: fab1
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/1
        dst_interface_name: Ethernet1/1
        config_data:
          policy_type: ipv6LinkLocal
          template_inputs:
            interface_admin_state: true
            mtu: 9216
    state: merged

- name: Identify switches by management IP (avoids hostname collisions)
  cisco.nd.nd_links:
    fabric_name: fab1
    config:
      - src_fabric_name: fab1
        dst_fabric_name: fab1
        src_switch_ip: 192.0.2.10
        dst_switch_ip: 192.0.2.11
        src_interface_name: Ethernet1/1
        dst_interface_name: Ethernet1/1
        config_data:
          policy_type: numbered
          template_inputs:
            src_ip: 10.0.0.1
            dst_ip: 10.0.0.2
            mtu: 9216
            interface_admin_state: true
    state: merged

- name: Create links with explicit scope and change control
  cisco.nd.nd_links:
    fabric_name: fab1
    link_scope: one_manage
    cluster_name: cluster-191
    ticket_id: CHG-12345
    config:
      - src_fabric_name: fab2
        dst_fabric_name: fab1
        src_switch_name: v1-bgw2
        dst_switch_name: v1-bgw1
        src_interface_name: Ethernet1/12
        dst_interface_name: Ethernet1/12
        config_data:
          policy_type: multisiteUnderlay
          template_inputs:
            src_ebgp_asn: "200"
            dst_ebgp_asn: "100"
    state: merged

- name: Delete links (bulk)
  cisco.nd.nd_links:
    fabric_name: fab1
    config:
      - src_cluster_name: cluster-191
        dst_cluster_name: cluster-187
        src_fabric_name: fab2
        dst_fabric_name: fab1
        src_switch_name: v1-bgw2
        dst_switch_name: v1-bgw1
        src_interface_name: Ethernet1/12
        dst_interface_name: Ethernet1/12
    state: deleted
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule  # noqa: F401  (retained for sanity-test compatibility)
from ansible_collections.cisco.nd.plugins.module_utils.client.build_module import build_module
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.links import NDLinkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.manage_link import ManageLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.one_manage_link import OneManageLinkStrategy


def determine_strategy(module):
    """Pick the link strategy from O(link_scope) or autodetect from config cluster fields."""
    link_scope = module.params.get("link_scope", "auto")
    fabric_name = module.params.get("fabric_name")
    cluster_name = module.params.get("cluster_name")
    ticket_id = module.params.get("ticket_id")

    if link_scope == "manage":
        return ManageLinkStrategy(fabric_name=fabric_name)

    if link_scope == "one_manage":
        return OneManageLinkStrategy(
            fabric_name=fabric_name,
            cluster_name=cluster_name,
            ticket_id=ticket_id,
        )

    if link_scope == "auto":
        config = module.params.get("config", [])
        has_cluster_fields = any(
            item.get("src_cluster_name") or item.get("dst_cluster_name")
            for item in config
        )
        if has_cluster_fields:
            return OneManageLinkStrategy(
                fabric_name=fabric_name,
                cluster_name=cluster_name,
                ticket_id=ticket_id,
            )
        return ManageLinkStrategy(fabric_name=fabric_name)

    module.fail_json(msg="Invalid link_scope: {0}".format(link_scope))


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(NDLinkModel.get_argument_spec())
    argument_spec.update(
        fabric_name=dict(type="str", required=True),
        link_scope=dict(
            type="str",
            default="auto",
            choices=["auto", "manage", "one_manage"],
        ),
        cluster_name=dict(type="str"),
        ticket_id=dict(type="str"),
    )

    module = build_module(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        strategy = determine_strategy(module)
        NDLinkModel.identifiers = strategy.identifier_fields

        nd_module = NDModule(module)
        orchestrator = NDLinkOrchestrator(sender=nd_module, strategy=strategy)

        state_machine = NDStateMachine(module=module, model_orchestrator=orchestrator)
        state_machine.manage_state()

        result = state_machine.output.format()
        module.exit_json(**result)

    except NDStateMachineError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg="Unexpected error: {0}".format(str(e)))


if __name__ == "__main__":
    main()
