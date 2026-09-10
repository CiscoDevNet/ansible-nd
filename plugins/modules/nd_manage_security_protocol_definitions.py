#!/usr/bin/python

# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security protocol definitions on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_security_protocol_definitions
version_added: "2.0.0"
short_description: Manage security protocol definitions on Cisco Nexus Dashboard
description:
- Manage Nexus Dashboard security protocol definitions in a fabric.
- Protocol definitions are referenced by security contract rules.
- This module intentionally does not implement CSV import/export or O(state=gathered) in this first release.
author:
- Cisco
options:
  fabric_name:
    description:
    - Name of the standalone fabric or parent fabric group.
    type: str
    required: true
  cluster_name:
    description:
    - Optional Nexus Dashboard cluster name for multi-cluster API calls.
    type: str
  config:
    description:
    - List of security protocol definitions.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description:
        - Protocol definition name.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the protocol definition.
        - Omit this option for non-tenant VXLAN fabrics.
        - Set this only when the tenant is associated with the target fabric.
        type: str
      display_name:
        description:
        - Display name shown in Nexus Dashboard.
        type: str
      description:
        description:
        - Description for the protocol definition.
        type: str
      match_type:
        description:
        - Match type for the protocol definition.
        type: str
        choices: [ any ]
      match_items:
        description:
        - Protocol match criteria.
        type: list
        elements: dict
        suboptions:
          match_name:
            description:
            - Match item name.
            type: str
            required: true
          type:
            description:
            - IP protocol family selector.
            type: str
            choices: [ Default, IP, IPv4, IPv6 ]
          protocol_options:
            description:
            - Protocol option accepted by Nexus Dashboard, such as C(TCP), C(UDP), C(ICMP), or a numeric protocol value.
            type: str
          src_port_range:
            description:
            - Numeric source port or inclusive range, such as C(80) or C(1000-2000). Service names are not accepted.
            type: str
          dst_port_range:
            description:
            - Numeric destination port or inclusive range, such as C(443) or C(8000-8080). Service names are not accepted.
            type: str
          tcp_flags:
            description:
            - TCP flag match.
            type: str
            choices: [ est, ack, fin, rst, syn ]
          only_fragments:
            description:
            - Match only IP fragments.
            type: bool
          stateful:
            description:
            - Enable stateful inspection for the match item.
            type: bool
          dscp:
            description:
            - DSCP value. Must be between 0 and 63.
            type: int
  config_actions:
    description:
    - Controls save and deploy behavior after inventory is updated.
    type: dict
    suboptions:
      save:
        description:
        - Save/Recalculate the configuration of the fabric after inventory is updated.
        type: bool
        default: true
      deploy:
        description:
        - Deploy the pending configuration after inventory is updated.
        - When set to C(true), C(save) must also be C(true).
        type: bool
        default: true
      type:
        description:
        - Scope of the deploy operation.
        - C(switch) deploys the affected scope.
        - C(global) deploys all pending changes for the entire fabric.
        type: str
        default: switch
        choices: [ switch, global ]
  state:
    description:
    - Desired state of the security protocol definitions.
    - O(state=merged) creates missing definitions and updates specified fields.
    - O(state=replaced) replaces the listed definitions.
    - O(state=overridden) makes the fabric's protocol definition set match O(config). Use with caution.
    - O(state=deleted) removes the listed definitions.
    - O(state=gathered) is intentionally deferred to a future release.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module uses the Nexus Dashboard Manage Security and Segmentation APIs.
"""

EXAMPLES = r"""
- name: Create a security protocol definition
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
        description: HTTP and HTTPS traffic
        match_type: any
        match_items:
          - match_name: http
            type: IPv4
            protocol_options: TCP
            dst_port_range: "80"
          - match_name: https
            type: IPv4
            protocol_options: TCP
            dst_port_range: "443"
    config_actions:
      save: true
      deploy: true
      type: switch
    state: merged

- name: Replace a security protocol definition
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
        match_type: any
        match_items:
          - match_name: web
            type: IPv4
            protocol_options: TCP
            dst_port_range: "80-443"
    state: replaced

- name: Override security protocol definitions
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
        match_type: any
    state: overridden

- name: Delete a security protocol definition
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
    state: deleted
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import SecurityProtocolDefinitionModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import SecurityProtocolDefinitionOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.security_module import run_security_module


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityProtocolDefinitionModel,
        orchestrator_class=SecurityProtocolDefinitionOrchestrator,
        logger_name="nd.nd_manage_security_protocol_definitions",
    )


if __name__ == "__main__":
    main()
