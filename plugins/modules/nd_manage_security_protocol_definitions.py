#!/usr/bin/python

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security protocol definitions on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_manage_security_protocol_definitions
version_added: "2.0.0"
short_description: Manage security protocol definitions on Cisco Nexus Dashboard
description:
- Manage security protocol definitions through the Nexus Dashboard (ND) Manage Security and Segmentation API.
- ND 4.2.1 and ND 4.3.1 are supported.
- Protocol definitions must be created before security contracts that reference them.
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description:
    - Name of the standalone fabric or parent fabric group that owns the definitions.
    type: str
    required: true
  cluster_name:
    description:
    - Name of the ND cluster that manages the fabric in a multi-cluster deployment.
    - When set, the value is sent as the C(clusterName) query parameter on fabric, resource, and action requests.
    type: str
  config:
    description:
    - List of security protocol definitions.
    - Required for write states. Omit for O(state=gathered) to return all definitions.
    type: list
    elements: dict
    required: false
    suboptions:
      name:
        description:
        - Protocol definition name. Names are case insensitive.
        - The ND OpenAPI specifications allow a name without O(config.tenant_name) to contain at most 63 characters.
        - The maximum qualified-name length is 92 characters on ND 4.2.1 and 102 characters on ND 4.3.1.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the protocol definition.
        - The module sends tenant-scoped names as C(tenant_name~name) and returns gathered names in separate O(config.tenant_name) and O(config.name) fields.
        - Omit this option for non-tenant VXLAN fabrics.
        type: str
      display_name:
        description:
        - Display name shown in ND. The maximum length is 64 characters.
        type: str
      description:
        description:
        - Description for the protocol definition. The maximum length is 128 characters.
        - ND 4.3.1 does not accept carriage-return or line-feed characters.
        type: str
      match_type:
        description:
        - How the entries in O(config.match_items) are combined.
        type: str
        choices: [ any ]
      match_items:
        description:
        - Unique protocol match criteria.
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
            - Protocol accepted by ND, such as C(TCP), C(UDP), C(ICMP), or a numeric IP protocol value.
            - ND validates this string against its release-specific protocol list. The module intentionally
              does not copy that large enum so newer controller values remain usable.
            - ND 4.3.1 adds the bare numeric values C(61), C(63), C(68), C(99), and C(114).
            type: str
          src_port_range:
            description:
            - Numeric source port or inclusive range, such as C(80) or C(1000-2000).
            - Service names are not accepted. Values must be between 0 and 65535.
            type: str
          dst_port_range:
            description:
            - Numeric destination port or inclusive range, such as C(443) or C(8000-8080).
            - Service names are not accepted. Values must be between 0 and 65535.
            type: str
          tcp_flags:
            description:
            - TCP flags to match.
            - ND 4.2.1 accepts one of C(est), C(ack), C(fin), C(rst), or C(syn).
            - ND 4.3.1 also accepts semicolon-separated combinations of C(ack), C(fin), C(rst), and C(syn), such as C(ack;syn).
            - C(est) must be used by itself on both releases.
            type: str
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
            - DSCP value from 0 through 63.
            type: int
  config_actions:
    description:
    - Controls fabric save and deploy actions after a resource change.
    - Omit this option when O(state=gathered). Read-only runs never save or deploy.
    type: dict
    suboptions:
      save:
        description:
        - Save and recalculate the fabric configuration after a resource change.
        type: bool
        default: false
      deploy:
        description:
        - Deploy pending fabric configuration after a resource change.
        - C(true) requires O(config_actions.save=true).
        type: bool
        default: false
      type:
        description:
        - Deployment scope.
        - C(switch) deploys affected out-of-sync switches; C(global) deploys all pending fabric changes.
        type: str
        default: switch
        choices: [ switch, global ]
  state:
    description:
    - Desired state of the security protocol definitions.
    - O(state=merged) creates missing definitions and updates specified fields.
    - O(state=replaced) replaces the listed definitions.
    - O(state=overridden) makes the fabric's definition set match O(config). Use with caution.
    - O(state=deleted) removes the listed definitions.
    - O(state=gathered) returns replayable configuration without changing, saving, or deploying anything.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Group Based Policy must already be enabled and ready on the target fabric. This module does not enable the feature or reload switches.
- Security resources are supported only on iBGP VXLAN fabrics. PVLAN, change-control, and eBGP-underlay VXLAN fabrics are unsupported.
- CSV import and export workflows are outside this module's scope.
- O(config.match_items.protocol_options) is controller-validated to preserve compatibility with newly added protocol values.
- Delete associations and contracts before deleting protocol definitions that they reference.
- For ND 4.2 writes, unqualified protocol definition names are limited to 20 characters to match live controller behavior.
- ND 4.3 retains the 63-character schema limit. Longer legacy ND 4.2 names remain available to gather or delete.
"""

EXAMPLES = r"""
- name: Create an ND 4.2.1-compatible protocol definition without saving or deploying
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
        description: HTTP and HTTPS traffic
        match_type: any
        match_items:
          - match_name: https
            type: IPv4
            protocol_options: TCP
            dst_port_range: "443"
            tcp_flags: syn
    state: merged

- name: Use combined TCP flags on ND 4.3.1 and save and deploy affected switches
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    cluster_name: cluster-1
    config:
      - name: established_web
        match_type: any
        match_items:
          - match_name: acknowledged_web
            type: IPv4
            protocol_options: TCP
            dst_port_range: "80-443"
            tcp_flags: ack;syn
    config_actions:
      save: true
      deploy: true
      type: switch
    state: replaced

- name: Gather protocol definitions as replayable module configuration
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    cluster_name: cluster-1
    state: gathered
  register: protocol_definitions

- name: Authoritatively retain only the listed protocol definitions
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
        match_type: any
        match_items:
          - match_name: https
            type: IPv4
            protocol_options: TCP
            dst_port_range: "443"
    state: overridden

- name: Delete a security protocol definition
  cisco.nd.nd_manage_security_protocol_definitions:
    fabric_name: SITE1
    config:
      - name: web_tcp
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, security protocol definitions.
  returned: always
  type: bool
  sample: true
output_level:
  description: Output verbosity selected by O(output_level).
  returned: always
  type: str
  sample: normal
before:
  description: Definitions before reconciliation. Empty for O(state=gathered).
  returned: always
  type: list
  elements: dict
after:
  description: Definitions after reconciliation. Empty for O(state=gathered).
  returned: always
  type: list
  elements: dict
diff:
  description: Difference between C(before) and C(after).
  returned: for write states
  type: list
  elements: dict
proposed:
  description: Configuration proposed by the task.
  returned: for write states when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
gathered:
  description:
  - Definitions read from ND, pruned to fields accepted by O(config).
  - An empty list is returned when no definitions exist.
  returned: when O(state=gathered)
  type: list
  elements: dict
config_actions_result:
  description: Structured save and deploy plan or result, including requested and effective actions, status, reason, targets, and action steps.
  returned: when save or deploy is requested for a changed or planned resource
  type: dict
api_paths:
  description: API paths included in the result at Ansible verbosity level 2 or higher.
  returned: at verbosity level 2 or higher
  type: list
  elements: str
api_verbs:
  description: HTTP verbs included in the result at Ansible verbosity level 2 or higher.
  returned: at verbosity level 2 or higher
  type: list
  elements: str
logs:
  description: Internal diagnostic log messages.
  returned: when O(output_level=debug)
  type: list
  elements: str
msg:
  description: Human-readable error message.
  returned: on failure
  type: str
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import (
    SecurityProtocolDefinitionModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityProtocolDefinitionOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.security_module import (
    run_security_module,
)


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityProtocolDefinitionModel,
        orchestrator_class=SecurityProtocolDefinitionOrchestrator,
        logger_name="nd.nd_manage_security_protocol_definitions",
    )


if __name__ == "__main__":
    main()
