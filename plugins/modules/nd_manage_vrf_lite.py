#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_vrf_lite
version_added: "2.0.0"
short_description: Manage VRF Lite attachments on Cisco Nexus Dashboard

description:
- Manage VRF Lite attachment configuration in ND fabrics.
- Supports C(gathered), C(merged), C(replaced), C(overridden), and C(deleted) states.
- Supports optional save/deploy controls through C(config_actions).

author:
- Sivakami Sivaraman (@sivakasi)

options:
  state:
    description:
    - Desired state of the VRF Lite configuration.
    type: str
    default: merged
    choices: [ merged, replaced, deleted, overridden, gathered ]

  fabric_name:
    description:
    - Target fabric name.
    type: str
    required: true

  config_actions:
    description:
    - Optional save/deploy actions after state reconciliation.
    type: dict
    suboptions:
      save:
        description:
        - Trigger a config save after state reconciliation.
        type: bool
        default: true
      deploy:
        description:
        - Trigger a VRF deploy after save. Requires C(save=true).
        type: bool
        default: true
      type:
        description:
        - Scope of the config save operation.
        type: str
        default: switch
        choices: [ switch, global ]

  verify:
    description:
    - Verification controls used by runtime query/deploy helpers.
    type: dict
    suboptions:
      enabled:
        description:
        - Enable post-deploy verification polling.
        type: bool
        default: true
      retries:
        description:
        - Number of polling retries during verification.
        type: int
        default: 5
      timeout:
        description:
        - Total per-request timeout budget used by verification queries.
        type: int
        default: 10

  force:
    description:
    - Reserved for delete workflows.
    - Currently accepted for interface parity with other ND manage modules.
    type: bool
    default: false

  config:
    description:
    - List of VRF Lite entries.
    type: list
    elements: dict
    suboptions:
      vrf_name:
        description:
        - VRF name.
        type: str
        required: true
      vlan_id:
        description:
        - VRF VLAN id.
        type: int
      deploy:
        description:
        - Per-VRF deploy intent used by deploy planning.
        type: bool
      attach:
        description:
        - Per-switch attachment list.
        type: list
        elements: dict
        suboptions:
          ip_address:
            description:
            - Switch management IP or serial number.
            type: str
            required: true
          deploy:
            description:
            - Per-attachment deploy intent used by deploy planning.
            type: bool
          import_evpn_rt:
            description:
            - EVPN route-target to import, in ASN:NN format.
            type: str
          export_evpn_rt:
            description:
            - EVPN route-target to export, in ASN:NN format.
            type: str
          vrf_lite:
            description:
            - VRF Lite extension entries for the attachment.
            type: list
            elements: dict
            suboptions:
              interface:
                description:
                - Layer-3 interface used for the VRF Lite extension (e.g. C(Ethernet1/20)).
                type: str
                required: true
              dot1q:
                description:
                - 802.1Q VLAN tag for the sub-interface.
                type: int
              ipv4_addr:
                description:
                - IPv4 address with prefix length for the extension interface (e.g. C(10.0.0.1/30)).
                type: str
              neighbor_ipv4:
                description:
                - Peer IPv4 address for the VRF Lite BGP or static-route neighbour.
                type: str
              ipv6_addr:
                description:
                - IPv6 address with prefix length for the extension interface.
                type: str
              neighbor_ipv6:
                description:
                - Peer IPv6 address for the VRF Lite BGP or static-route neighbour.
                type: str
              peer_vrf:
                description:
                - Name of the peer VRF for the VRF Lite extension.
                type: str

extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Gather VRF Lite state
  cisco.nd.nd_manage_vrf_lite:
    fabric_name: my_fabric
    state: gathered

- name: Merge VRF Lite attachment
  cisco.nd.nd_manage_vrf_lite:
    fabric_name: my_fabric
    state: merged
    config:
      - vrf_name: TENANT_A
        vlan_id: 500
        attach:
          - ip_address: 10.10.10.11
            import_evpn_rt: ""
            export_evpn_rt: ""
            vrf_lite:
              - interface: Ethernet1/20
                dot1q: 500
                ipv4_addr: 10.33.0.2/24
                neighbor_ipv4: 10.33.0.1
                peer_vrf: TENANT_A

- name: Delete all attachments for a VRF
  cisco.nd.nd_manage_vrf_lite:
    fabric_name: my_fabric
    state: deleted
    config:
      - vrf_name: TENANT_A
"""

RETURN = r"""
changed:
  description: Whether any change was made
  type: bool
  returned: always
before:
  description: State before operation
  type: list
  returned: always
after:
  description: State after operation
  type: list
  returned: always
current:
  description: Alias for after
  type: list
  returned: always
gathered:
  description: Gathered data when C(state=gathered)
  type: list
  returned: when state is gathered
warnings:
  description: Collected runtime warnings from validation/deploy helpers
  type: list
  elements: str
  returned: when warnings are present
deployment:
  description: Save/deploy action output when config_actions are enabled
  type: dict
  returned: when config_actions is used
"""

import json

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteModel,
    VrfLitePlaybookConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import (
    ManageVrfLiteOrchestrator,
)


def main() -> None:
    """Entry point for nd_manage_vrf_lite.

    Follows the 'declare, don't implement' pattern:
    - Validate input
    - Delegate state reconciliation to NDStateMachine + orchestrator
    - Delegate deploy/gather to orchestrator methods
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(VrfLiteModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    try:
        module_config = VrfLitePlaybookConfigModel.model_validate(module.params, by_alias=True, by_name=True)
    except ValidationError as error:
        validation_errors = []
        detail_msg = str(error)
        try:
            validation_errors = json.loads(error.json())
            if validation_errors and isinstance(validation_errors[0], dict):
                detail_msg = validation_errors[0].get("msg", detail_msg)
        except Exception:
            validation_errors = [{"msg": str(error)}]

        module.fail_json(
            msg="Invalid nd_manage_vrf_lite playbook configuration: {0}".format(detail_msg),
            validation_errors=validation_errors,
        )

    state = module_config.state

    ManageVrfLiteOrchestrator.prepare_module_params(module, module_config)

    try:
        if state == "gathered":
            nd_state_machine = NDStateMachine(module=module, model_orchestrator=ManageVrfLiteOrchestrator)
            result = nd_state_machine.model_orchestrator.gather()
            module.exit_json(**result)

        module.params["state"] = "overridden" if state == "replaced" else state
        nd_state_machine = NDStateMachine(module=module, model_orchestrator=ManageVrfLiteOrchestrator)
        nd_state_machine.manage_state()
        module.params["state"] = state

        module.params["_changed_vrfs"] = sorted({item.vrf_name for item in nd_state_machine.sent})

        result = nd_state_machine.output.format()
        result.setdefault("current", result.get("after", []))
        result = nd_state_machine.model_orchestrator.format_public_output(result)

        deploy_result = nd_state_machine.model_orchestrator.deploy_pending(result)
        if deploy_result:
            result["deployment"] = deploy_result
            result["deployment_needed"] = deploy_result.get("deployment_needed", False)
            if deploy_result.get("changed"):
                result["changed"] = True

        result = nd_state_machine.model_orchestrator.refresh_verified_state(result)
        result = nd_state_machine.model_orchestrator.inject_runtime_metadata(result)
        module.exit_json(**result)

    except VrfLiteResourceError as error:
        module.params["state"] = state
        module.fail_json(msg=error.msg, **error.details)
    except Exception as error:
        module.params["state"] = state
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
