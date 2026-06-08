#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_vrf_lite
version_added: "1.4.0"
short_description: Manage VRF Lite attachments on Cisco Nexus Dashboard

description:
- Manage VRF Lite attachment configuration in ND/NDFC fabrics.
- Supports C(gathered), C(merged), C(replaced), C(overridden), and C(deleted) states.
- Supports optional save/deploy controls through C(config_actions).

author:
- Cisco Nexus Dashboard Team

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
        type: bool
        default: true
      deploy:
        type: bool
        default: true
      type:
        type: str
        default: switch
        choices: [ switch, global ]

  verify:
    description:
    - Verification controls used by runtime query/deploy helpers.
    type: dict
    suboptions:
      enabled:
        type: bool
        default: true
      retries:
        type: int
        default: 5
      timeout:
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
            type: str
          export_evpn_rt:
            type: str
          vrf_lite:
            description:
            - VRF Lite extension entries for the attachment.
            type: list
            elements: dict
            suboptions:
              interface:
                type: str
                required: true
              dot1q:
                type: int
              ipv4_addr:
                type: str
              neighbor_ipv4:
                type: str
              ipv6_addr:
                type: str
              neighbor_ipv6:
                type: str
              peer_vrf:
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
