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
    - Optional save/deploy actions applied after state reconciliation.
    type: dict
    suboptions:
      save:
        description:
        - Trigger a fabric config save after state reconciliation.
        - Controls only whether the config-save API is called.
        type: bool
        default: true
      deploy:
        description:
        - Trigger a VRF deploy after the config save. Requires C(save=true).
        type: bool
        default: true
      type:
        description:
        - Scope of the VRF deploy operation.
        - C(switch) deploys only the switches affected by the changed VRFs.
        - C(global) performs a fabric-wide deploy of the changed VRFs.
        - A global deploy cannot exclude an individual switch. If any changed
          attachment for a VRF is deploy-enabled, the whole VRF is deployed;
          use C(switch) to honor per-attachment C(deploy=false) exclusions.
        type: str
        default: switch
        choices: [ switch, global ]

  verify:
    description:
    - Verification controls used by runtime query/deploy helpers.
    - When O(verify.enabled=true) the module performs a single post-deploy state
      refresh of the affected VRF Lite attachments. Retry-based polling until the
      controller reports a converged state is not yet implemented; O(verify.retries)
      is accepted for forward compatibility but does not currently re-poll for
      convergence.
    type: dict
    suboptions:
      enabled:
        description:
        - Perform a single post-deploy state refresh of the affected VRF Lite attachments.
        type: bool
        default: true
      retries:
        description:
        - Reserved for future post-deploy convergence polling.
        - Currently accepted but does not yet retry until controller state converges.
        type: int
        default: 5
      timeout:
        description:
        - Total per-request timeout budget used by verification queries.
        type: int
        default: 10

  config:
    description:
    - List of VRF Lite entries.
    - Required and must not be null for C(merged), C(replaced), and C(overridden).
    - Use C(config=[]) only to request an intentional empty desired set. With
      C(replaced) or C(overridden), it removes all managed VRF Lite attachments
      in the fabric. To remove every attachment for only one VRF with
      C(replaced), list that VRF with C(attach=[]).
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
            - Per-switch exclusion applies when O(config_actions.type=switch).
              A global deployment targets the whole changed VRF when at least
              one of its changed attachments is deploy-enabled.
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

- name: Merge VRF Lite attachment and stage only (save without deploy)
  cisco.nd.nd_manage_vrf_lite:
    fabric_name: my_fabric
    state: merged
    # Save the staged intent on the controller but do not push it to the
    # switches yet. A later run (or another tool) can deploy it.
    config_actions:
      save: true
      deploy: false
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

- name: Replace VRF Lite attachments for the listed VRFs and deploy affected switches
  cisco.nd.nd_manage_vrf_lite:
    fabric_name: my_fabric
    state: replaced
    # 'replaced' rewrites the attachment set for the VRFs you list; VRFs that
    # are not listed are left untouched. type=switch deploys only the switches
    # affected by the changed VRFs.
    config_actions:
      save: true
      deploy: true
      type: switch
    config:
      - vrf_name: TENANT_A
        vlan_id: 500
        attach:
          - ip_address: 10.10.10.11
            vrf_lite:
              - interface: Ethernet1/20
                dot1q: 500
                ipv4_addr: 10.33.0.2/24
                neighbor_ipv4: 10.33.0.1
                peer_vrf: TENANT_A

- name: Override fabric VRF Lite to match config exactly and deploy fabric-wide
  cisco.nd.nd_manage_vrf_lite:
    fabric_name: my_fabric
    state: overridden
    # 'overridden' makes the fabric match this config exactly; any VRF Lite
    # attachment not listed below is removed. type=global performs a
    # fabric-wide deploy of the changed VRFs.
    config_actions:
      save: true
      deploy: true
      type: global
    config:
      - vrf_name: TENANT_A
        vlan_id: 500
        attach:
          - ip_address: 10.10.10.11
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
  description: Whether the module changed, or in check mode would change, the VRF Lite configuration.
  type: bool
  returned: always
output_level:
  description: The output verbosity level in effect for the run, echoing O(output_level).
  type: str
  returned: always
before:
  description: VRF Lite configuration present on ND before the operation.
  type: list
  elements: dict
  returned: always
after:
  description:
  - VRF Lite configuration returned after the operation.
  - For write states in check mode, this is the projected state and is not written to ND.
  - For gathered state, this is the same read-only state exposed through C(gathered).
  type: list
  elements: dict
  returned: always
current:
  description: Alias for C(after).
  type: list
  elements: dict
  returned: always
diff:
  description:
  - Configuration-difference collection exposed for output compatibility.
  - The current VRF Lite workflow returns an empty list.
  type: list
  elements: dict
  returned: always
proposed:
  description: VRF Lite configuration proposed before reconciliation with existing state.
  type: list
  elements: dict
  returned: when O(output_level) is V(info) or V(debug) for a write-state operation
logs:
  description:
  - Internal diagnostic-message collection exposed for debug-output compatibility.
  - The current VRF Lite workflow returns an empty list.
  type: list
  elements: str
  returned: when O(output_level) is V(debug) for a write-state operation
gathered:
  description: VRF Lite configuration returned by a read-only gathered operation.
  type: list
  elements: dict
  returned: when O(state) is V(gathered)
warnings:
  description: Runtime warnings collected by validation and deployment helpers.
  type: list
  elements: str
  returned: when warnings are present
deployment:
  description: Detailed save and deploy action output.
  type: dict
  returned: when O(config_actions.save) is V(true) for a successful write-state operation
  contains:
    msg:
      description: Human-readable summary of the deployment decision or completed actions.
      type: str
      returned: always
    deployment_needed:
      description: Whether save or deploy actions are needed.
      type: bool
      returned: always
    changed:
      description: Whether the deployment phase changed, or in check mode would change, controller state.
      type: bool
      returned: always
    config_actions:
      description: Effective save and deploy controls used by the operation.
      type: dict
      returned: always
      contains:
        save:
          description: Whether the fabric configuration-save action is enabled.
          type: bool
          returned: always
        deploy:
          description: Whether deployment of affected VRFs is enabled after configuration save.
          type: bool
          returned: always
        type:
          description: Deployment scope, either C(switch) or C(global).
          type: str
          returned: always
    target_vrfs:
      description:
      - Changed VRFs eligible for VRF deployment.
      - This can be empty when only the fabric-wide configuration-save action is planned.
      type: list
      elements: str
      returned: when configuration save or deployment actions are needed
    planned_actions:
      description: REST actions planned or executed by the deployment phase.
      type: list
      elements: str
      returned: when configuration save or deployment actions are needed
    response:
      description: Per-action controller responses collected by the deployment phase.
      type: list
      elements: dict
      returned: always
deployment_needed:
  description: Whether the reconciled VRF Lite changes require configuration save or deployment actions.
  type: bool
  returned: when O(config_actions.save) is V(true) for a successful write-state operation
ip_to_sn_mapping:
  description: Mapping of fabric switch management IP addresses to controller serial numbers.
  type: dict
  returned: when the fabric switch query returns a non-empty mapping
response:
  description:
  - Controller-response collection reserved for gathered-output compatibility.
  - The current gathered workflow returns an empty list.
  type: list
  elements: dict
  returned: when O(state) is V(gathered)
result:
  description:
  - Normalized-result collection reserved for gathered-output compatibility.
  - The current gathered workflow returns an empty list.
  type: list
  elements: dict
  returned: when O(state) is V(gathered)
"""

import json
import logging

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
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
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.deploy import (
    _changed_entries_from_preview,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import (
    ManageVrfLiteOrchestrator,
)


def _validate_config_presence(state: str, config: object) -> None:
    """Reject omitted/null write config before runtime normalization."""
    if state in {"merged", "replaced", "overridden"} and config is None:
        raise VrfLiteResourceError(
            msg="config must be provided and cannot be null for state '{0}'. "
            "Use config: [] only when intentionally managing an explicit empty set.".format(state)
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

    setup_logging(module)
    log = logging.getLogger("nd.nd_manage_vrf_lite")

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
    log.info("nd_manage_vrf_lite invoked: state=%s, fabric=%s, check_mode=%s", state, module_config.fabric_name, module.check_mode)

    try:
        # Validate the original playbook value before prepare_module_params()
        # normalizes omitted/null config to an empty runtime list. This keeps an
        # accidental missing write configuration distinct from an intentional
        # ``config: []`` request.
        _validate_config_presence(state, module_config.config)
        ManageVrfLiteOrchestrator.prepare_module_params(module, module_config)

        if state == "gathered":
            log.debug("Dispatching read-only gathered workflow for fabric %s", module_config.fabric_name)
            nd_state_machine = NDStateMachine(module=module, model_orchestrator=ManageVrfLiteOrchestrator)
            result = nd_state_machine.model_orchestrator.gather()
            module.exit_json(**result)

        module.params["state"] = "overridden" if state == "replaced" else state
        nd_state_machine = NDStateMachine(module=module, model_orchestrator=ManageVrfLiteOrchestrator)
        # Preflight the proposed attachments before reconciliation. In check mode the
        # state machine skips all write methods (and their inline guardrails), so this
        # runs the same read-only VRF-existence/switch-support validation to avoid a
        # false-green plan that a real run would reject.
        nd_state_machine.model_orchestrator.preflight_validate_check_mode(list(nd_state_machine.proposed))
        nd_state_machine.manage_state()
        module.params["state"] = state

        change_entries = list(nd_state_machine.sent)
        if module.check_mode and not change_entries:
            # sent is intentionally empty in check mode; recover the change set from
            # the before/after preview so the plan reports the VRFs a real run would
            # deploy while save and deploy stay suppressed.
            change_entries = _changed_entries_from_preview(nd_state_machine.before, nd_state_machine.existing)
        module.params["_changed_vrfs"] = sorted({item.vrf_name for item in change_entries})
        # Operation journal: every (vrf, switch) pair attached OR detached this run.
        # Deletes are included (track_deletes_in_sent=True), so the deploy scope can
        # cover switches whose attachment was removed by replaced/overridden/deleted
        # and are therefore absent from the retained desired config.
        after_identifiers = set(nd_state_machine.existing.keys())
        module.params["_deploy_targets"] = [
            {
                "vrf_name": item.vrf_name,
                "switch_ip": getattr(item, "switch_ip", None),
                "operation": "write" if item.get_identifier_value() in after_identifiers else "delete",
            }
            for item in change_entries
            if getattr(item, "vrf_name", None) and getattr(item, "switch_ip", None)
        ]
        log.info("state=%s: reconciliation complete, changed_vrfs=%s", state, module.params["_changed_vrfs"])

        result = nd_state_machine.output.format()
        result.setdefault("current", result.get("after", []))
        result = nd_state_machine.model_orchestrator.format_public_output(result)

        deploy_result = nd_state_machine.model_orchestrator.deploy_pending(result)
        if deploy_result:
            log.info(
                "state=%s: config actions executed, deployment_needed=%s, changed=%s",
                state,
                deploy_result.get("deployment_needed", False),
                deploy_result.get("changed", False),
            )
            result["deployment"] = deploy_result
            result["deployment_needed"] = deploy_result.get("deployment_needed", False)
            if deploy_result.get("changed"):
                result["changed"] = True

        result = nd_state_machine.model_orchestrator.refresh_verified_state(result)
        result = nd_state_machine.model_orchestrator.inject_runtime_metadata(result)
        module.exit_json(**result)

    except VrfLiteResourceError as error:
        module.params["state"] = state
        log.error("nd_manage_vrf_lite failed (state=%s): %s", state, error.msg)
        module.fail_json(msg=error.msg, **error.details)
    except Exception as error:
        module.params["state"] = state
        log.exception("nd_manage_vrf_lite unexpected error (state=%s)", state)
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
