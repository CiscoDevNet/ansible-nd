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
from typing import Any

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLitePlaybookConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    append_runtime_warning,
    get_config_actions,
    get_runtime_warnings,
    get_verify_settings,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.deploy import (
    custom_vrf_lite_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    custom_vrf_lite_query_all,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import (
    ManageVrfLiteOrchestrator,
)


def _get_raw_module_args() -> dict[str, Any]:
    """Best-effort extraction of raw user-provided args before defaults."""
    try:
        from ansible.module_utils import basic as ansible_basic

        raw_payload = getattr(ansible_basic, "_ANSIBLE_ARGS", None)
        if raw_payload is None:
            return {}

        if isinstance(raw_payload, (bytes, bytearray)):
            decoded = raw_payload.decode("utf-8")
        elif isinstance(raw_payload, str):
            decoded = raw_payload
        else:
            return {}

        parsed = json.loads(decoded)
        module_args = parsed.get("ANSIBLE_MODULE_ARGS")
        return module_args if isinstance(module_args, dict) else {}
    except Exception:
        return {}


class _VrfLiteQueryContext:
    """Minimal query context exposing .module."""

    def __init__(self, module: Any) -> None:
        self.module = module


def _inject_runtime_metadata(module: Any, payload: dict[str, Any]) -> dict[str, Any]:
    warnings = get_runtime_warnings(module.params)
    if warnings:
        payload["warnings"] = warnings

    if module.params.get("_ip_to_sn_mapping"):
        payload["ip_to_sn_mapping"] = module.params.get("_ip_to_sn_mapping")

    return payload


def _build_gathered_output(module: Any, gathered: list) -> dict[str, Any]:
    output = {
        "output_level": module.params.get("output_level", "normal"),
        "changed": False,
        "before": gathered,
        "after": gathered,
        "current": gathered,
        "diff": [],
        "response": [],
        "result": [],
        "gathered": gathered,
    }
    return _inject_runtime_metadata(module, output)


def _refresh_verified_state(module: Any, result: dict[str, Any]) -> dict[str, Any]:
    verify_settings = get_verify_settings(module.params)
    if not verify_settings.get("enabled", True):
        return result
    if module.check_mode or not result.get("changed"):
        return result

    refreshed = custom_vrf_lite_query_all(_VrfLiteQueryContext(module))
    result["after"] = refreshed
    result["current"] = refreshed
    return result


def main() -> None:
    argument_spec = nd_argument_spec()
    argument_spec.update(VrfLitePlaybookConfigModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

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
    config_actions = get_config_actions(module.params)
    verify_settings = get_verify_settings(module.params)

    raw_module_args = _get_raw_module_args()
    raw_config_actions = raw_module_args.get("config_actions")
    explicit_config_actions = isinstance(raw_config_actions, dict)

    if state == "gathered":
        explicit_write_requested = False
        if explicit_config_actions:
            normalized_actions = module.params.get("config_actions") or {}
            save_requested = "save" in raw_config_actions and normalized_actions.get("save") is True
            deploy_requested = "deploy" in raw_config_actions and normalized_actions.get("deploy") is True
            if save_requested or deploy_requested:
                explicit_write_requested = True

        if explicit_write_requested:
            module.fail_json(
                msg=("config_actions.save/config_actions.deploy are not allowed with 'gathered' state. " "Gathered workflows are strictly read-only.")
            )

        config_actions = {
            "save": False,
            "deploy": False,
            "type": config_actions.get("type", "switch"),
        }

    if config_actions.get("deploy") and not config_actions.get("save"):
        module.fail_json(msg="Invalid config_actions: config_actions.deploy=true requires config_actions.save=true")

    if module_config.force and state != "deleted":
        append_runtime_warning(
            module.params,
            "Parameter 'force' only applies to state 'deleted'. Ignoring force for state '{0}'.".format(state),
        )

    normalized_config = [item.to_runtime_config() for item in (module_config.config or [])]
    module.params["config"] = normalized_config
    module.params["config_actions"] = config_actions
    module.params["verify"] = verify_settings

    if state == "gathered":
        module.params["_gather_filter_config"] = list(normalized_config)
        module.params["config"] = []
    else:
        module.params["_gather_filter_config"] = []

    if state == "deleted" and not module.params.get("config"):
        module.fail_json(msg="Config parameter is required for state 'deleted'. Specify one or more vrf_name entries in config.")

    module.params["_changed_vrfs"] = []
    module.params["_not_in_sync_vrfs"] = []
    module.params["_ip_to_sn_mapping"] = {}
    module.params["_sn_to_ip_mapping"] = {}
    module.params["_have"] = []
    module.params["_raw_vrf_attachment_map"] = {}
    module.params["_fabric_switch_inventory"] = {}
    module.params["_warnings"] = list(module.params.get("_warnings")) if isinstance(module.params.get("_warnings"), list) else []

    fabric_name = module.params.get("fabric_name")

    try:
        if state == "gathered":
            result = _build_gathered_output(module, custom_vrf_lite_query_all(_VrfLiteQueryContext(module)))
            module.exit_json(**result)

        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageVrfLiteOrchestrator,
        )
        nd_state_machine.manage_state()
        result = nd_state_machine.output.format()
        result.setdefault("current", result.get("after", []))

        if config_actions.get("save", False) or config_actions.get("deploy", False):
            deploy_result = custom_vrf_lite_deploy(module, fabric_name=fabric_name, result=result)
            result["deployment"] = deploy_result
            result["deployment_needed"] = deploy_result.get("deployment_needed", False)
            if deploy_result.get("changed"):
                result["changed"] = True

        result = _refresh_verified_state(module, result)
        result = _inject_runtime_metadata(module, result)
        module.exit_json(**result)

    except VrfLiteResourceError as error:
        module.fail_json(msg=error.msg, **error.details)
    except Exception as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
