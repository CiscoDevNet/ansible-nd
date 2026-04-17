# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "Sivakami S"

DOCUMENTATION = """
---
module: nd_manage_vpc_pair
short_description: Manage vPC pairs in Nexus devices.
description:
- Create, update, delete, override, and gather vPC pairs on Nexus devices.
- Uses NDStateMachine framework with a vPC orchestrator.
- Integrates RestSend for battle-tested HTTP handling with retry logic.
- Handles VPC API quirks via custom orchestrator action handlers.
author:
- Sivakami Sivaraman (@sivakasi)
options:
    state:
        choices:
        - merged
        - replaced
        - deleted
        - overridden
        - gathered
        default: merged
        description:
        - The state of the vPC pair configuration after module completion.
        - gathered is the query/read-only mode for this module.
        type: str
    fabric_name:
        description:
        - Name of the fabric.
        required: true
        type: str
    config_actions:
        description:
        - Configuration save/deploy controls for write operations.
        type: dict
        suboptions:
            save:
                description:
                - Save configuration after state reconciliation.
                type: bool
                default: true
            deploy:
                description:
                - Deploy configuration after save.
                type: bool
                default: true
            type:
                description:
                - Scope type for save/deploy action payload.
                - Valid values are C(switch) and C(global).
                type: str
                choices: [switch, global]
                default: switch
    force:
        description:
        - Force deletion without pre-deletion validation checks.
        - 'WARNING: Bypasses safety checks for networks, VRFs, and vPC interfaces.'
        - Use only when validation API timeouts or you are certain deletion is safe.
        - Only applies to deleted state.
        type: bool
        default: false
    verify:
        description:
        - Verification controls for post-write refresh behavior.
        type: dict
        suboptions:
            enabled:
                description:
                - Enable post-write verification refresh query.
                type: bool
                default: true
            retries:
                description:
                - Number of verification retry attempts.
                type: int
                default: 5
            timeout:
                description:
                - Per-query timeout in seconds.
                type: int
                default: 10
    config:
        description:
        - List of vPC pair configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            peer1_switch_id:
                description:
                - Peer1 switch serial number or management IP address for the vPC pair.
                required: true
                type: str
                aliases:
                - switch_id
            peer2_switch_id:
                description:
                - Peer2 switch serial number or management IP address for the vPC pair.
                required: true
                type: str
                aliases:
                - peer_switch_id
            use_virtual_peer_link:
                description:
                - Enable virtual peer link for the vPC pair.
                type: bool
                default: false
            vpc_pair_details:
                description:
                - Optional vPC pair template details (default/custom template fields).
                type: dict
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
    - This module uses NDStateMachine framework for state management
    - RestSend provides protocol-based HTTP abstraction with automatic retry logic
    - Results are aggregated using the Results class for consistent output format
    - Check mode is fully supported via both framework and RestSend
    - No separate dry_run parameter is supported; use native Ansible check_mode
    - "Validation error: C(config_actions.save=false) with C(config_actions.deploy=true) is not allowed"
"""

EXAMPLES = """
# Create a new vPC pair
- name: Create vPC pair
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        use_virtual_peer_link: true

# Delete a vPC pair
- name: Delete vPC pair
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: deleted
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Create a new vPC pair using management IPs
- name: Create vPC pair with switch management IPs
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: merged
    config:
      - peer1_switch_id: "10.10.10.11"
        peer2_switch_id: "10.10.10.12"
        use_virtual_peer_link: true

# Gather existing vPC pairs
- name: Gather all vPC pairs
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: gathered

# Create and deploy
- name: Create vPC pair and deploy
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: merged
    config_actions:
      save: true
      deploy: true
      type: switch
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Create and save only (no deploy)
- name: Create vPC pair and save only
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: merged
    config_actions:
      save: true
      deploy: false
      type: global
    verify:
      enabled: true
      retries: 5
      timeout: 10
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Native Ansible check_mode behavior
- name: Check mode vPC pair creation
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
  check_mode: true
"""

RETURN = """
changed:
    description: Whether the module made any changes
    type: bool
    returned: always
    sample: true
before:
    description:
    - vPC pair state before changes.
    - May contain controller read-only properties because it is queried from controller state.
    type: list
    returned: always
    sample: [{"switchId": "FDO123", "peerSwitchId": "FDO456", "useVirtualPeerLink": false}]
after:
    description:
    - vPC pair state after changes.
    - By default this is refreshed from controller after write operations and may include read-only properties.
    - Refresh verification runs when verify.enabled=true (default).
    type: list
    returned: always
    sample: [{"switchId": "FDO123", "peerSwitchId": "FDO456", "useVirtualPeerLink": true}]
gathered:
    description: Current vPC pairs (gathered state only)
    type: dict
    returned: when state is gathered
    contains:
        vpc_pairs:
            description: List of configured VPC pairs
            type: list
        pending_delete_vpc_pairs:
            description: VPC pairs in transitional delete state
            type: list
    sample:
        vpc_pairs: [{"switchId": "FDO123", "peerSwitchId": "FDO456"}]
        pending_delete_vpc_pairs: []
response:
    description: List of all API responses
    type: list
    returned: always
    sample: [{"RETURN_CODE": 200, "METHOD": "PUT", "MESSAGE": "Success"}]
result:
    description: List of all operation results
    type: list
    returned: always
    sample: [{"success": true, "changed": true}]
diff:
    description: List of all changes made, organized by operation
    type: list
    returned: always
    contains:
        operation:
            description: Type of operation (POST/PUT/DELETE)
            type: str
        vpc_pair_key:
            description: Identifier for the VPC pair (switchId-peerSwitchId)
            type: str
        path:
            description: API endpoint path used
            type: str
        payload:
            description: Request payload sent to API
            type: dict
    sample: [{"operation": "PUT", "vpc_pair_key": "FDO123-FDO456", "path": "/api/v1/...", "payload": {}}]
created:
    description: List of created object identifiers
    type: list
    returned: always
    sample: [["FDO123", "FDO456"]]
deleted:
    description: List of deleted object identifiers
    type: list
    returned: always
    sample: [["FDO123", "FDO456"]]
updated:
    description: List of updated object identifiers and changed properties
    type: list
    returned: always
    sample: [{"identifier": ["FDO123", "FDO456"], "changed_properties": ["useVirtualPeerLink"]}]
metadata:
    description: Operation metadata with sequence and identifiers
    type: dict
    returned: when operations are performed
    contains:
        vpc_pair_key:
            description: VPC pair identifier
            type: str
        operation:
            description: Operation type (create/update/delete)
            type: str
        sequence_number:
            description: Operation sequence in batch
            type: int
    sample: {"vpc_pair_key": "FDO123-FDO456", "operation": "create", "sequence_number": 1}
warnings:
    description: List of warning messages from validation or operations
    type: list
    returned: when warnings occur
    sample: ["VPC pair has 2 vPC interfaces - deletion may require manual cleanup"]
failed:
    description: Whether any operation failed
    type: bool
    returned: when operations fail
    sample: false
ip_to_sn_mapping:
    description: Mapping of switch IP addresses to serial numbers
    type: dict
    returned: when available from fabric inventory
    sample: {"10.1.1.1": "FDO123", "10.1.1.2": "FDO456"}
deployment:
    description: Save/deploy action results (when config_actions is enabled)
    type: dict
    returned: when config_actions.save=true or config_actions.deploy=true
    contains:
        deployment_needed:
            description: Whether deployment was needed based on changes
            type: bool
        changed:
            description: Whether deployment made changes
            type: bool
        response:
            description: List of action API responses (save and/or deploy)
            type: list
    sample: {"deployment_needed": true, "changed": true, "response": [...]}
deployment_needed:
    description: Flag indicating if deployment was needed
    type: bool
    returned: when config_actions.save=true or config_actions.deploy=true
    sample: true
pending_create_pairs_not_in_delete:
    description: VPC pairs in pending create state not included in delete wants (deleted state only)
    type: list
    returned: when state is deleted and pending create pairs exist
    sample: [{"switchId": "FDO789", "peerSwitchId": "FDO012"}]
pending_delete_pairs_not_in_delete:
    description: VPC pairs in pending delete state not included in delete wants (deleted state only)
    type: list
    returned: when state is deleted and pending delete pairs exist
    sample: []
"""

import json
from typing import Any, Dict

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec

# Service layer imports
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.resources import (
    VpcPairResourceService,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)

# Static imports so Ansible's AnsiballZ packager includes these files in the
# module zip. Keep them optional when framework files are intentionally absent.
try:
    import ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection as _nd_config_collection
    import ansible_collections.cisco.nd.plugins.module_utils.utils as _nd_utils
except Exception:  # pragma: no cover - compatibility for stripped framework trees
    _nd_config_collection = None
    _nd_utils = None

# Keep explicit references so static analysis doesn't treat optional imports as unused.
_PACKAGER_IMPORTS = (_nd_config_collection, _nd_utils)

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import (
    VpcPairPlaybookConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.deploy import (
    _needs_deployment,
    custom_vpc_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runner import (
    run_vpc_module,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
    get_config_actions,
    get_verify_settings,
)

# ===== Module Entry Point =====


def _get_raw_module_args() -> Dict[str, Any]:
    """
    Best-effort extraction of raw user-provided module args before defaults.
    """
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


def main() -> None:
    """
    Module entry point combining framework + RestSend.

    Builds argument spec from Pydantic models, validates state-level rules,
    normalizes config keys, creates VpcPairResourceService with handler
    callbacks, and delegates execution.

    Architecture:
    - Thin module entrypoint delegates to VpcPairResourceService
    - VpcPairResourceService handles NDStateMachine orchestration
    - Custom actions use RestSend (NDModuleV2) for HTTP with retry logic

    Raises:
        VpcPairResourceError: Converted to module.fail_json with structured details
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(VpcPairPlaybookConfigModel.get_argument_spec())

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    setup_logging(module)

    try:
        module_config = VpcPairPlaybookConfigModel.model_validate(module.params, by_alias=True, by_name=True)
    except ValidationError as e:
        # e.errors() may contain raw Exception objects inside ctx (for example
        # ValueError), which are not safely serializable by module.fail_json.
        validation_errors = []
        detail_msg = str(e)
        try:
            validation_errors = json.loads(e.json())
            if validation_errors and isinstance(validation_errors[0], dict):
                detail_msg = validation_errors[0].get("msg", detail_msg)
        except Exception:
            validation_errors = [{"msg": str(e)}]

        module.fail_json(
            msg="Invalid nd_manage_vpc_pair playbook configuration: {0}".format(detail_msg),
            validation_errors=validation_errors,
        )

    # State-specific parameter validations
    state = module_config.state
    config_actions = get_config_actions(module)
    verify_settings = get_verify_settings(module)
    raw_module_args = _get_raw_module_args()
    raw_config_actions = raw_module_args.get("config_actions")
    explicit_config_actions = isinstance(raw_config_actions, dict)

    if state == "gathered":
        explicit_write_requested = False

        if explicit_config_actions:
            normalized_actions = module.params.get("config_actions") or {}
            if ("save" in raw_config_actions and bool(normalized_actions.get("save", False))) or (
                "deploy" in raw_config_actions and bool(normalized_actions.get("deploy", False))
            ):
                explicit_write_requested = True

        if explicit_write_requested:
            module.fail_json(
                msg=(
                    "Write action parameters cannot be used with 'gathered' state. " "config_actions.save/config_actions.deploy are not allowed for gathered."
                )
            )

        # Gathered is strictly read-only by default.
        config_actions = {
            "save": False,
            "deploy": False,
            "type": config_actions.get("type", "switch"),
        }

    # Runtime normalization for downstream service/orchestrator code.
    module.params["config_actions"] = config_actions
    module.params["verify"] = verify_settings

    if config_actions.get("deploy", False) and not config_actions.get("save", False):
        module.fail_json(msg="Invalid config_actions: config_actions.deploy=true requires config_actions.save=true")

    # Validate force parameter usage:
    # - state=deleted only
    force = module_config.force
    force_applicable = state == "deleted"
    if force and not force_applicable:
        module.warn("Parameter 'force' only applies to state 'deleted'. " f"Ignoring force for state '{state}'.")

    # Normalize config keys for runtime/state-machine model handling.
    normalized_config = [item.to_runtime_config() for item in (module_config.config or [])]

    module.params["config"] = normalized_config

    # Gather must remain strictly read-only. Preserve user-provided config as a
    # query filter, but clear the framework desired config to avoid unintended
    # reconciliation before run_vpc_module() handles gathered output.
    if state == "gathered":
        module.params["_gather_filter_config"] = list(normalized_config)
        module.params["config"] = []
    else:
        module.params["_gather_filter_config"] = []

    # VpcPairResourceService bridges NDStateMachine lifecycle hooks to RestSend actions.
    fabric_name = module.params.get("fabric_name")
    try:
        service = VpcPairResourceService(
            module=module,
            run_state_handler=run_vpc_module,
            deploy_handler=custom_vpc_deploy,
            needs_deployment_handler=_needs_deployment,
        )
        result = service.execute(fabric_name=fabric_name)

        module.exit_json(**result)

    except VpcPairResourceError as e:
        module.fail_json(msg=e.msg, **e.details)
    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
