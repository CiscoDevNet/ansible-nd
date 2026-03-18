# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "Sivakami S"

DOCUMENTATION = """
---
module: nd_manage_vpc_pair
short_description: Manage vPC pairs in Nexus devices.
version_added: "1.0.0"
description:
- Create, update, delete, override, and gather vPC pairs on Nexus devices.
- Uses NDStateMachine framework with a vPC orchestrator.
- Integrates RestSend for battle-tested HTTP handling with retry logic.
- Handles VPC API quirks via custom orchestrator action handlers.
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
        - C(gathered) is the query/read-only mode for this module.
        type: str
    fabric_name:
        description:
        - Name of the fabric.
        required: true
        type: str
    deploy:
        description:
        - Deploy configuration changes after applying them.
        - Saves fabric configuration and triggers deployment.
        type: bool
        default: false
    dry_run:
        description:
        - Show what changes would be made without executing them.
        - Maps to Ansible check_mode internally.
        type: bool
        default: false
    force:
        description:
        - Force deletion without pre-deletion validation checks.
        - 'WARNING: Bypasses safety checks for networks, VRFs, and vPC interfaces.'
        - Use only when validation API timeouts or you are certain deletion is safe.
        - Only applies to deleted state.
        type: bool
        default: false
    api_timeout:
        description:
        - API request timeout in seconds for primary operations (create, update, delete).
        - Increase for large fabrics or slow networks.
        type: int
        default: 30
    query_timeout:
        description:
        - API request timeout in seconds for query and recommendation operations.
        - Lower timeout for non-critical queries to avoid port exhaustion.
        type: int
        default: 10
    refresh_after_apply:
        description:
        - Query controller again after write operations to populate final C(after) state.
        - Disable for faster execution when eventual consistency is acceptable.
        type: bool
        default: true
    refresh_after_timeout:
        description:
        - Optional timeout in seconds for the post-apply refresh query.
        - When omitted, C(query_timeout) is used.
        type: int
    config:
        description:
        - List of vPC pair configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            peer1_switch_id:
                description:
                - Peer1 switch serial number for the vPC pair.
                required: true
                type: str
            peer2_switch_id:
                description:
                - Peer2 switch serial number for the vPC pair.
                required: true
                type: str
            use_virtual_peer_link:
                description:
                - Enable virtual peer link for the vPC pair.
                type: bool
                default: true
notes:
    - This module uses NDStateMachine framework for state management
    - RestSend provides protocol-based HTTP abstraction with automatic retry logic
    - Results are aggregated using the Results class for consistent output format
    - Check mode is fully supported via both framework and RestSend
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
    deploy: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Dry run to see what would change
- name: Dry run vPC pair creation
  cisco.nd.nd_manage_vpc_pair:
    fabric_name: myFabric
    state: merged
    dry_run: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
"""

RETURN = """
changed:
    description: Whether the module made any changes
    type: bool
    returned: always
    sample: true
before:
    description: vPC pair state before changes
    type: list
    returned: always
    sample: [{"switchId": "FDO123", "peerSwitchId": "FDO456", "useVirtualPeerLink": false}]
after:
    description: vPC pair state after changes
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
        pending_create_vpc_pairs:
            description: VPC pairs ready to be created (switches are paired but VPC not configured)
            type: list
        pending_delete_vpc_pairs:
            description: VPC pairs in transitional delete state
            type: list
    sample:
        vpc_pairs: [{"switchId": "FDO123", "peerSwitchId": "FDO456"}]
        pending_create_vpc_pairs: []
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
    description: Deployment operation results (when deploy=true)
    type: dict
    returned: when deploy parameter is true
    contains:
        deployment_needed:
            description: Whether deployment was needed based on changes
            type: bool
        changed:
            description: Whether deployment made changes
            type: bool
        response:
            description: List of deployment API responses (save and deploy)
            type: list
    sample: {"deployment_needed": true, "changed": true, "response": [...]}
deployment_needed:
    description: Flag indicating if deployment was needed
    type: bool
    returned: when deploy=true
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

import sys

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging

# Service layer imports
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.vpc_pair_resources import (
    VpcPairResourceService,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_exceptions import (
    VpcPairResourceError,
)

# Static imports so Ansible's AnsiballZ packager includes these files in the
# module zip. Keep them optional when framework files are intentionally absent.
try:
    from ansible_collections.cisco.nd.plugins.module_utils import nd_config_collection as _nd_config_collection
    from ansible_collections.cisco.nd.plugins.module_utils import utils as _nd_utils
except Exception:  # pragma: no cover - compatibility for stripped framework trees
    _nd_config_collection = None  # noqa: F841
    _nd_utils = None  # noqa: F841

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.vpc_pair_enums import (
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_common import (
    DEEPDIFF_IMPORT_ERROR,
    HAS_DEEPDIFF,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_deploy import (
    _needs_deployment,
    custom_vpc_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_runner import (
    run_vpc_module,
)


# ===== Module Entry Point =====


def main():
    """
    Module entry point combining framework + RestSend.

    Architecture:
    - Thin module entrypoint delegates to VpcPairResourceService
    - VpcPairResourceService handles NDStateMachine orchestration
    - Custom actions use RestSend (NDModuleV2) for HTTP with retry logic
    """
    argument_spec = dict(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "gathered"],
        ),
        fabric_name=dict(type="str", required=True),
        deploy=dict(type="bool", default=False),
        dry_run=dict(type="bool", default=False),
        force=dict(
            type="bool",
            default=False,
            description="Force deletion without pre-deletion validation (bypasses safety checks)"
        ),
        api_timeout=dict(
            type="int",
            default=30,
            description="API request timeout in seconds for primary operations"
        ),
        query_timeout=dict(
            type="int",
            default=10,
            description="API request timeout in seconds for query/recommendation operations"
        ),
        refresh_after_apply=dict(
            type="bool",
            default=True,
            description="Refresh final after-state by querying controller after write operations",
        ),
        refresh_after_timeout=dict(
            type="int",
            required=False,
            description="Optional timeout in seconds for post-apply after-state refresh query",
        ),
        config=dict(
            type="list",
            elements="dict",
            options=dict(
                peer1_switch_id=dict(type="str", required=True, aliases=["switch_id"]),
                peer2_switch_id=dict(type="str", required=True, aliases=["peer_switch_id"]),
                use_virtual_peer_link=dict(type="bool", default=True),
                vpc_pair_details=dict(type="dict"),
            ),
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    setup_logging(module)

    # Module-level validations
    if sys.version_info < (3, 9):
        module.fail_json(msg="Python version 3.9 or higher is required for this module.")

    if not HAS_DEEPDIFF:
        module.fail_json(
            msg=missing_required_lib("deepdiff"),
            exception=DEEPDIFF_IMPORT_ERROR
        )

    # State-specific parameter validations
    state = module.params.get("state", "merged")
    deploy = module.params.get("deploy")
    dry_run = module.params.get("dry_run")

    if state == "gathered" and deploy:
        module.fail_json(msg="Deploy parameter cannot be used with 'gathered' state")

    if state == "gathered" and dry_run:
        module.fail_json(msg="Dry_run parameter cannot be used with 'gathered' state")

    # Map dry_run to check_mode
    if dry_run:
        module.check_mode = True

    # Validate force parameter usage:
    # - state=deleted
    # - state=overridden with empty config (interpreted as delete-all)
    force = module.params.get("force", False)
    user_config = module.params.get("config") or []
    force_applicable = state == "deleted" or (
        state == "overridden" and len(user_config) == 0
    )
    if force and not force_applicable:
        module.warn(
            "Parameter 'force' only applies to state 'deleted' or to "
            "state 'overridden' when config is empty (delete-all behavior). "
            f"Ignoring force for state '{state}'."
        )

    # Normalize config keys for model
    config = module.params.get("config") or []
    normalized_config = []

    for item in config:
        switch_id = item.get("peer1_switch_id") or item.get("switch_id")
        peer_switch_id = item.get("peer2_switch_id") or item.get("peer_switch_id")
        use_virtual_peer_link = item.get("use_virtual_peer_link", True)
        vpc_pair_details = item.get("vpc_pair_details")
        normalized = {
            "switch_id": switch_id,
            "peer_switch_id": peer_switch_id,
            "use_virtual_peer_link": use_virtual_peer_link,
            "vpc_pair_details": vpc_pair_details,
            # Defensive dual-shape normalization for state-machine/model variants.
            VpcFieldNames.SWITCH_ID: switch_id,
            VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
            VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_virtual_peer_link,
            VpcFieldNames.VPC_PAIR_DETAILS: vpc_pair_details,
        }
        normalized_config.append(normalized)

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
