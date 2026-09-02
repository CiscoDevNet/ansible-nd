# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_tor
version_added: "2.0.0"
short_description: Manage access or ToR switch associations on Cisco Nexus Dashboard
description:
- Manage access or ToR (Top of Rack) switch associations with aggregation or leaf switches on Cisco Nexus Dashboard (ND).
- It supports associating, disassociating, and querying ToR switch pairings within a fabric.
- Four association topologies are supported - single (1:1), aggregation VPC, back-to-back VPC, and bulk mixed.
author:
- Matt Tarkington (@mtarking)
options:
  fabric_name:
    description:
    - The name of the fabric containing the switches.
    type: str
    required: true
  config:
    description:
    - The list of access or ToR switch associations to configure.
    - Required when O(state=merged) or O(state=deleted).
    - Ignored when O(state=gathered); all associations in the fabric are returned.
    type: list
    elements: dict
    suboptions:
      access_or_tor_switch:
        description:
        - The serial number or management IP address of the access or ToR switch.
        - When a management IP address is provided it is resolved to the switch serial number.
        - Required when O(state=merged) or O(state=deleted).
        type: str
      aggregation_or_leaf_switch:
        description:
        - The serial number or management IP address of the aggregation or leaf switch.
        - When a management IP address is provided it is resolved to the switch serial number.
        type: str
        required: true
      access_or_tor_peer_switch:
        description:
        - The serial number or management IP address of the access or ToR VPC peer switch.
        - When a management IP address is provided it is resolved to the switch serial number.
        - Required for back-to-back VPC topologies.
        type: str
      aggregation_or_leaf_peer_switch:
        description:
        - The serial number or management IP address of the aggregation or leaf VPC peer switch.
        - When a management IP address is provided it is resolved to the switch serial number.
        - Required for aggregation VPC and back-to-back VPC topologies.
        type: str
      access_or_tor_port_channel_id:
        description:
        - The port channel number on the access or ToR switch.
        - Value must be between 1 and 4096.
        - Required when O(state=merged).
        type: int
      aggregation_or_leaf_port_channel_id:
        description:
        - The port channel number on the aggregation or leaf switch.
        - Value must be between 1 and 4096.
        - Required when O(state=merged).
        type: int
      access_or_tor_peer_port_channel_id:
        description:
        - The port channel number on the access or ToR VPC peer switch.
        - Value must be between 1 and 4096.
        type: int
      access_or_tor_vpc_id:
        description:
        - The VPC ID of the VPC pair of access or ToR switches.
        - Value must be between 1 and 4096.
        type: int
      aggregation_or_leaf_peer_port_channel_id:
        description:
        - The port channel number on the aggregation or leaf VPC peer switch.
        - Value must be between 1 and 4096.
        type: int
      aggregation_or_leaf_vpc_id:
        description:
        - The VPC ID of the VPC pair of aggregation or leaf switches.
        - Value must be between 1 and 4096.
        type: int
  state:
    description:
    - The desired state of the access or ToR switch associations on the Cisco Nexus Dashboard.
    - Use O(state=merged) to associate access or ToR switches with aggregation or leaf switches.
      Existing associations not specified in the configuration will be left unchanged.
    - Use O(state=overridden) to make the fabric's access or ToR switch associations match O(config) exactly.
      Associations in O(config) are created or updated and any existing association in the fabric that is
      not in O(config) is disassociated. An empty or omitted O(config) removes every association in the fabric.
    - Use O(state=deleted) to disassociate the access or ToR switches specified in the configuration.
    - Use O(state=gathered) to retrieve current access or ToR switch associations from the fabric without making changes.
      O(config) is not required and is ignored; every association in the fabric is returned in a single query.
    type: str
    default: merged
    choices: [ merged, overridden, deleted, gathered ]
  config_actions:
    description:
    - Controls saving and deploying the fabric configuration after ToR associations are
      staged. Associate and disassociate only stage pending intent; a save and deploy are
      required to realize (or remove) the configuration on the switches.
    - Applied for O(state=merged), O(state=overridden) and O(state=deleted), only when a real change is made.
    - Not used when O(state=gathered).
    type: dict
    suboptions:
      save:
        description:
        - Save the fabric configuration (recalculate intent) after staging changes.
        type: bool
        default: false
      deploy:
        description:
        - Deploy the fabric configuration to the switches after saving. Requires O(config_actions.save=true).
        type: bool
        default: false
      type:
        description:
        - The deploy scope. V(switch) deploys only the out-of-sync switches in the fabric
          via the switch-level deploy endpoint. V(global) deploys the entire fabric.
        type: str
        default: switch
        choices: [ switch, global ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- The associate and disassociate API operations are bulk operations that return per-item status.
"""

EXAMPLES = r"""
- name: Associate a ToR switch with a leaf switch
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch: 10.15.33.23
        aggregation_or_leaf_switch: 10.15.33.13
        access_or_tor_port_channel_id: 501
        aggregation_or_leaf_port_channel_id: 502
    state: merged

- name: Associate a ToR switch with a leaf switch using management IP addresses
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch: "192.0.2.10"
        aggregation_or_leaf_switch: "192.0.2.20"
        access_or_tor_port_channel_id: 501
        aggregation_or_leaf_port_channel_id: 502
    state: merged

- name: Associate a ToR switch and save and deploy the fabric configuration
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch: "98AFDSD8V0"
        aggregation_or_leaf_switch: "98AM4FFFFV0"
        access_or_tor_port_channel_id: 501
        aggregation_or_leaf_port_channel_id: 502
    state: merged
    config_actions:
      save: true
      deploy: true
      type: switch

- name: Associate a ToR VPC pair with a leaf VPC pair (back-to-back VPC)
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch: "98AFDSD8V0"
        aggregation_or_leaf_switch: "98AM4FFFFV0"
        access_or_tor_peer_switch: "98AWSETG8V0"
        aggregation_or_leaf_peer_switch: "98AMDDDD8V0"
        access_or_tor_port_channel_id: 501
        aggregation_or_leaf_port_channel_id: 502
        access_or_tor_peer_port_channel_id: 503
        aggregation_or_leaf_peer_port_channel_id: 504
        access_or_tor_vpc_id: 1
        aggregation_or_leaf_vpc_id: 2
    state: merged

- name: Disassociate a ToR switch
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch: "98AFDSD8V0"
        aggregation_or_leaf_switch: "98AM4FFFFV0"
    state: deleted

- name: Override the fabric to a single ToR association and stage the removal of the rest
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch: "98AFDSD8V0"
        aggregation_or_leaf_switch: "98AM4FFFFV0"
    state: overridden
    config_actions:
      save: true
      deploy: false

- name: Remove every ToR association in the fabric
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    state: overridden

- name: Gather all ToR associations for a fabric
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    state: gathered
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, the ToR association configuration.
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
  - The existing ToR association configuration before the module ran.
  - Switch identifiers are reported as serial numbers, regardless of whether a serial or a management IP was supplied.
  - An empty list when no matching ToR association existed.
  returned: always
  type: list
  elements: dict
  sample:
  - fabric_name: nac-tme-fabric
    access_or_tor_switch_id: 9WU9XPHL9SW
    aggregation_or_leaf_switch_id: 98AFDSD8V0
    access_or_tor_switch_name: tor-101
after:
  description:
  - The ToR association configuration after the module ran.
  - In check mode, the configuration that would result had the module run outside of check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - fabric_name: nac-tme-fabric
    access_or_tor_switch_id: 9WU9XPHL9SW
    aggregation_or_leaf_switch_id: 98AFDSD8V0
    access_or_tor_switch_name: tor-101
    access_or_tor_port_channel_id: 501
    aggregation_or_leaf_port_channel_id: 501
diff:
  description: The per-association difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - fabric_name: nac-tme-fabric
    access_or_tor_switch_id: 9WU9XPHL9SW
    aggregation_or_leaf_switch_id: 98AFDSD8V0
    access_or_tor_port_channel_id: 501
    aggregation_or_leaf_port_channel_id: 501
proposed:
  description:
  - The configuration the module proposed to apply, before reconciliation with the controller.
  - Any management IP address supplied for a switch is resolved to its serial number before this collection is built.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - fabric_name: nac-tme-fabric
    access_or_tor_switch_id: 9WU9XPHL9SW
    aggregation_or_leaf_switch_id: 98AFDSD8V0
logs:
  description: Internal diagnostic log messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample:
  - "Querying existing ToR association configuration"
msg:
  description: A human-readable error message, present only when the module fails.
  returned: on failure
  type: str
  sample: "Switch resolution failed: Could not resolve management IP 192.0.2.10 in fabric nac-tme-fabric"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import ManageTorModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_tor import ManageTorOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory_helpers import inventory_for_fabric, resolve

import ipaddress
import logging

_LOGGER = logging.getLogger("nd.nd_manage_tor")

# Maps each user-facing switch suboption (serial or management IP) to the
# ``*_switch_id`` serial field the model and API expect.
_SWITCH_FIELD_MAP = {
    "access_or_tor_switch": "access_or_tor_switch_id",
    "aggregation_or_leaf_switch": "aggregation_or_leaf_switch_id",
    "access_or_tor_peer_switch": "access_or_tor_peer_switch_id",
    "aggregation_or_leaf_peer_switch": "aggregation_or_leaf_peer_switch_id",
}


def _looks_like_ip(value):
    """Return True when value parses as an IPv4/IPv6 address (vs a serial number)."""
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _resolve_switch_config(config, fabric_name, get_inventory):
    """Remap each user switch key to its ``*_switch_id`` serial field, resolving IPs.

    A value that parses as an IP address is looked up in the fabric switch
    inventory and replaced with that switch's serial number; a serial is used
    as-is. ``get_inventory`` is a zero-argument callable returning a
    ``FabricSwitchInventory``; it is invoked lazily and only once, so a config
    made up entirely of serials performs no inventory query.
    """
    inventory_cache = {}

    def _inventory():
        if "value" not in inventory_cache:
            inventory_cache["value"] = get_inventory()
        return inventory_cache["value"]

    for entry in config:
        for user_key, serial_key in _SWITCH_FIELD_MAP.items():
            value = entry.pop(user_key, None)
            if value is None:
                continue
            if _looks_like_ip(value):
                value = resolve(_inventory(), switch_ip=value, fabric_name=fabric_name, side=serial_key)
            entry[serial_key] = value


def _build_rest_send(module):
    """Build a RestSend wired to this module, matching the state machine's setup."""
    sender = Sender()
    sender.ansible_module = module
    rest_send_params = dict(module.params)
    rest_send_params["check_mode"] = module.check_mode
    rest_send = RestSend(rest_send_params)
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    return rest_send


def _verbosity_of(module):
    return module._verbosity if hasattr(module, "_verbosity") else 0


def _run_gathered(module, fabric_name):
    """Query current ToR associations without mutating ND.

    ``NDStateMachine`` cannot be used for ``gathered`` because it always builds
    the proposed collection from ``config`` (which for gathered may be absent)
    and its ``manage_state`` rejects the state. So the REST stack is built here
    the same way the state machine does, then ``query_all`` -- a single
    fabric-wide GET returning every association -- is run directly and returned
    as both ``before`` and ``after``.
    """
    rest_send = _build_rest_send(module)

    results = Results()
    results.state = module.params.get("state", "")
    results.check_mode = module.check_mode

    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=results)
    response_data = orchestrator.query_all()
    gathered = NDConfigCollection.from_api_response(response_data=response_data, model_class=ManageTorModel)

    output = NDOutput(output_level=module.params.get("output_level", "normal"))
    output.assign(before=gathered, after=gathered)
    module.exit_json(**output.format_with_verbosity(_verbosity_of(module), results))


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(ManageTorModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "deleted", ["config"]],
        ],
    )
    require_pydantic(module)

    state = module.params["state"]
    fabric_name = module.params["fabric_name"]

    # Resolve serial-or-IP switch inputs to serials and remap the user-facing
    # *_switch keys onto the *_switch_id model fields. This runs before the
    # state machine builds the proposed collection so the composite identity is
    # serial-based and matches the existing associations read from ND.
    config = module.params.get("config") or []
    if state in ("merged", "overridden", "deleted"):
        for item in config:
            if not item.get("access_or_tor_switch"):
                module.fail_json(msg="config[].access_or_tor_switch is required when state is '{0}'.".format(state))
        if config:
            try:
                rest_send = _build_rest_send(module)
                _resolve_switch_config(config, fabric_name, lambda: inventory_for_fabric(rest_send, fabric_name, _LOGGER))
            except Exception as e:
                module.fail_json(msg="Switch resolution failed: {0}".format(str(e)))

    # Inject fabric_name into each config item for model construction (it is a
    # path parameter, not a config suboption).
    for item in config:
        item["fabric_name"] = fabric_name

    if state == "gathered":
        try:
            _run_gathered(module, fabric_name)
        except Exception as e:
            module.fail_json(msg="Module execution failed: {0}".format(str(e)))
        return

    # Parse and validate config_actions BEFORE any state mutation so invalid
    # input fails deterministically on every run, including idempotent no-drift
    # runs, and never mutates ND before failing.
    config_actions = module.params.get("config_actions") or {}
    save = config_actions.get("save", False)
    deploy = config_actions.get("deploy", False)
    deploy_type = config_actions.get("type", "switch")

    try:
        ManageTorOrchestrator.validate_config_actions(save=save, deploy=deploy, deploy_type=deploy_type)
    except ValueError as e:
        module.fail_json(msg=str(e))

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageTorOrchestrator,
        )
        nd_state_machine.manage_state()

        # Execute config save/deploy only on real changes. Unlike the fabric
        # modules, ToR gates on len(sent) for merged, overridden AND deleted: an
        # associate stages pending config that a disassociate (including an
        # overridden removal) must also push (save+deploy) to realize on the
        # switches.
        if len(nd_state_machine.sent) > 0:
            # Scope a switch-level deploy to only the switches referenced by the
            # ToR pairs changed this run. `sent` already holds created/updated
            # pairs (merged/overridden) and removed pairs (deleted, plus the
            # overridden removals of pairs present in ND but absent from config),
            # so both members of every affected vPC pair are covered. A global
            # deploy ignores this and stays fabric-wide.
            only_switch_ids: set = set()
            for pair in nd_state_machine.sent:
                only_switch_ids |= pair.affected_switch_ids()
            nd_state_machine.model_orchestrator.execute_config_actions(
                fabric_names=[fabric_name],
                save=save,
                deploy=deploy,
                deploy_type=deploy_type,
                only_switch_ids=only_switch_ids or None,
            )

        module.exit_json(**nd_state_machine.output.format_with_verbosity(_verbosity_of(module), nd_state_machine.results))

    except NDStateMachineError as e:
        output = nd_state_machine.output.format_with_verbosity(_verbosity_of(module), nd_state_machine.results) if nd_state_machine else {}
        module.fail_json(msg=str(e), **output)
    except Exception as e:
        output = nd_state_machine.output.format_with_verbosity(_verbosity_of(module), nd_state_machine.results) if nd_state_machine else {}
        module.fail_json(msg="Module execution failed: {0}".format(str(e)), **output)


if __name__ == "__main__":
    main()
