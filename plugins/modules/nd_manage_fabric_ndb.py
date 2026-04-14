#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_ndb
version_added: "2.0.0"
short_description: Manage Data Broker (NDB) fabrics on Cisco Nexus Dashboard
description:
- Manage Nexus Dashboard Data Broker (NDB) fabrics on Cisco Nexus Dashboard (ND).
- It supports creating, updating, replacing, and deleting Data Broker fabrics.
- The Data Broker fabric type (C(dataBroker)) has minimal management settings compared to other fabric types.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of Data Broker fabrics to configure.
    type: list
    elements: dict
    suboptions:
      fabric_name:
        description:
        - The name of the fabric.
        - Only letters, numbers, underscores, and hyphens are allowed.
        - The O(config.fabric_name) must be defined when creating, updating or deleting a fabric.
        type: str
        required: true
      category:
        description:
        - The resource category.
        type: str
        default: fabric
      location:
        description:
        - The geographic location of the fabric.
        type: dict
        suboptions:
          latitude:
            description:
            - Latitude coordinate of the fabric location (-90 to 90).
            type: float
            required: true
          longitude:
            description:
            - Longitude coordinate of the fabric location (-180 to 180).
            type: float
            required: true
      license_tier:
        description:
        - License Tier for fabric.
        type: str
        default: essentials
        choices: [ essentials, advantage, premier ]
      alert_suspend:
        description:
        - Alert Suspend state configured on the fabric.
        type: str
        default: disabled
        choices: [ enabled, disabled ]
      telemetry_collection:
        description:
        - Enable telemetry collection.
        type: bool
        default: true
      telemetry_collection_type:
        description:
        - Telemetry collection method.
        type: str
        default: inBand
        choices: [ inBand, outOfBand ]
      telemetry_streaming_protocol:
        description:
        - Telemetry Streaming Protocol.
        type: str
        default: ipv4
        choices: [ ipv4, ipv6 ]
      telemetry_source_interface:
        description:
        - Telemetry Source Interface Loopback ID, only valid if Telemetry Collection is set to inBand.
        type: str
        default: loopback0
      telemetry_source_vrf:
        description:
        - VRF over which telemetry is streamed, valid only if Telemetry Collection is set to inBand.
        type: str
        default: default
      security_domain:
        description:
        - Security Domain associated with the fabric.
        type: str
        default: all
      management:
        description:
        - The Data Broker management configuration for the fabric.
        - The Data Broker fabric type has minimal management settings — only the C(type) discriminator.
        type: dict
        suboptions:
          type:
            description:
            - The fabric management type. Must be C(dataBroker) for Data Broker fabrics.
            type: str
            default: dataBroker
            choices: [ dataBroker ]
      telemetry_settings:
        description:
        - Telemetry configuration for the fabric.
        type: dict
        suboptions:
          flow_collection:
            description:
            - Flow collection settings.
            type: dict
            suboptions:
              traffic_analytics:
                description:
                - Traffic analytics state.
                type: str
                default: enabled
              traffic_analytics_scope:
                description:
                - Traffic analytics scope.
                type: str
                default: intraFabric
              operating_mode:
                description:
                - Operating mode.
                type: str
                default: flowTelemetry
              udp_categorization:
                description:
                - UDP categorization.
                type: str
                default: enabled
          microburst:
            description:
            - Microburst detection settings.
            type: dict
            suboptions:
              microburst:
                description:
                - Enable microburst detection.
                type: bool
                default: false
              sensitivity:
                description:
                - Microburst sensitivity level.
                type: str
                default: low
          analysis_settings:
            description:
            - Analysis settings.
            type: dict
            suboptions:
              is_enabled:
                description:
                - Enable telemetry analysis.
                type: bool
                default: false
          nas:
            description:
            - NAS telemetry configuration.
            type: dict
            suboptions:
              server:
                description:
                - NAS server address.
                type: str
                default: ""
              export_settings:
                description:
                - NAS export settings.
                type: dict
                suboptions:
                  export_type:
                    description:
                    - Export type.
                    type: str
                    default: full
                  export_format:
                    description:
                    - Export format.
                    type: str
                    default: json
          energy_management:
            description:
            - Energy management settings.
            type: dict
            suboptions:
              cost:
                description:
                - Energy cost per unit.
                type: float
                default: 1.2
      external_streaming_settings:
        description:
        - External streaming settings for the fabric.
        type: dict
        suboptions:
          email:
            description:
            - Email streaming configuration.
            type: list
            elements: dict
          message_bus:
            description:
            - Message bus configuration.
            type: list
            elements: dict
          syslog:
            description:
            - Syslog streaming configuration.
            type: dict
          webhooks:
            description:
            - Webhook configuration.
            type: list
            elements: dict
  state:
    description:
    - The desired state of the fabric resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new fabrics and update existing ones as defined in the configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the fabric configuration specified in the configuration.
      Any settings not explicitly provided will revert to their defaults.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      Any fabric existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the fabrics specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1.0 or higher.
- Only Data Broker fabric type (C(dataBroker)) is supported by this module.
- The Data Broker management configuration is minimal — it contains only the C(type) discriminator field.
"""

EXAMPLES = r"""
- name: Create a Data Broker fabric using state merged
  cisco.nd.nd_manage_fabric_ndb:
    state: merged
    config:
      - fabric_name: my_ndb_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: dataBroker
  register: result

- name: Update location on an existing Data Broker fabric using state merged
  cisco.nd.nd_manage_fabric_ndb:
    state: merged
    config:
      - fabric_name: my_ndb_fabric
        location:
          latitude: 40.7128
          longitude: -74.0060
  register: result

- name: Replace a Data Broker fabric configuration using state replaced
  cisco.nd.nd_manage_fabric_ndb:
    state: replaced
    config:
      - fabric_name: my_ndb_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: advantage
        alert_suspend: enabled
        security_domain: all
        telemetry_collection: true
        telemetry_collection_type: inBand
        management:
          type: dataBroker
  register: result

- name: Delete a Data Broker fabric using state deleted
  cisco.nd.nd_manage_fabric_ndb:
    state: deleted
    config:
      - fabric_name: my_ndb_fabric
  register: result

- name: Delete multiple Data Broker fabrics in a single task
  cisco.nd.nd_manage_fabric_ndb:
    state: deleted
    config:
      - fabric_name: ndb_fabric_east
      - fabric_name: ndb_fabric_west
  register: result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ndb import FabricDataBrokerModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ndb import ManageNdbFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricDataBrokerModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageNdbFabricOrchestrator,
        )

        # Manage state
        nd_state_machine.manage_state()

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}")


if __name__ == "__main__":
    main()
