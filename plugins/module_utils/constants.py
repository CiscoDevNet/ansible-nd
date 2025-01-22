# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

OBJECT_TYPES = {
    "tenant": "OST_TENANT",
    "vrf": "OST_VRF",
    "bd": "OST_BD",
    "epg": "OST_EPG",
    "contract": "OST_CONTRACT",
    "subject": "OST_SUBJECT",
    "filter": "OST_FILTER",
}

MATCH_TYPES = {
    "tenant": {
        "match_value": "tenantMatch",
        "pattern_value": "tenant",
        "permitted_objects": ["tenant"],  # currently not used
        "permitted_sub_match_types": ["vrf", "bd"],  # currently not used
    },
    "vrf": {"match_value": "vrfMatch", "pattern_value": "vrf", "permitted_objects": ["tenant", "vrf"]},  # currently not used
    "bd": {"match_value": "bdMatch", "pattern_value": "bd", "permitted_objects": ["tenant", "bd"]},  # currently not used
    "epg": {"match_value": "applicationEpgmatch", "pattern_value": "applicationEpg", "permitted_objects": ["tenant", "ap", "epg"]},  # currently not used
    "ap": {
        "match_value": "applicationProfileMatch",
        "pattern_value": "applicationProfile",
        "permitted_objects": ["tenant", "ap"],  # currently not used
        "permitted_sub_match_types": ["vrf", "bd"],  # currently not used
    },
    "l3out": {"match_value": "l3ExtOutMatch", "pattern_value": "l3ExtOut", "permitted_objects": ["tenant", "l3out"]},  # currently not used
    "l3instp": {"match_value": "l2ExtInstpMatch", "pattern_value": "l2ExtInstp", "permitted_objects": ["tenant", "l3out", "l3instp"]},  # currently not used
    "l2out": {"match_value": "l2ExtOutMatch", "pattern_value": "l2ExtOut", "permitted_objects": ["tenant", "l2out"]},  # currently not used
    "l2instp": {"match_value": "l2ExtInstpMatch", "pattern_value": "l2instp", "permitted_objects": ["tenant", "l2out", "l2instp"]},  # currently not used
    "filter": {"match_value": "filterMatch", "pattern_value": "filter", "permitted_objects": ["tenant", "filter"]},  # currently not used
    "subject": {"match_value": "subjectMatch", "pattern_value": "subject", "permitted_objects": ["tenant", "contract", "subject"]},  # currently not used
    "contract": {"match_value": "contractMatch", "pattern_value": "contract", "permitted_objects": ["tenant", "contract"]},  # currently not used
}

ETHER_TYPES = ["arp", "fcoe", "ip", "mac_security", "mpls_unicast", "trill"]

PROTOCOL_TYPES = ["all", "egp", "eigrp", "icmp", "icmpv6", "igmp", "igp", "l2tp", "ospfigp", "pim", "tcp", "udp"]

OPERATORS = ["contains", "begins_with", "ends_with", "equal_to", "not_equal_to", "not_contains", "not_begins_with", "not_ends_with"]

CONFIG_OPERATORS = ["regex", "exact", "at_least", "at_most", "all", "none", "at_least_one"]

PARAMETER_TYPES = {
    "name": {"parameter_value": "CCP_NAME", "valid_for": ["epg", "bd", "vrf", "contract", "subject", "filter"]},  # currently not used
    "name_alias": {"parameter_value": "CCP_NAME_ALIAS", "valid_for": ["epg", "bd", "vrf", "contract", "subject", "filter"]},  # currently not used
    "enforcement_preference": {
        "parameter_value": "CCP_ENFORCEMENT_PREFERENCE",
        "valid_for": ["vrf", "epg"],  # currently not used
        "permitted_values": ["Unenforced", "Enforced"],  # currently not used
    },
    "enforcement_direction": {
        "parameter_value": "CCP_ENFORCEMENT_DIRECTION",
        "valid_for": ["vrf"],  # currently not used
        "permitted_values": ["Ingress", "Egress"],  # currently not used
    },
    "preferred_group": {
        "parameter_value": "CCP_PREFERRED_GROUP",
        "valid_for": ["vrf"],  # currently not used
        "permitted_values": ["Disabled", "Enabled"],  # currently not used
    },
    "bd_enforcement": {
        "parameter_value": "CCP_BD_ENFORCEMENT",
        "valid_for": ["vrf"],  # currently not used
        "permitted_values": ["No", "Yes"],  # currently not used
    },
    "bd_type": {"parameter_value": "CCP_BD_TYPE", "valid_for": ["bd"], "permitted_values": ["Regular", "Fc"]},  # currently not used  # currently not used
    "l2_unknown_unicast": {
        "parameter_value": "CCP_L2_UNKNOWN_UNICAST",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["Hardware Proxy", "Flood"],  # currently not used
    },
    "l3_unknown_unicast_flooding": {
        "parameter_value": "CCP_L3_UNKNOWN_MULTICAST_FLOODING",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["Optimized Flood", "Flood"],  # currently not used
    },
    "bd_multi_destination_flooding": {
        "parameter_value": "CCP_BD_MULTI_DESTINATION_FLOODING",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["drop", "bd-flood", "encap-flood"],  # currently not used
    },
    "pim": {"parameter_value": "CCP_PIM", "valid_for": ["bd"], "permitted_values": ["Disabled", "Enabled"]},  # currently not used  # currently not used
    "arp_flooding": {
        "parameter_value": "CCP_ARP_FLOODING",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["No", "Yes"],  # currently not used
    },
    "limit_ip_learning_to_subnet": {
        "parameter_value": "CCP_LIMIT_IP_LEARNING_TO_SUBNET",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["No", "Yes"],  # currently not used
    },
    "unicast_routing": {
        "parameter_value": "CCP_UNICAST_ROUTING",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["No", "Yes"],  # currently not used
    },
    "epg_association_count": {"parameter_value": "CCP_OBJECT_ASSOCIATION_COUNT", "valid_for": ["bd"]},  # currently not used
    "subnets": {
        "parameter_value": "CCP_OBJECT_ASSOCIATION_COUNT",
        "valid_for": ["bd"],  # currently not used
        "permitted_values": ["Shared", "Private", "Public"],  # currently not used
    },
    "preferred_group_member": {
        "parameter_value": "CCP_PREFERRED_GROUP_EPG",
        "valid_for": ["epg"],  # currently not used
        "permitted_values": ["Exclude", "Include"],  # currently not used
    },
    "qos_class": {
        "parameter_value": "CCP_PRIORITY",
        "valid_for": ["epg"],  # currently not used
        "permitted_values": ["unspecified", "level1", "level2", "level3"],  # currently not used
    },
}

TCP_FLAGS = {"ack": "ACKNOWLEDGEMENT", "est": "ESTABLISHED", "fin": "FINISH", "res": "RESET", "syn": "SYNCHRONIZED"}

EPOCH_DELTA_TYPES = {"latest": 0, "last_15_min": 900, "last_hour": 3600, "last_2_hours": 7200, "last_6_hours": 21600, "last_day": 86400, "last_week": 604800}

SITE_TYPE_MAP = {"aci": "ACI", "dcnm": "DCNM", "third_party": "ThirdParty", "cloud_aci": "CloudACI", "dcnm_ng": "DCNMNG", "ndfc": "NDFC"}

FILTER_BY_ATTIRBUTES_KEYS = {
    "provider_epg": "providerEpgName",
    "consumer_epg": "consumerEpgName",
    "provider_tenant": "providerTenantName",
    "consumer_tenant": "consumerTenantName",
    "contract": "contractName",
    "filter": "filterName",
    "consumer_vrf": "consumerVrfName",
    "action": "action",
    "leaf": "leaf",
}

# Allowed states to append sent and proposed values in the task result
ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED = (
    "absent",
    "present",
    "upload",
    "restore",
    "download",
    "move",
    "backup",
    "enable",
    "disable",
    "restart",
    "delete",
    "update",
)

INTERFACE_FLOW_RULES_TYPES_MAPPING = {"port_channel": "PORTCHANNEL", "physical": "PHYSICAL", "l3out_sub_interface": "L3_SUBIF", "l3out_svi": "SVI"}

INTERFACE_FLOW_RULES_STATUS_MAPPING = {"enabled": "ENABLED", "disabled": "DISABLED"}

ND_SETUP_NODE_ROLE_MAPPING = {"primary": "Master", "secondary": "Worker", "standby": "Standby"}

ND_REST_KEYS_TO_SANITIZE = ["metadata"]
