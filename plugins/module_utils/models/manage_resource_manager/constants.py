# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared constants and Ansible/DCNM-style enums for Resource Management models.

Imported by all nd_manage_resource_manager_updated_models_*.py files.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from enum import Enum
from typing import Dict, List

# =============================================================================
# POOL_SCOPE_MAP - Derived from dcnm_rm_check_resource_params()
# Maps known pool names to the scope types they are valid for.
# Custom / user-defined pool names not present here are unrestricted.
# =============================================================================

POOL_SCOPE_MAP: Dict[str, List[str]] = {
    "L3_VNI": ["fabric"],
    "L2_VNI": ["fabric"],
    "BGP_ASN_ID": ["fabric"],
    "VPC_DOMAIN_ID": ["fabric"],
    "VPC_ID": ["device_pair"],
    "VPC_PEER_LINK_VLAN": ["device_pair"],
    "FEX_ID": ["device"],
    "LOOPBACK_ID": ["device"],
    "PORT_CHANNEL_ID": ["device"],
    "TUNNEL_ID_IOS_XE": ["device"],
    "OBJECT_TRACKING_NUMBER_POOL": ["device"],
    "INSTANCE_ID": ["device"],
    "PORT_CHANNEL_ID_IOS_XE": ["device"],
    "ROUTE_MAP_SEQUENCE_NUMBER_POOL": ["device"],
    "SERVICE_NETWORK_VLAN": ["device"],
    "TOP_DOWN_VRF_VLAN": ["device"],
    "TOP_DOWN_NETWORK_VLAN": ["device"],
    "TOP_DOWN_L3_DOT1Q": ["device_interface"],
    "IP_POOL": ["fabric", "device_interface"],
    "SUBNET": ["link"],
    "loopbackId": ["device"],
}

# =============================================================================
# SCOPE_TYPE_TO_API / API_SCOPE_TYPE_TO_PLAYBOOK
# Maps between playbook scope_type values (underscore) and ND API scopeType
# values (camelCase).
# =============================================================================

SCOPE_TYPE_TO_API: Dict[str, str] = {
    "fabric": "fabric",
    "device": "device",
    "device_interface": "deviceInterface",
    "device_pair": "devicePair",
    "link": "link",
}

API_SCOPE_TYPE_TO_PLAYBOOK: Dict[str, str] = {v: k for k, v in SCOPE_TYPE_TO_API.items()}

# =============================================================================
# ENUMS - Ansible/DCNM-style values
# =============================================================================


class PoolType(str, Enum):
    """
    Pool type enumeration using Ansible/DCNM-style values.

    User-facing values (as used in dcnm_resource_manager.py DOCUMENTATION):
      ID     → integer ID pool  (ND API: idPool)
      IP     → IP address pool  (ND API: ipPool)
      SUBNET → subnet/CIDR pool (ND API: subnetPool)
    """

    ID = "ID"
    IP = "IP"
    SUBNET = "SUBNET"

    @classmethod
    def choices(cls) -> List[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class ScopeType(str, Enum):
    """
    Scope type enumeration using values (underscores).

    User-facing values (as used in dcnm_resource_manager.py DOCUMENTATION):
      fabric           (ND API: fabric)
      device           (ND API: device)
      device_interface (ND API: deviceInterface)
      device_pair      (ND API: devicePair)
      link             (ND API: link)
    """

    FABRIC = "fabric"
    DEVICE = "device"
    DEVICE_INTERFACE = "device_interface"
    DEVICE_PAIR = "device_pair"
    LINK = "link"

    @classmethod
    def choices(cls) -> List[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class VlanType(str, Enum):
    """
    VLAN type enumeration for the proposeVlan and unusedVlans endpoints.

    Valid values:
      networkVlan         - Network VLAN
      vrfVlan             - VRF VLAN
      serviceNetworkVlan  - Service network VLAN
      vpcPeerLinkVlan     - VPC peer-link VLAN
    """

    NETWORK_VLAN = "networkVlan"
    VRF_VLAN = "vrfVlan"
    SERVICE_NETWORK_VLAN = "serviceNetworkVlan"
    VPC_PEER_LINK_VLAN = "vpcPeerLinkVlan"

    @classmethod
    def choices(cls):
        """Return list of valid string values."""
        return [e.value for e in cls]


__all__ = [
    "POOL_SCOPE_MAP",
    "PoolType",
    "ScopeType",
    "VlanType",
]
