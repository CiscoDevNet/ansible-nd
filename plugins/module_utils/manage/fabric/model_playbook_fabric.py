from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Mike Wiebe"

"""
Validation model for cisco.nd.manage.fabric playbooks.
"""
from enum import Enum
import re
from typing import List, Optional

# This try-except block is used to handle the import of Pydantic.
# If Pydantic is not available, it will define a minimal BaseModel class
# and related functions to ensure compatibility with existing code.
#
# This is used to satisfy the ansible sanity test requirements
try:
    from pydantic import BaseModel, ConfigDict, Field, field_validator
except ImportError as imp_exc:
    PYDANTIC_IMPORT_ERROR = imp_exc

    # If Pydantic is not available, define a minimal BaseModel and related functions
    # Reference: https://docs.ansible.com/ansible-core/2.17/dev_guide/testing/sanity/import.html
    class BaseModel:
        pass

    def ConfigDict(*args, **kwargs):
        return dict(*args, **kwargs)

    def Field(*args, **kwargs):
        return None

    def field_validator(*args, **kwargs):
        """
        A placeholder for field_validator to maintain compatibility with Pydantic.
        This will not perform any validation but allows the code to run without errors.
        """

        def decorator(func):
            return func

        return decorator

else:
    PYDANTIC_IMPORT_ERROR = None


class NetflowExporterModel(BaseModel):
    """
    Represents a netflow exporter configuration.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    exporter_name: str = Field(alias="exporterName")
    exporter_ip: str = Field(alias="exporterIp")
    vrf: str = Field(alias="vrf")
    source_interface_name: str = Field(alias="sourceInterfaceName")
    udp_port: str = Field(alias="udpPort")


class NetflowMonitorModel(BaseModel):
    """
    Represents a netflow monitor configuration.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    monitor_name: str = Field(alias="monitorName")
    record_name: str = Field(alias="recordName")
    exporter1_name: str = Field(alias="exporter1Name")
    exporter2_name: str = Field(default="", alias="exporter2Name")


class NetflowRecordModel(BaseModel):
    """
    Represents a netflow record configuration.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    record_name: str = Field(alias="recordName")
    record_template: str = Field(alias="recordTemplate")
    layer2_record: str = Field(alias="layer2Record")


class NetflowSettingsModel(BaseModel):
    """
    Represents netflow settings for fabric management.

    When netflow is enabled (True), the exporter, monitor, and record lists
    can be populated with configuration objects. When netflow is disabled (False),
    these lists are ignored and can remain empty.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    netflow: bool = Field(default=False, alias="netflow")
    netflow_exporter_list: List[NetflowExporterModel] = Field(default_factory=list, alias="netflowExporterList")
    netflow_monitor_list: List[NetflowMonitorModel] = Field(default_factory=list, alias="netflowMonitorList")
    netflow_record_list: List[NetflowRecordModel] = Field(default_factory=list, alias="netflowRecordList")

    @field_validator("netflow_exporter_list", "netflow_monitor_list", "netflow_record_list", mode="after")
    @classmethod
    def validate_netflow_lists(cls, value, info):
        """
        Validates that netflow configuration lists are only populated when netflow is enabled.

        When netflow is False, the lists can be empty or populated (they'll be ignored).
        When netflow is True, the lists can contain valid netflow configurations.

        Args:
            value: The list value being validated
            info: Validation context containing other field values

        Returns:
            The validated list value

        Note:
            This validator allows flexibility - you can provide netflow configs even when
            netflow is disabled, but they won't be used. This prevents validation errors
            during model construction while maintaining logical separation.
        """
        # Get the netflow field value from the model data
        netflow_enabled = info.data.get("netflow", False)

        # If netflow is disabled and lists are provided, we can optionally log a warning
        # but we'll allow it for flexibility in configuration management
        if not netflow_enabled and value:
            # Optional: You could add logging here if needed
            # import logging
            # logging.warning(f"Netflow configuration provided but netflow is disabled")
            pass

        return value

    @property
    def effective_exporter_list(self) -> List[NetflowExporterModel]:
        """
        Returns the netflow exporter list only if netflow is enabled.

        Returns:
            List of netflow exporters if netflow is True, empty list otherwise
        """
        return self.netflow_exporter_list if self.netflow else []

    @property
    def effective_monitor_list(self) -> List[NetflowMonitorModel]:
        """
        Returns the netflow monitor list only if netflow is enabled.

        Returns:
            List of netflow monitors if netflow is True, empty list otherwise
        """
        return self.netflow_monitor_list if self.netflow else []

    @property
    def effective_record_list(self) -> List[NetflowRecordModel]:
        """
        Returns the netflow record list only if netflow is enabled.

        Returns:
            List of netflow records if netflow is True, empty list otherwise
        """
        return self.netflow_record_list if self.netflow else []

    def should_configure_netflow(self) -> bool:
        """
        Helper method to determine if netflow should be configured.

        Returns:
            True if netflow is enabled and has valid configuration, False otherwise
        """
        return self.netflow and (len(self.netflow_exporter_list) > 0 or len(self.netflow_monitor_list) > 0 or len(self.netflow_record_list) > 0)


class LocationModel(BaseModel):
    """
    Represents the geographic location of a fabric.

    Attributes:
        latitude (float): The latitude coordinate, defaults to 0.0
        longitude (float): The longitude coordinate, defaults to 0.0
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    latitude: float = Field(default=0.0, alias="latitude")
    longitude: float = Field(default=0.0, alias="longitude")


class FabricManagementType(Enum):
    """
    Enumeration for Fabric Management Types used in Cisco Nexus Dashboard.

    This enum defines the supported fabric management types that can be configured
    when creating or managing network fabrics. Each type represents a different
    networking topology and configuration approach.

    Attributes:
        VXLAN_IBGP (str): VXLAN fabric with iBGP routing protocol
        VXLAN_EBGP (str): VXLAN fabric with eBGP routing protocol
        VXLAN_CAMPUS (str): VXLAN fabric optimized for campus networks
        AIML_VXLAN_IBGP (str): AI/ML optimized VXLAN fabric with iBGP
        AIML_VXLAN_EBGP (str): AI/ML optimized VXLAN fabric with eBGP
        AIML_ROUTED (str): AI/ML optimized routed fabric
        ROUTED (str): Traditional routed fabric topology
        CLASSIC_LAN (str): Classic LAN fabric configuration
        CLASSIC_LAN_ENHANCED (str): Enhanced classic LAN fabric with additional features
        IPFM (str): IP Fabric for Media configuration
        IPFM_ENHANCED (str): Enhanced IP Fabric for Media with additional capabilities
        EXTERNAL_CONNECTIVITY (str): Fabric for external network connectivity
        VXLAN_EXTERNAL (str): VXLAN fabric with external connectivity focus
        ACI (str): Application Centric Infrastructure fabric type
        META (str): Meta fabric type for special configurations

    Methods:
        choices(): Returns a list of all available fabric management types

    Example:
        >>> fabric_type = FabricManagementType.VXLAN_IBGP
        >>> all_types = FabricManagementType.choices()
    """

    VXLAN_IBGP = "vxlanIbgp"
    VXLAN_EBGP = "vxlanEbgp"
    VXLAN_CAMPUS = "vxlanCampus"
    AIML_VXLAN_IBGP = "aimlVxlanIbgp"
    AIML_VXLAN_EBGP = "aimlVxlanEbgp"
    AIML_ROUTED = "aimlRouted"
    ROUTED = "routed"
    CLASSIC_LAN = "classicLan"
    CLASSIC_LAN_ENHANCED = "classicLanEnhanced"
    IPFM = "ipfm"
    IPFM_ENHANCED = "ipfmEnhanced"
    EXTERNAL_CONNECTIVITY = "externalConnectivity"
    VXLAN_EXTERNAL = "vxlanExternal"
    ACI = "aci"
    META = "meta"

    @classmethod
    def choices(cls):
        """
        Returns a list of all the encryption types.
        """
        return [
            cls.VXLAN_IBGP,
            cls.VXLAN_EBGP,
            cls.VXLAN_CAMPUS,
            cls.AIML_VXLAN_IBGP,
            cls.AIML_VXLAN_EBGP,
            cls.AIML_ROUTED,
            cls.ROUTED,
            cls.CLASSIC_LAN,
            cls.CLASSIC_LAN_ENHANCED,
            cls.IPFM,
            cls.IPFM_ENHANCED,
            cls.EXTERNAL_CONNECTIVITY,
            cls.VXLAN_EXTERNAL,
            cls.ACI,
            cls.META,
        ]


class FabricReplicationMode(Enum):
    """
    This enumeration defines the available replication modes for fabric configuration
    in Cisco ND (Nexus Dashboard). The replication mode determines how multicast
    traffic is handled within the fabric.

    Attributes:
        MULTICAST (str): Uses multicast replication mode for traffic distribution.
        INGRESS (str): Uses ingress replication mode for traffic distribution.

    Methods:
        choices(): Returns a list of all available replication mode values.

    Example:
        >>> mode = FabricReplicationMode.MULTICAST
        >>> print(mode.value)
        'multicast'
        >>> available_modes = FabricReplicationMode.choices()
        >>> print(available_modes)
        [<FabricReplicationMode.MULTICAST: 'multicast'>, <FabricReplicationMode.INGRESS: 'ingress'>]
    """

    MULTICAST = "multicast"
    INGRESS = "ingress"

    @classmethod
    def choices(cls):
        """
        Returns a list of all the replication modes.
        """
        return [cls.MULTICAST, cls.INGRESS]


class FabricManagementModel(BaseModel):
    """
    A comprehensive model representing fabric management configuration for VXLAN fabrics.

    This Pydantic model defines the configuration parameters required for managing
    network fabrics, particularly in Cisco environments. It handles validation and
    type enforcement for key fabric attributes.

    The model includes all management settings for fabric configuration including
    BGP, OSPF, ISIS, VPC, VRF, netflow, and many other advanced features.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    # Core fabric management settings
    type: FabricManagementType = Field(default=FabricManagementType.VXLAN_IBGP.value, alias="type")
    bgp_asn: str = Field(default="", alias="bgpAsn")
    anycast_gateway_mac: str = Field(default="2020.0000.00aa", alias="anycastGatewayMac")
    replication_mode: FabricReplicationMode = Field(default=FabricReplicationMode.MULTICAST.value, alias="replicationMode")

    # Netflow settings
    netflow_settings: Optional[NetflowSettingsModel] = Field(default=None, alias="netflowSettings")

    # VPC and peering settings
    vpc_layer3_peer_router: bool = Field(default=True, alias="vpcLayer3PeerRouter")
    vpc_peer_link_port_channel_id: str = Field(default="500", alias="vpcPeerLinkPortChannelId")
    vpc_peer_link_vlan: str = Field(default="3600", alias="vpcPeerLinkVlan")
    vpc_peer_keep_alive_option: str = Field(default="management", alias="vpcPeerKeepAliveOption")
    vpc_domain_id_range: str = Field(default="1-1000", alias="vpcDomainIdRange")
    vpc_delay_restore_timer: int = Field(default=150, alias="vpcDelayRestoreTimer")
    vpc_auto_recovery_timer: int = Field(default=360, alias="vpcAutoRecoveryTimer")
    vpc_tor_delay_restore_timer: int = Field(default=30, alias="vpcTorDelayRestoreTimer")
    vpc_ipv6_neighbor_discovery_sync: bool = Field(default=True, alias="vpcIpv6NeighborDiscoverySync")
    vpc_peer_link_enable_native_vlan: bool = Field(default=False, alias="vpcPeerLinkEnableNativeVlan")
    fabric_vpc_qos: bool = Field(default=False, alias="fabricVpcQos")
    fabric_vpc_qos_policy_name: str = Field(default="spine_qos_for_fabric_vpc_peering", alias="fabricVpcQosPolicyName")
    fabric_vpc_domain_id: bool = Field(default=False, alias="fabricVpcDomainId")

    # VNI and VLAN ranges
    l3_vni_range: str = Field(default="50000-59000", alias="l3VniRange")
    l2_vni_range: str = Field(default="30000-49000", alias="l2VniRange")
    vrf_vlan_range: str = Field(default="2000-2299", alias="vrfVlanRange")
    network_vlan_range: str = Field(default="2300-2999", alias="networkVlanRange")
    service_network_vlan_range: str = Field(default="3000-3199", alias="serviceNetworkVlanRange")

    # BGP settings
    bgp_loopback_id: int = Field(default=0, alias="bgpLoopbackId")
    bgp_loopback_ip_range: str = Field(default="10.2.0.0/22", alias="bgpLoopbackIpRange")
    bgp_authentication: bool = Field(default=False, alias="bgpAuthentication")
    bgp_authentication_key_type: str = Field(default="3des", alias="bgpAuthenticationKeyType")
    auto_bgp_neighbor_description: bool = Field(default=True, alias="autoBgpNeighborDescription")

    # NVE settings
    nve_loopback_id: int = Field(default=1, alias="nveLoopbackId")
    nve_loopback_ip_range: str = Field(default="10.3.0.0/22", alias="nveLoopbackIpRange")
    nve_hold_down_timer: int = Field(default=180, alias="nveHoldDownTimer")

    # IPv6 settings
    underlay_ipv6: bool = Field(default=False, alias="underlayIpv6")
    ipv6_link_local: bool = Field(default=True, alias="ipv6LinkLocal")
    ipv6_subnet_target_mask: int = Field(default=126, alias="ipv6SubnetTargetMask")

    # VRF settings
    vrf_template: str = Field(default="Default_VRF_Universal", alias="vrfTemplate")
    vrf_extension_template: str = Field(default="Default_VRF_Extension_Universal", alias="vrfExtensionTemplate")
    vrf_lite_subnet_range: str = Field(default="10.33.0.0/16", alias="vrfLiteSubnetRange")
    vrf_lite_subnet_target_mask: int = Field(default=30, alias="vrfLiteSubnetTargetMask")
    vrf_lite_ipv6_subnet_range: str = Field(default="fd00::a33:0/112", alias="vrfLiteIpv6SubnetRange")
    vrf_lite_ipv6_subnet_target_mask: int = Field(default=126, alias="vrfLiteIpv6SubnetTargetMask")
    vrf_lite_auto_config: str = Field(default="manual", alias="vrfLiteAutoConfig")
    vrf_lite_macsec: bool = Field(default=False, alias="vrfLiteMacsec")
    auto_unique_vrf_lite_ip_prefix: bool = Field(default=False, alias="autoUniqueVrfLiteIpPrefix")
    auto_symmetric_vrf_lite: bool = Field(default=False, alias="autoSymmetricVrfLite")
    auto_symmetric_default_vrf: bool = Field(default=False, alias="autoSymmetricDefaultVrf")
    auto_vrf_lite_default_vrf: bool = Field(default=False, alias="autoVrfLiteDefaultVrf")
    vrf_route_import_id_reallocation: bool = Field(default=False, alias="vrfRouteImportIdReallocation")
    per_vrf_loopback_auto_provision: bool = Field(default=False, alias="perVrfLoopbackAutoProvision")
    per_vrf_loopback_auto_provision_ipv6: bool = Field(default=False, alias="perVrfLoopbackAutoProvisionIpv6")

    # Network settings
    network_template: str = Field(default="Default_Network_Universal", alias="networkTemplate")
    network_extension_template: str = Field(default="Default_Network_Extension_Universal", alias="networkExtensionTemplate")
    brownfield_network_name_format: str = Field(default="Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$", alias="brownfieldNetworkNameFormat")
    brownfield_skip_overlay_network_attachments: bool = Field(default=False, alias="brownfieldSkipOverlayNetworkAttachments")

    # Fabric interface and underlay settings
    fabric_interface_type: str = Field(default="p2p", alias="fabricInterfaceType")
    fabric_mtu: int = Field(default=9216, alias="fabricMtu")
    l2_host_interface_mtu: int = Field(default=9216, alias="l2HostInterfaceMtu")
    target_subnet_mask: int = Field(default=30, alias="targetSubnetMask")
    intra_fabric_subnet_range: str = Field(default="10.4.0.0/16", alias="intraFabricSubnetRange")
    static_underlay_ip_allocation: bool = Field(default=False, alias="staticUnderlayIpAllocation")

    # OSPF settings
    ospf_area_id: str = Field(default="0.0.0.0", alias="ospfAreaId")
    ospf_authentication: bool = Field(default=False, alias="ospfAuthentication")
    link_state_routing_protocol: str = Field(default="ospf", alias="linkStateRoutingProtocol")
    link_state_routing_tag: str = Field(default="UNDERLAY", alias="linkStateRoutingTag")

    # ISIS settings
    isis_level: str = Field(default="level-2", alias="isisLevel")
    isis_area_number: str = Field(default="0001", alias="isisAreaNumber")
    isis_authentication: bool = Field(default=False, alias="isisAuthentication")
    mpls_isis_area_number: str = Field(default="0001", alias="mplsIsisAreaNumber")

    # BFD settings
    bfd: bool = Field(default=False, alias="bfd")
    bfd_pim: bool = Field(default=False, alias="bfdPim")
    bfd_isis: bool = Field(default=False, alias="bfdIsis")
    bfd_ospf: bool = Field(default=False, alias="bfdOspf")
    bfd_ibgp: bool = Field(default=False, alias="bfdIbgp")
    bfd_authentication: bool = Field(default=False, alias="bfdAuthentication")

    # Multicast settings
    anycast_rendezvous_point_ip_range: str = Field(default="10.254.254.0/24", alias="anycastRendezvousPointIpRange")
    rendezvous_point_mode: str = Field(default="asm", alias="rendezvousPointMode")
    rendezvous_point_count: int = Field(default=2, alias="rendezvousPointCount")
    rendezvous_point_loopback_id: int = Field(default=254, alias="rendezvousPointLoopbackId")
    multicast_group_subnet: str = Field(default="239.1.1.0/25", alias="multicastGroupSubnet")
    auto_generate_multicast_group_address: bool = Field(default=False, alias="autoGenerateMulticastGroupAddress")
    underlay_multicast_group_address_limit: int = Field(default=128, alias="underlayMulticastGroupAddressLimit")
    tenant_routed_multicast: bool = Field(default=False, alias="tenantRoutedMulticast")
    tenant_routed_multicast_ipv6: bool = Field(default=False, alias="tenantRoutedMulticastIpv6")

    # Security and authentication
    security_group_tag: bool = Field(default=False, alias="securityGroupTag")
    macsec: bool = Field(default=False, alias="macsec")
    pim_hello_authentication: bool = Field(default=False, alias="pimHelloAuthentication")

    # PTP and timing
    ptp: bool = Field(default=False, alias="ptp")

    # Management and monitoring
    real_time_backup: bool = Field(default=True, alias="realTimeBackup")
    scheduled_backup: bool = Field(default=True, alias="scheduledBackup")
    scheduled_backup_time: str = Field(default="21:38", alias="scheduledBackupTime")
    real_time_interface_statistics_collection: bool = Field(default=False, alias="realTimeInterfaceStatisticsCollection")
    performance_monitoring: bool = Field(default=False, alias="performanceMonitoring")
    strict_config_compliance_mode: bool = Field(default=False, alias="strictConfigComplianceMode")

    # System settings
    site_id: str = Field(default="4225625065", alias="siteId")
    power_redundancy_mode: str = Field(default="redundant", alias="powerRedundancyMode")
    heartbeat_interval: int = Field(default=190, alias="heartbeatInterval")

    # QoS and queuing
    default_queuing_policy: bool = Field(default=False, alias="defaultQueuingPolicy")
    default_queuing_policy_other: str = Field(default="queuing_policy_default_other", alias="defaultQueuingPolicyOther")
    default_queuing_policy_cloudscale: str = Field(default="queuing_policy_default_8q_cloudscale", alias="defaultQueuingPolicyCloudscale")
    default_queuing_policy_r_series: str = Field(default="queuing_policy_default_r_series", alias="defaultQueuingPolicyRSeries")
    aiml_qos: bool = Field(default=False, alias="aimlQos")
    aiml_qos_policy: str = Field(default="400G", alias="aimlQosPolicy")

    # DHCP and AAA
    tenant_dhcp: bool = Field(default=True, alias="tenantDhcp")
    local_dhcp_server: bool = Field(default=False, alias="localDhcpServer")
    aaa: bool = Field(default=False, alias="aaa")

    # Protocol settings
    cdp: bool = Field(default=False, alias="cdp")
    nxapi: bool = Field(default=False, alias="nxapi")
    nxapi_http: bool = Field(default=True, alias="nxapiHttp")
    nxapi_http_port: int = Field(default=80, alias="nxapiHttpPort")
    nxapi_https_port: int = Field(default=443, alias="nxapiHttpsPort")
    snmp_trap: bool = Field(default=True, alias="snmpTrap")

    # Overlay and EVPN settings
    overlay_mode: str = Field(default="cli", alias="overlayMode")
    route_reflector_count: int = Field(default=2, alias="routeReflectorCount")
    advertise_physical_ip: bool = Field(default=False, alias="advertisePhysicalIp")
    advertise_physical_ip_on_border: bool = Field(default=True, alias="advertisePhysicalIpOnBorder")
    anycast_border_gateway_advertise_physical_ip: bool = Field(default=False, alias="anycastBorderGatewayAdvertisePhysicalIp")

    # VLAN and interface ranges
    sub_interface_dot1q_range: str = Field(default="2-511", alias="subInterfaceDot1qRange")
    object_tracking_number_range: str = Field(default="100-299", alias="objectTrackingNumberRange")
    route_map_sequence_number_range: str = Field(default="1-65534", alias="routeMapSequenceNumberRange")
    ip_service_level_agreement_id_range: str = Field(default="10000-19999", alias="ipServiceLevelAgreementIdRange")

    # Private VLAN
    private_vlan: bool = Field(default=False, alias="privateVlan")

    # Advanced features
    policy_based_routing: bool = Field(default=False, alias="policyBasedRouting")
    tcam_allocation: bool = Field(default=True, alias="tcamAllocation")
    l3_vni_no_vlan_default_option: bool = Field(default=False, alias="l3VniNoVlanDefaultOption")
    host_interface_admin_state: bool = Field(default=True, alias="hostInterfaceAdminState")
    allow_vlan_on_leaf_tor_pairing: str = Field(default="none", alias="allowVlanOnLeafTorPairing")

    # Routing and STP
    stp_root_option: str = Field(default="unmanaged", alias="stpRootOption")
    leaf_to_r_id_range: bool = Field(default=False, alias="leafToRIdRange")

    # Bootstrap and day0
    day0_bootstrap: bool = Field(default=False, alias="day0Bootstrap")
    bootstrap_multi_subnet: str = Field(default="#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix", alias="bootstrapMultiSubnet")

    # OAM and debugging
    next_generation_oam: bool = Field(default=True, alias="nextGenerationOAM")
    ngoam_south_bound_loop_detect: bool = Field(default=False, alias="ngoamSouthBoundLoopDetect")
    greenfield_debug_flag: str = Field(default="disable", alias="greenfieldDebugFlag")

    # MPLS
    mpls_handoff: bool = Field(default=False, alias="mplsHandoff")

    # CoPP
    copp_policy: str = Field(default="strict", alias="coppPolicy")

    # In-band management
    inband_management: bool = Field(default=False, alias="inbandManagement")

    # SSH
    advanced_ssh_option: bool = Field(default=False, alias="advancedSshOption")

    # Server collections
    ntp_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerCollection")
    ntp_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerVrfCollection")
    dns_collection: List[str] = Field(default_factory=lambda: ["5.192.28.174"], alias="dnsCollection")
    # dns_vrf_collection: List[str] = Field(default_factory=list, alias="dnsVrfCollection")
    dns_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="dnsVrfCollection")
    syslog_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerCollection")
    syslog_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerVrfCollection")
    syslog_severity_collection: List[str] = Field(default_factory=lambda: ["7"], alias="syslogSeverityCollection")

    # Extra configuration sections
    extra_config_leaf: str = Field(default="string", alias="extraConfigLeaf")
    extra_config_spine: str = Field(default="string", alias="extraConfigSpine")
    extra_config_tor: str = Field(default="string", alias="extraConfigTor")
    extra_config_aaa: str = Field(default="string", alias="extraConfigAaa")
    extra_config_intra_fabric_links: str = Field(default="string", alias="extraConfigIntraFabricLinks")
    pre_interface_config_leaf: str = Field(default="string", alias="preInterfaceConfigLeaf")
    pre_interface_config_spine: str = Field(default="string", alias="preInterfaceConfigSpine")
    pre_interface_config_tor: str = Field(default="string", alias="preInterfaceConfigTor")

    # Fabric name (from the top level but also appears in management)
    # name: str = Field(default="postman-fabric", alias="name")

    @field_validator("bgp_asn", mode="before")
    @classmethod
    def validate_bgp_asn(cls, value: str) -> str:
        """
        Validate BGP Autonomous System Number (ASN) format.

        This validator ensures the BGP ASN is provided as a string and matches
        the expected format for both 2-byte and 4-byte ASNs.

        Args:
            value (str): The BGP ASN value to validate

        Returns:
            str: The validated BGP ASN value

        Raises:
            ValueError: If the value is not a string, is empty, or doesn't match
                    the valid ASN format

        Note:
            Accepts the following ASN formats:
            - Plain ASN format: "65001"
            - Dotted notation: "65000.123"
            - 4-byte ASN range: 1-4294967295
            - 2-byte ASN range: 1-65535 (with optional dotted notation)
        """
        # Regex pattern for BGP ASN validation (plain and dotted notation, 2-byte and 4-byte ASN)
        pattern = (
            r"^(("
            r"[1-9]{1}[0-9]{0,8}|[1-3]{1}[0-9]{1,9}|[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|"
            r"[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|"
            r"[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|"
            r"655[0-2]\d|6553[0-5])(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))?)$"
        )
        if not isinstance(value, str):
            raise ValueError("BGP ASN must be a string")
        # Check if the value is empty
        if not value:
            raise ValueError("BGP ASN cannot be an empty string")
        # Check if the value matches the regex pattern
        # The regex allows for both plain ASN (e.g., "65001") and dotted notation (e.g., "65000.123")
        # It also allows for 32-bit ASNs in the format "65535.65535"
        if not re.match(pattern, value):
            raise ValueError(f"Invalid BGP ASN format: {value}. Must be a valid ASN number.")
        return value

    @field_validator("anycast_gateway_mac", mode="before")
    @classmethod
    def validate_anycast_gateway_mac(cls, value: str) -> str:
        """
        Validates that the anycastGatewayMac field follows Cisco-style MAC address format.

        This validator ensures that the MAC address is provided as a string in the
        Cisco-style format (XXXX.XXXX.XXXX) where each X represents a hexadecimal digit.

        Args:
            value (str): The MAC address string to validate.

        Returns:
            str: The validated MAC address string in Cisco-style format.

        Raises:
            ValueError: If the value is not a string or if the MAC address format
                        is invalid (not matching XXXX.XXXX.XXXX pattern with hex digits).

        Example:
            Valid formats: "2020.0000.00aa", "ABCD.1234.5678"
            Invalid formats: "20:20:00:00:00:aa", "202000000aa", "XXXX.YYYY.ZZZZ"
        """

        # Create a regex pattern to match the Cisco-Style format below
        pattern = r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$"
        if not isinstance(value, str):
            raise ValueError("Anycast Gateway MAC must be a string in Cisco-style format (e.g., 2020.0000.00aa)")
        if not re.match(pattern, value):
            raise ValueError(f"Invalid Anycast Gateway MAC format: {value}. Must be in Cisco-style format 'XXXX.XXXX.XXXX' where X is a hex digit.")
        return value


class FabricModel(BaseModel):
    """
    Represents a Fabric model in the network infrastructure.
    This class models a fabric configuration including its name, security domain,
    location, and management settings. It enforces validation rules for these properties.
    Attributes:
        name (str): The name of the fabric. Must start with a letter and contain only
            alphanumeric characters, underscores, or hyphens. Defaults to an empty string.
        alert_suspend (str): Alert suspension setting. Defaults to "disabled".
        category (str): The fabric category. Defaults to "fabric".
        security_domain (str): The security domain for this fabric. Defaults to "all".
        location (Optional[LocationModel]): The geographic location of the fabric.
        management (FabricManagementModel): The management configuration for this fabric.
    Notes:
        - Whitespace is automatically stripped from string values
        - Values are validated upon assignment, not just initialization

    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    name: str = Field(default="", alias="name")
    alert_suspend: str = Field(default="disabled", alias="alertSuspend")
    category: str = Field(default="fabric", alias="category")
    security_domain: str = Field(default="all", alias="securityDomain")
    location: Optional[LocationModel] = Field(default=None, alias="location")
    management: FabricManagementModel = Field(alias="management")

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """
        Validates that a fabric name follows the required naming conventions.

        Args:
            value (str): The fabric name to validate.

        Returns:
            str: The validated fabric name if it passes all checks.

        Raises:
            ValueError: If the name is empty, not a string, or doesn't match the required pattern.
                        The name must start with a letter and contain only alphanumeric characters,
                        underscores, or hyphens.

        Example:
            >>> validate_name("MyFabric-1")
            'MyFabric-1'
            >>> validate_name("123Invalid")
            ValueError: Name must start with a letter and contain only alphanumeric characters, underscores, or hyphens.
        """
        if not value or not isinstance(value, str):
            raise ValueError("Name must be a non-empty string.")
        pattern = r"^[A-Za-z][A-Za-z0-9_-]*$"
        if not re.match(pattern, value):
            raise ValueError("Name must start with a letter and contain only alphanumeric characters, underscores, or hyphens.")
        return value
