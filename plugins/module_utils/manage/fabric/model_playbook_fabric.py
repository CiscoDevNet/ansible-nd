from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Mike Wiebe"

"""
Validation model for cisco.nd.manage.fabric playbooks.
"""
from enum import Enum
import re

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
    A model representing fabric management configuration for VXLAN fabrics.

    This Pydantic model defines the configuration parameters required for managing
    network fabrics, particularly in Cisco environments. It handles validation and
    type enforcement for key fabric attributes.

    Attributes:
        type (FabricManagementType): The fabric management type, defaults to VXLAN_IBGP.
        bgpAsn (str): BGP Autonomous System Number in valid format, defaults to empty string.
            Supports both plain ASN (e.g., "65001") and dotted notation (e.g., "65000.123").
        anycastGatewayMac (str): MAC address for the anycast gateway in Cisco format (XXXX.XXXX.XXXX),
            defaults to "2020.0000.00aa".
        replicationMode (FabricReplicationMode): The fabric replication mode,
            defaults to MULTICAST.

    The class includes validators that enforce proper formatting for BGP ASN and
    anycast gateway MAC address values.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,  # Allow both snake_case and camelCase
    )

    type: FabricManagementType = Field(default=FabricManagementType.VXLAN_IBGP.value, alias="type")
    bgp_asn: str = Field(default="", alias="bgpAsn")
    anycast_gateway_mac: str = Field(default="2020.0000.00aa", alias="anycastGatewayMac")
    replication_mode: FabricReplicationMode = Field(default=FabricReplicationMode.MULTICAST.value, alias="replicationMode")

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
    and management settings. It enforces validation rules for these properties.
    Attributes:
        name (str): The name of the fabric. Must start with a letter and contain only
            alphanumeric characters, underscores, or hyphens. Defaults to an empty string.
        securityDomain (str): The security domain for this fabric. Defaults to "all".
        management (FabricManagementModel): The management configuration for this fabric.
    Notes:
        - Whitespace is automatically stripped from string values
        - Values are validated upon assignment, not just initialization

    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,  # Allow both snake_case and camelCase
    )

    name: str = Field(default="", alias="name")
    category: str = Field(default="fabric", alias="category")
    security_domain: str = Field(default="all", alias="securityDomain")
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
