from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Neil John"

"""
Validation model for cisco.nd.nd_manage_vpc_pair playbooks.
"""
import logging
from enum import Enum
from typing import Optional

# Logging setup
try:
    from ...common.log import Log
    log = Log()
    log.commit()
    mainlog = logging.getLogger("nd.vpc_pair_model")
except (ImportError, ValueError) as error:
    # Raise module error if Log class is not available or relative import fails
    raise ImportError(f"Failed to initialize logging for VPC pair model: {error}") from error

# This try-except block is used to handle the import of Pydantic.
# If Pydantic is not available, it will define a minimal BaseModel class
# and related functions to ensure compatibility with existing code.
#
# This is used to satisfy the ansible sanity test requirements
try:
    from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
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

    def model_validator(*args, **kwargs):
        """
        A placeholder for model_validator to maintain compatibility with Pydantic.
        This will not perform any validation but allows the code to run without errors.
        """

        def decorator(func):
            return func

        return decorator

else:
    PYDANTIC_IMPORT_ERROR = None


class VpcRole(str, Enum):
    """
    Enumeration of valid VPC roles.
    """
    PRIMARY = "primary"
    SECONDARY = "secondary"
    OPERATIONAL_PRIMARY = "operationalPrimary"
    OPERATIONAL_SECONDARY = "operationalSecondary"


class VpcPairModel(BaseModel):
    """
    Represents a VPC pair configuration.
    
    This model defines the structure for VPC pair configurations in Cisco Nexus Dashboard,
    supporting both playbook input validation and API response processing.
    
    Attributes:
        peer1SwitchId (str): Serial number of the first switch in the VPC pair.
            Maps to both peer1SwitchId in API and peer1_switch_id in playbook.
        peer2SwitchId (str): Serial number of the second switch in the VPC pair.
            Maps to both peer2SwitchId in API and peer2_switch_id in playbook.
        useVirtualPeerLink (bool): Whether to use virtual peer link.
            Maps to useVirtualPeerLink in API. Defaults to False.
        # description (Optional[str]): Description of the VPC pair.
        # domain_id (Optional[int]): Domain ID of the VPC pair.
        # peer1_name (Optional[str]): Hostname of the first peer switch.
        # peer1_vpc_role (Optional[VpcRole]): VPC role of the first peer.
        # peer2_name (Optional[str]): Hostname of the second peer switch.  
        # peer2_vpc_role (Optional[VpcRole]): VPC role of the second peer.
        # intended_peer_name (Optional[str]): Hostname of the intended peer switch.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="ignore",
    )

    # Required fields for playbook configuration
    peer1SwitchId: str = Field(
        alias="peerOneId",
        description="Serial number of the first switch in the VPC pair"
    )
    peer2SwitchId: Optional[str] = Field(
        default=None,
        alias="peerTwoId",
        description="Serial number of the second switch in the VPC pair"
    )
    useVirtualPeerLink: bool = Field(
        default=False,
        description="Whether to use virtual peer link for the VPC pair"
    )
    
    # # Optional fields for API response data
    # description: Optional[str] = Field(
    #     default=None,
    #     description="Description of the VPC pair record"
    # )
    # domain_id: Optional[int] = Field(
    #     default=None,
    #     alias="domainId",
    #     description="Domain ID of the VPC"
    # )
    # peer1_name: Optional[str] = Field(
    #     default=None,
    #     alias="peer1Name",
    #     description="Hostname of the first peer switch"
    # )
    # peer1_vpc_role: Optional[VpcRole] = Field(
    #     default=None,
    #     alias="peer1VpcRole",
    #     description="VPC role of the first peer switch"
    # )
    # peer2_name: Optional[str] = Field(
    #     default=None,
    #     alias="peer2Name", 
    #     description="Hostname of the second peer switch"
    # )
    # peer2_vpc_role: Optional[VpcRole] = Field(
    #     default=None,
    #     alias="peer2VpcRole",
    #     description="VPC role of the second peer switch"
    # )
    # intended_peer_name: Optional[str] = Field(
    #     default=None,
    #     alias="intendedPeerName",
    #     description="Hostname of the intended peer switch"
    # )

    @field_validator("peer1SwitchId", "peer2SwitchId", mode="before")
    @classmethod
    def validate_switch_ids(cls, value: str, info) -> str:
        """
        Validates switch serial numbers.
        
        Args:
            value: The switch serial number to validate.
            info: Field validation info containing field name.
            
        Returns:
            str: The validated switch serial number.
            
        Raises:
            ValueError: If the switch ID is empty or not a string.
        """
        if value is None:
            return value
            
        # Handle empty strings for optional peer2SwitchId
        if isinstance(value, str) and value.strip() == "":
            if info.field_name == "peer2SwitchId":
                mainlog.debug("Empty string provided for optional peer2SwitchId, converting to None")
                return None
            else:
                mainlog.error(f"Invalid switch ID: empty string provided for required field {info.field_name}")
                raise ValueError("Switch ID must be a non-empty string.")
        
        mainlog.debug(f"Validating switch ID: {value}")
        if not value or not isinstance(value, str):
            mainlog.error(f"Invalid switch ID: {value}. Must be a non-empty string.")
            raise ValueError("Switch ID must be a non-empty string.")
        validated_value = value.strip()
        mainlog.debug(f"Switch ID validation successful: {validated_value}")
        return validated_value

    @model_validator(mode="after")
    def validate_different_switch_ids(self) -> "VpcPairModel":
        """
        Validates that peer1SwitchId and peer2SwitchId are different when both are present.
        Also ensures consistent ordering by sorting peer1 and peer2 switch IDs.
        
        Returns:
            VpcPairModel: The validated model instance.
            
        Raises:
            ValueError: If both switch IDs are the same.
        """
        mainlog.debug(f"Validating switch IDs are different: peer1={self.peer1SwitchId}, peer2={self.peer2SwitchId}")
        
        # Check if peer2SwitchId is present and both IDs are the same
        if self.peer2SwitchId and self.peer1SwitchId == self.peer2SwitchId:
            mainlog.error(f"Invalid VPC pair: peer1SwitchId and peer2SwitchId cannot be the same: {self.peer1SwitchId}, {self.peer2SwitchId}")
            raise ValueError("peer1SwitchId and peer2SwitchId must be different")
        
        # Sort peer1 and peer2 to ensure consistent ordering when both are present
        if self.peer2SwitchId:
            switches = sorted([self.peer1SwitchId, self.peer2SwitchId])
            if switches[0] != self.peer1SwitchId or switches[1] != self.peer2SwitchId:
                mainlog.debug(f"Reordering switches for consistency: {self.peer1SwitchId}, {self.peer2SwitchId} -> {switches[0]}, {switches[1]}")
                object.__setattr__(self, 'peer1SwitchId', switches[0])
                object.__setattr__(self, 'peer2SwitchId', switches[1])
        
        mainlog.debug("Switch ID difference validation successful")
        return self

    # @field_validator("domain_id", mode="before")
    # @classmethod
    # def validate_domain_id(cls, value) -> Optional[int]:
    #     """
    #     Validates domain ID is a positive integer.
        
    #     Args:
    #         value: The domain ID to validate.
            
    #     Returns:
    #         Optional[int]: The validated domain ID or None.
            
    #     Raises:
    #         ValueError: If domain ID is not a positive integer.
    #     """
    #     mainlog.debug(f"Validating domain ID: {value}")
    #     if value is None:
    #         mainlog.debug("Domain ID is None, validation passed")
    #         return None
    #     if not isinstance(value, int) or value <= 0:
    #         mainlog.error(f"Invalid domain ID: {value}. Must be a positive integer.")
    #         raise ValueError("Domain ID must be a positive integer.")
    #     mainlog.debug(f"Domain ID validation successful: {value}")
    #     return value

    def __eq__(self, other) -> bool:
        """
        Compare VPC pairs for equality based on switch IDs.
        
        Args:
            other: Another VpcPairModel instance to compare with.
            
        Returns:
            bool: True if the VPC pairs have the same switch IDs (in any order).
        """
        mainlog.debug(f"Comparing VPC pairs: {self} vs {other}")
        if not isinstance(other, VpcPairModel):
            mainlog.debug("Comparison failed: other is not a VpcPairModel instance")
            return False
        
        # VPC pairs are considered equal if they have the same switches,
        # regardless of which is peer1 vs peer2
        self_switches = {self.peer1SwitchId, self.peer2SwitchId}
        other_switches = {other.peer1SwitchId, other.peer2SwitchId}
        result = self_switches == other_switches and self.useVirtualPeerLink == other.useVirtualPeerLink
        mainlog.debug(f"VPC pair comparison result: {result}")
        return result

    def get_switch_pair_key(self) -> str:
        """
        Generate a consistent key for the VPC pair regardless of switch order.

        Returns:
            str: A consistent string key for the switch pair.
        """
        switches = sorted([self.peer1SwitchId, self.peer2SwitchId])
        key = f"{switches[0]}-{switches[1]}"
        mainlog.debug(f"Generated switch pair key: {key}")
        return key

    def to_api_payload(self) -> dict:
        """
        Convert the model to API payload format for create/update operations.
        
        Returns:
            dict: The API payload dictionary.
        """
        payload = {
            "peer1SwitchId": self.peer1SwitchId,
            "peer2SwitchId": self.peer2SwitchId,
            "useVirtualPeerLink": self.useVirtualPeerLink
        }
        mainlog.debug(f"Generated API payload: {payload}")
        return payload

    @classmethod
    def get_model(cls, data: dict, state: str = None, extra: str = "ignore", sw_sn_from_ip: dict = None) -> "VpcPairModel":
        """
        Create a VpcPairModel instance from dict.
        
        Args:
            data: Dictionary containing data for the VPC pair.
            state: The state parameter to determine validation requirements.
            extra: If "forbid", emulates extra="forbid" behavior by rejecting unexpected fields.
            sw_sn_from_ip: Dictionary mapping switch IP addresses to serial numbers.

        Returns:
            VpcPairModel: A new instance populated for the VPC pair.
        """
        mainlog.debug(f"Creating VpcPairModel from VPC pair data: {data}, state: {state}, extra: {extra}")
        
        # Create a copy to avoid modifying the original data
        processed_data = data.copy()
        
        # Handle both naming conventions for peer1_switch_id
        if processed_data.get("peerOneId"):
            processed_data["peer1SwitchId"] = processed_data.pop("peerOneId")
        
        # Handle both naming conventions for peer2_switch_id  
        if processed_data.get("peerTwoId"):
            processed_data["peer2SwitchId"] = processed_data.pop("peerTwoId")
            
        # Convert IP addresses to serial numbers if mapping is provided
        if sw_sn_from_ip:
            if processed_data.get("peer1SwitchId"):
                original_peer1 = processed_data["peer1SwitchId"]
                processed_data["peer1SwitchId"] = sw_sn_from_ip.get(original_peer1, original_peer1)
                # If conversion didn't happen and state is not query, check if it's a valid serial number in the fabric
                if (state and state.lower() != "query" and 
                    processed_data["peer1SwitchId"] == original_peer1 and 
                    original_peer1 not in sw_sn_from_ip.values()):
                    raise ValueError(f"peer1SwitchId '{original_peer1}' not found in fabric inventory. Must be either a valid switch IP address or serial number. Available IP-SN: {sw_sn_from_ip}")
            
            if processed_data.get("peer2SwitchId"):
                original_peer2 = processed_data["peer2SwitchId"] 
                processed_data["peer2SwitchId"] = sw_sn_from_ip.get(original_peer2, original_peer2)
                # If conversion didn't happen and state is not query, check if it's a valid serial number in the fabric
                if (state and state.lower() != "query" and 
                    processed_data["peer2SwitchId"] == original_peer2 and 
                    original_peer2 not in sw_sn_from_ip.values()):
                    raise ValueError(f"peer2SwitchId '{original_peer2}' not found in fabric inventory. Must be either a valid switch IP address or serial number. Available IP-SN: {sw_sn_from_ip}")
        
        # Emulate extra="forbid" behavior if strict mode is enabled
        if extra == "forbid":
            # Get all valid field names including aliases
            valid_fields = set()
            for field_name, field_info in cls.model_fields.items():
                valid_fields.add(field_name)
                if hasattr(field_info, 'alias') and field_info.alias:
                    valid_fields.add(field_info.alias)
            
            # Check for unexpected fields
            unexpected_fields = set(processed_data.keys()) - valid_fields
            if unexpected_fields:
                mainlog.error(f"Unexpected fields found in extra=forbid mode: {unexpected_fields}")
                raise ValueError(f"Unexpected fields not allowed in extra=forbid mode: {', '.join(sorted(unexpected_fields))}")
        
        # Validate that peer2SwitchId is present when state is not "query"
        if not state or state.lower() != "query":
            peer2_switch_id = processed_data.get("peer2_switch_id") or processed_data.get("peer2SwitchId")
            if not peer2_switch_id:
                mainlog.error(f"peer2SwitchId is required when state is '{state}'")
                raise ValueError(f"peer2SwitchId is required when state is '{state}'")
        
        # Validate that useVirtualPeerLink should not be set for query or deleted states
        if state and state.lower() in ["query", "deleted"]:
            if processed_data.get("useVirtualPeerLink") is not None:
                mainlog.error(f"useVirtualPeerLink should not be set when state is '{state}'.")
                raise ValueError(f"useVirtualPeerLink should not be set when state is '{state}'.")
        
        instance = cls(**processed_data)
        mainlog.debug(f"Successfully created VpcPairModel instance: {instance}")
        return instance
