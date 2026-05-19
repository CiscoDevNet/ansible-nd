# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for switch-specific validators."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import (
    validate_serial_number,
    require_serial_number,
    validate_vpc_domain,
    check_discovery_credentials_pair,
)


class TestValidateSerialNumber:
    """Tests for validate_serial_number."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_serial_number(None) is None

    def test_empty_string(self):
        """Test empty string returns None."""
        assert validate_serial_number("") is None
        assert validate_serial_number("   ") is None

    def test_valid_serial_numbers(self):
        """Test valid serial number formats."""
        assert validate_serial_number("ABC123") == "ABC123"
        assert validate_serial_number("FOC12345678") == "FOC12345678"
        assert validate_serial_number("SN-123-456") == "SN-123-456"
        assert validate_serial_number("SN_123_456") == "SN_123_456"
        assert validate_serial_number("123456") == "123456"
        assert validate_serial_number("ABCD-1234-EFGH") == "ABCD-1234-EFGH"

    def test_alphanumeric_only(self):
        """Test alphanumeric serial numbers."""
        assert validate_serial_number("ABC123DEF456") == "ABC123DEF456"
        assert validate_serial_number("1234567890") == "1234567890"
        assert validate_serial_number("ABCDEFGH") == "ABCDEFGH"

    def test_with_hyphens(self):
        """Test serial numbers with hyphens."""
        assert validate_serial_number("A-B-C") == "A-B-C"
        assert validate_serial_number("123-456-789") == "123-456-789"

    def test_with_underscores(self):
        """Test serial numbers with underscores."""
        assert validate_serial_number("A_B_C") == "A_B_C"
        assert validate_serial_number("123_456_789") == "123_456_789"

    def test_mixed_separators(self):
        """Test serial numbers with mixed hyphens and underscores."""
        assert validate_serial_number("ABC_123-DEF") == "ABC_123-DEF"

    def test_whitespace_stripped(self):
        """Test whitespace is stripped."""
        assert validate_serial_number("  ABC123  ") == "ABC123"
        assert validate_serial_number("\tFOC12345\n") == "FOC12345"

    def test_invalid_characters(self):
        """Test invalid characters raise ValueError."""
        with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
            validate_serial_number("ABC@123")
        
        with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
            validate_serial_number("ABC 123")
        
        with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
            validate_serial_number("ABC.123")
        
        with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
            validate_serial_number("ABC/123")
        
        with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
            validate_serial_number("ABC#123")

    def test_special_characters_not_allowed(self):
        """Test various special characters are rejected."""
        invalid_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '[', ']', '{', '}', '|', '\\', '/', '?', '.', ',', '<', '>', ' ']
        for char in invalid_chars:
            with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
                validate_serial_number(f"ABC{char}123")


class TestRequireSerialNumber:
    """Tests for require_serial_number."""

    def test_valid_serial_number(self):
        """Test valid serial number passes through."""
        assert require_serial_number("ABC123") == "ABC123"
        assert require_serial_number("FOC12345678") == "FOC12345678"

    def test_empty_raises(self):
        """Test empty value raises ValueError with default field name."""
        with pytest.raises(ValueError, match="serial_number cannot be empty"):
            require_serial_number("")

    def test_whitespace_only_raises(self):
        """Test whitespace-only value raises ValueError."""
        with pytest.raises(ValueError, match="serial_number cannot be empty"):
            require_serial_number("   ")

    def test_custom_field_name(self):
        """Test custom field name in error message."""
        with pytest.raises(ValueError, match="device_serial cannot be empty"):
            require_serial_number("", "device_serial")

    def test_invalid_format_with_custom_field(self):
        """Test invalid format with custom field name."""
        with pytest.raises(ValueError, match="Serial number must be alphanumeric"):
            require_serial_number("ABC@123", "device_serial")

    def test_switch_id_field_name(self):
        """Test with switch_id field name (common use case)."""
        with pytest.raises(ValueError, match="switch_id cannot be empty"):
            require_serial_number("", "switch_id")
        
        assert require_serial_number("FOC123", "switch_id") == "FOC123"

    def test_peer_switch_id_field_name(self):
        """Test with peer_switch_id field name (common use case)."""
        with pytest.raises(ValueError, match="peer_switch_id cannot be empty"):
            require_serial_number("", "peer_switch_id")
        
        assert require_serial_number("FOC456", "peer_switch_id") == "FOC456"


class TestValidateVpcDomain:
    """Tests for validate_vpc_domain."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_vpc_domain(None) is None

    def test_valid_vpc_domains(self):
        """Test valid VPC domain IDs."""
        assert validate_vpc_domain(1) == 1
        assert validate_vpc_domain(100) == 100
        assert validate_vpc_domain(500) == 500
        assert validate_vpc_domain(1000) == 1000

    def test_boundary_values(self):
        """Test boundary values."""
        assert validate_vpc_domain(1) == 1  # Minimum
        assert validate_vpc_domain(1000) == 1000  # Maximum

    def test_below_minimum(self):
        """Test VPC domain ID below minimum."""
        with pytest.raises(ValueError, match="VPC domain must be between 1 and 1000"):
            validate_vpc_domain(0)
        
        with pytest.raises(ValueError, match="VPC domain must be between 1 and 1000"):
            validate_vpc_domain(-1)
        
        with pytest.raises(ValueError, match="VPC domain must be between 1 and 1000"):
            validate_vpc_domain(-100)

    def test_above_maximum(self):
        """Test VPC domain ID above maximum."""
        with pytest.raises(ValueError, match="VPC domain must be between 1 and 1000"):
            validate_vpc_domain(1001)
        
        with pytest.raises(ValueError, match="VPC domain must be between 1 and 1000"):
            validate_vpc_domain(5000)

    def test_common_values(self):
        """Test commonly used VPC domain IDs."""
        common_domains = [1, 10, 50, 100, 200, 500, 999, 1000]
        for domain in common_domains:
            assert validate_vpc_domain(domain) == domain


class TestCheckDiscoveryCredentialsPair:
    """Tests for check_discovery_credentials_pair."""

    def test_both_none(self):
        """Test both discovery_username and discovery_password are None."""
        # Should not raise
        check_discovery_credentials_pair(None, None)

    def test_both_present(self):
        """Test both discovery_username and discovery_password are present."""
        # Should not raise
        check_discovery_credentials_pair("admin", "password123")
        check_discovery_credentials_pair("user", "pass")

    def test_both_empty_strings(self):
        """Test both are empty strings (falsy)."""
        # Should not raise
        check_discovery_credentials_pair("", "")

    def test_username_only(self):
        """Test only discovery_username is provided."""
        with pytest.raises(ValueError, match="discovery_password must be set when discovery_username is specified"):
            check_discovery_credentials_pair("admin", None)
        
        with pytest.raises(ValueError, match="discovery_password must be set when discovery_username is specified"):
            check_discovery_credentials_pair("admin", "")

    def test_password_only(self):
        """Test only discovery_password is provided."""
        with pytest.raises(ValueError, match="discovery_username must be set when discovery_password is specified"):
            check_discovery_credentials_pair(None, "password123")
        
        with pytest.raises(ValueError, match="discovery_username must be set when discovery_password is specified"):
            check_discovery_credentials_pair("", "password123")

    def test_various_credential_combinations(self):
        """Test various valid credential combinations."""
        # Valid combinations
        valid_combinations = [
            (None, None),
            ("", ""),
            ("admin", "pass"),
            ("user123", "P@ssw0rd!"),
            ("discovery_user", "complex_pass_123"),
        ]
        
        for username, password in valid_combinations:
            # Should not raise
            check_discovery_credentials_pair(username, password)

    def test_invalid_combinations(self):
        """Test various invalid credential combinations."""
        invalid_combinations = [
            ("admin", None),
            ("admin", ""),
            (None, "password"),
            ("", "password"),
            ("user", None),
            (None, "pass"),
        ]
        
        for username, password in invalid_combinations:
            with pytest.raises(ValueError):
                check_discovery_credentials_pair(username, password)


class TestValidatorIntegration:
    """Integration tests for validators working together."""

    def test_serial_number_in_vpc_context(self):
        """Test serial number validation in VPC configuration context."""
        # Valid VPC configuration
        serial = validate_serial_number("FOC12345678")
        vpc_domain = validate_vpc_domain(100)
        
        assert serial == "FOC12345678"
        assert vpc_domain == 100

    def test_discovery_with_valid_serial(self):
        """Test discovery credentials with serial number validation."""
        serial = require_serial_number("FOC12345", "device_serial")
        
        # Valid credentials
        check_discovery_credentials_pair("admin", "password")
        
        assert serial == "FOC12345"

    def test_multiple_validators_chain(self):
        """Test multiple validators in a chain."""
        # Simulate validating a switch configuration
        serial = require_serial_number("FOC123456", "switch_id")
        vpc_domain = validate_vpc_domain(50)
        
        # Discovery credentials optional (both None)
        check_discovery_credentials_pair(None, None)
        
        assert serial == "FOC123456"
        assert vpc_domain == 50

    def test_error_handling_order(self):
        """Test that validators fail fast with clear errors."""
        # First validator should catch empty serial
        with pytest.raises(ValueError, match="serial_number cannot be empty"):
            require_serial_number("")
        
        # Invalid VPC domain
        with pytest.raises(ValueError, match="VPC domain must be between"):
            validate_vpc_domain(2000)
        
        # Incomplete credentials
        with pytest.raises(ValueError, match="discovery_password must be set"):
            check_discovery_credentials_pair("admin", None)
