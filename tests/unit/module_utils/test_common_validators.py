# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for common validators."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.validators import (
    _normalize_optional_string,
    _require_field,
    validate_ip_address,
    validate_cidr,
    validate_ip_or_cidr_as_cidr,
    validate_hostname,
    validate_mac_address,
    require_ip_address,
    require_ip_or_cidr_as_cidr,
    require_hostname,
    require_mac_address,
    validate_cidr_optional,
    check_credentials_pair,
)


class TestNormalizeOptionalString:
    """Tests for _normalize_optional_string helper."""

    def test_none_input(self):
        """Test None input returns None."""
        assert _normalize_optional_string(None) is None

    def test_empty_string(self):
        """Test empty string returns None."""
        assert _normalize_optional_string("") is None

    def test_whitespace_only(self):
        """Test whitespace-only string returns None."""
        assert _normalize_optional_string("   ") is None
        assert _normalize_optional_string("\t\n") is None

    def test_valid_string(self):
        """Test valid string is stripped and returned."""
        assert _normalize_optional_string("hello") == "hello"
        assert _normalize_optional_string("  hello  ") == "hello"
        assert _normalize_optional_string("\thello\n") == "hello"

    def test_numeric_input(self):
        """Test numeric input is converted to string."""
        assert _normalize_optional_string(123) == "123"
        assert _normalize_optional_string(0) == "0"


class TestRequireField:
    """Tests for _require_field helper."""

    def test_valid_value(self):
        """Test valid value passes through."""

        def dummy_validator(v):
            return v if v else None

        result = _require_field("test", dummy_validator, "test_field")
        assert result == "test"

    def test_empty_value_raises(self):
        """Test empty value raises ValueError."""

        def dummy_validator(v):
            return None

        with pytest.raises(ValueError, match="test_field cannot be empty"):
            _require_field("", dummy_validator, "test_field")


class TestValidateIpAddress:
    """Tests for validate_ip_address."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_ip_address(None) is None

    def test_empty_string(self):
        """Test empty string returns None."""
        assert validate_ip_address("") is None
        assert validate_ip_address("   ") is None

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip_address("192.168.1.1") == "192.168.1.1"
        assert validate_ip_address("10.0.0.1") == "10.0.0.1"
        assert validate_ip_address("255.255.255.255") == "255.255.255.255"
        assert validate_ip_address("0.0.0.0") == "0.0.0.0"

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip_address("2001:db8::1") == "2001:db8::1"
        assert validate_ip_address("::1") == "::1"
        assert validate_ip_address("fe80::1") == "fe80::1"

    def test_invalid_ip(self):
        """Test invalid IP addresses raise ValueError."""
        with pytest.raises(ValueError, match="Invalid IP address format"):
            validate_ip_address("256.1.1.1")

        with pytest.raises(ValueError, match="Invalid IP address format"):
            validate_ip_address("not-an-ip")

        with pytest.raises(ValueError, match="Invalid IP address format"):
            validate_ip_address("192.168.1")

    def test_whitespace_handling(self):
        """Test whitespace is stripped."""
        assert validate_ip_address("  192.168.1.1  ") == "192.168.1.1"


class TestValidateCidr:
    """Tests for validate_cidr."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_cidr(None) is None

    def test_empty_string(self):
        """Test empty string returns None."""
        assert validate_cidr("") is None

    def test_valid_ipv4_cidr(self):
        """Test valid IPv4 CIDR notation."""
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"
        assert validate_cidr("10.0.0.0/8") == "10.0.0.0/8"
        assert validate_cidr("172.16.0.0/12") == "172.16.0.0/12"

    def test_valid_ipv6_cidr(self):
        """Test valid IPv6 CIDR notation."""
        assert validate_cidr("2001:db8::/32") == "2001:db8::/32"
        assert validate_cidr("fe80::/10") == "fe80::/10"

    def test_missing_slash(self):
        """Test missing slash raises ValueError."""
        with pytest.raises(ValueError, match="CIDR notation required"):
            validate_cidr("192.168.1.0")

    def test_invalid_cidr(self):
        """Test invalid CIDR raises ValueError."""
        with pytest.raises(ValueError, match="Invalid CIDR format"):
            validate_cidr("192.168.1.0/33")

        with pytest.raises(ValueError, match="Invalid CIDR format"):
            validate_cidr("not-a-cidr/24")


class TestValidateIpOrCidrAsCidr:
    """Tests for validate_ip_or_cidr_as_cidr."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_ip_or_cidr_as_cidr(None) is None

    def test_plain_ipv4_normalized(self):
        """Test plain IPv4 is normalized to /32."""
        assert validate_ip_or_cidr_as_cidr("192.168.1.1") == "192.168.1.1/32"
        assert validate_ip_or_cidr_as_cidr("10.0.0.1") == "10.0.0.1/32"

    def test_plain_ipv6_normalized(self):
        """Test plain IPv6 is normalized to /128."""
        assert validate_ip_or_cidr_as_cidr("2001:db8::1") == "2001:db8::1/128"
        assert validate_ip_or_cidr_as_cidr("::1") == "::1/128"

    def test_ipv4_cidr_validated(self):
        """Test IPv4 CIDR is validated and returned."""
        result = validate_ip_or_cidr_as_cidr("192.168.1.0/24")
        assert result == "192.168.1.0/24"

    def test_ipv6_cidr_validated(self):
        """Test IPv6 CIDR is validated and returned."""
        result = validate_ip_or_cidr_as_cidr("2001:db8::/32")
        assert result == "2001:db8::/32"

    def test_invalid_ip(self):
        """Test invalid IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IP address format"):
            validate_ip_or_cidr_as_cidr("not-an-ip")

    def test_invalid_cidr(self):
        """Test invalid CIDR raises ValueError."""
        with pytest.raises(ValueError, match="Invalid CIDR format"):
            validate_ip_or_cidr_as_cidr("192.168.1.0/33")


class TestValidateHostname:
    """Tests for validate_hostname."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_hostname(None) is None

    def test_empty_string(self):
        """Test empty string returns None."""
        assert validate_hostname("") is None

    def test_valid_hostnames(self):
        """Test valid hostnames."""
        assert validate_hostname("switch1") == "switch1"
        assert validate_hostname("my-switch") == "my-switch"
        assert validate_hostname("switch_1") == "switch_1"
        assert validate_hostname("switch.example.com") == "switch.example.com"
        assert validate_hostname("SW01-LEAF-01") == "SW01-LEAF-01"

    def test_too_long(self):
        """Test hostname exceeding 255 characters."""
        long_name = "a" * 256
        with pytest.raises(ValueError, match="cannot exceed 255 characters"):
            validate_hostname(long_name)

    def test_invalid_start(self):
        """Test hostname starting with invalid character."""
        with pytest.raises(ValueError, match="Must start with alphanumeric"):
            validate_hostname("-switch")

        with pytest.raises(ValueError, match="Must start with alphanumeric"):
            validate_hostname(".switch")

    def test_invalid_characters(self):
        """Test hostname with invalid characters."""
        with pytest.raises(ValueError, match="Must start with alphanumeric"):
            validate_hostname("switch@host")

    def test_ending_with_dot(self):
        """Test hostname ending with dot."""
        with pytest.raises(ValueError, match="Cannot end with dot"):
            validate_hostname("switch.")

    def test_consecutive_dots(self):
        """Test hostname with consecutive dots."""
        with pytest.raises(ValueError, match="consecutive dots"):
            validate_hostname("switch..example.com")


class TestValidateMacAddress:
    """Tests for validate_mac_address."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_mac_address(None) is None

    def test_empty_string(self):
        """Test empty string returns None."""
        assert validate_mac_address("") is None

    def test_colon_separated(self):
        """Test colon-separated format."""
        assert validate_mac_address("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
        assert validate_mac_address("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
        assert validate_mac_address("00:11:22:33:44:55") == "00:11:22:33:44:55"

    def test_hyphen_separated(self):
        """Test hyphen-separated format."""
        assert validate_mac_address("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"
        assert validate_mac_address("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"

    def test_cisco_dot_notation(self):
        """Test Cisco dot notation format."""
        assert validate_mac_address("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
        assert validate_mac_address("AABB.CCDD.EEFF") == "AA:BB:CC:DD:EE:FF"

    def test_bare_hex(self):
        """Test bare hex format."""
        assert validate_mac_address("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
        assert validate_mac_address("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    def test_mixed_case(self):
        """Test mixed case normalization."""
        assert validate_mac_address("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:FF"

    def test_invalid_length(self):
        """Test invalid MAC address length."""
        with pytest.raises(ValueError, match="Invalid MAC address format"):
            validate_mac_address("AA:BB:CC:DD:EE")

        with pytest.raises(ValueError, match="Invalid MAC address format"):
            validate_mac_address("AA:BB:CC:DD:EE:FF:00")

    def test_invalid_characters(self):
        """Test invalid characters in MAC address."""
        with pytest.raises(ValueError, match="Invalid MAC address format"):
            validate_mac_address("GG:HH:II:JJ:KK:LL")

        with pytest.raises(ValueError, match="Invalid MAC address format"):
            validate_mac_address("not-a-mac")


class TestRequireValidators:
    """Tests for require_* validators."""

    def test_require_ip_address_valid(self):
        """Test require_ip_address with valid IP."""
        assert require_ip_address("192.168.1.1") == "192.168.1.1"

    def test_require_ip_address_empty(self):
        """Test require_ip_address with empty value."""
        with pytest.raises(ValueError, match="IP address cannot be empty"):
            require_ip_address("")

    def test_require_hostname_valid(self):
        """Test require_hostname with valid hostname."""
        assert require_hostname("switch1") == "switch1"

    def test_require_hostname_empty(self):
        """Test require_hostname with empty value."""
        with pytest.raises(ValueError, match="hostname cannot be empty"):
            require_hostname("")

    def test_require_mac_address_valid(self):
        """Test require_mac_address with valid MAC."""
        assert require_mac_address("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_require_mac_address_empty(self):
        """Test require_mac_address with empty value."""
        with pytest.raises(ValueError, match="MAC address cannot be empty"):
            require_mac_address("")

    def test_require_ip_or_cidr_as_cidr_valid(self):
        """Test require_ip_or_cidr_as_cidr with valid IP."""
        assert require_ip_or_cidr_as_cidr("192.168.1.1") == "192.168.1.1/32"

    def test_require_ip_or_cidr_as_cidr_empty(self):
        """Test require_ip_or_cidr_as_cidr with empty value."""
        with pytest.raises(ValueError, match="IP or CIDR cannot be empty"):
            require_ip_or_cidr_as_cidr("")


class TestValidateCidrOptional:
    """Tests for validate_cidr_optional."""

    def test_none_input(self):
        """Test None input returns None."""
        assert validate_cidr_optional(None) is None

    def test_valid_cidr(self):
        """Test valid CIDR passes through."""
        assert validate_cidr_optional("192.168.1.0/24") == "192.168.1.0/24"

    def test_empty_raises(self):
        """Test empty string raises ValueError."""
        with pytest.raises(ValueError, match="CIDR cannot be empty"):
            validate_cidr_optional("")


class TestCheckCredentialsPair:
    """Tests for check_credentials_pair."""

    def test_both_none(self):
        """Test both username and password are None."""
        # Should not raise
        check_credentials_pair(None, None)

    def test_both_present(self):
        """Test both username and password are present."""
        # Should not raise
        check_credentials_pair("admin", "password123")

    def test_both_empty_strings(self):
        """Test both are empty strings (falsy)."""
        # Should not raise
        check_credentials_pair("", "")

    def test_username_only(self):
        """Test only username is provided."""
        with pytest.raises(ValueError, match="password must be set when username is specified"):
            check_credentials_pair("admin", None)

    def test_password_only(self):
        """Test only password is provided."""
        with pytest.raises(ValueError, match="username must be set when password is specified"):
            check_credentials_pair(None, "password123")

    def test_custom_field_names(self):
        """Test custom field names in error messages."""
        with pytest.raises(ValueError, match="api_password must be set when api_username is specified"):
            check_credentials_pair("admin", None, "api_username", "api_password")

        with pytest.raises(ValueError, match="api_username must be set when api_password is specified"):
            check_credentials_pair(None, "password", "api_username", "api_password")
