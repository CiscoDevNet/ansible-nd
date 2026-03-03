# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for query_params.py

Tests the query parameter composition classes
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import BooleanStringEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.query_params import (
    CompositeQueryParams,
    EndpointQueryParams,
    LuceneQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import Field
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Helper test class for EndpointQueryParams
# =============================================================================


class SampleEndpointParams(EndpointQueryParams):
    """Sample implementation of EndpointQueryParams for testing."""

    force_show_run: BooleanStringEnum | None = Field(default=None)
    fabric_name: str | None = Field(default=None)
    switch_count: int | None = Field(default=None)


# =============================================================================
# Test: EndpointQueryParams
# =============================================================================


def test_query_params_00010():
    """
    # Summary

    Verify EndpointQueryParams default implementation

    ## Test

    - to_query_string() returns empty string when no params set

    ## Classes and Methods

    - EndpointQueryParams.to_query_string()
    """
    with does_not_raise():
        params = SampleEndpointParams()
        result = params.to_query_string()
    # Only non-None, non-default values are included
    assert result == ""


def test_query_params_00020():
    """
    # Summary

    Verify EndpointQueryParams snake_case to camelCase conversion

    ## Test

    - force_show_run converts to forceShowRun
    - fabric_name converts to fabricName

    ## Classes and Methods

    - EndpointQueryParams.to_query_string()
    - EndpointQueryParams._to_camel_case()
    """
    with does_not_raise():
        params = SampleEndpointParams(force_show_run=BooleanStringEnum.TRUE, fabric_name="Fabric1")
        result = params.to_query_string()
    assert "forceShowRun=" in result
    assert "fabricName=" in result
    # Verify no snake_case
    assert "force_show_run" not in result
    assert "fabric_name" not in result


def test_query_params_00030():
    """
    # Summary

    Verify EndpointQueryParams handles Enum values

    ## Test

    - BooleanStringEnum.TRUE converts to "true"
    - BooleanStringEnum.FALSE converts to "false"

    ## Classes and Methods

    - EndpointQueryParams.to_query_string()
    """
    with does_not_raise():
        params = SampleEndpointParams(force_show_run=BooleanStringEnum.TRUE)
        result = params.to_query_string()
    assert "forceShowRun=true" in result


def test_query_params_00040():
    """
    # Summary

    Verify EndpointQueryParams handles integer values

    ## Test

    - Integer values are converted to strings

    ## Classes and Methods

    - EndpointQueryParams.to_query_string()
    """
    with does_not_raise():
        params = SampleEndpointParams(switch_count=42)
        result = params.to_query_string()
    assert result == "switchCount=42"


def test_query_params_00050():
    """
    # Summary

    Verify EndpointQueryParams handles string values

    ## Test

    - String values are included as-is

    ## Classes and Methods

    - EndpointQueryParams.to_query_string()
    """
    with does_not_raise():
        params = SampleEndpointParams(fabric_name="MyFabric")
        result = params.to_query_string()
    assert result == "fabricName=MyFabric"


def test_query_params_00060():
    """
    # Summary

    Verify EndpointQueryParams handles multiple params

    ## Test

    - Multiple parameters are joined with '&'

    ## Classes and Methods

    - EndpointQueryParams.to_query_string()
    """
    with does_not_raise():
        params = SampleEndpointParams(force_show_run=BooleanStringEnum.TRUE, fabric_name="Fabric1", switch_count=10)
        result = params.to_query_string()
    assert "forceShowRun=true" in result
    assert "fabricName=Fabric1" in result
    assert "switchCount=10" in result
    assert result.count("&") == 2


def test_query_params_00070():
    """
    # Summary

    Verify EndpointQueryParams is_empty() method

    ## Test

    - is_empty() returns True when no params set
    - is_empty() returns False when params are set

    ## Classes and Methods

    - EndpointQueryParams.is_empty()
    """
    with does_not_raise():
        params = SampleEndpointParams()
        assert params.is_empty() is True

        params.fabric_name = "Fabric1"
        assert params.is_empty() is False


def test_query_params_00080():
    """
    # Summary

    Verify EndpointQueryParams _to_camel_case() static method

    ## Test

    - Correctly converts various snake_case strings to camelCase

    ## Classes and Methods

    - EndpointQueryParams._to_camel_case()
    """
    with does_not_raise():
        assert EndpointQueryParams._to_camel_case("simple") == "simple"
        assert EndpointQueryParams._to_camel_case("snake_case") == "snakeCase"
        assert EndpointQueryParams._to_camel_case("long_snake_case_name") == "longSnakeCaseName"
        assert EndpointQueryParams._to_camel_case("single") == "single"


# =============================================================================
# Test: LuceneQueryParams
# =============================================================================


def test_query_params_00100():
    """
    # Summary

    Verify LuceneQueryParams default values

    ## Test

    - All parameters default to None

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    """
    with does_not_raise():
        params = LuceneQueryParams()
    assert params.filter is None
    assert params.max is None
    assert params.offset is None
    assert params.sort is None
    assert params.fields is None


def test_query_params_00110():
    """
    # Summary

    Verify LuceneQueryParams filter parameter

    ## Test

    - filter can be set to a string value
    - to_query_string() includes filter parameter

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(filter="name:MyFabric")
        result = params.to_query_string()
    assert "filter=" in result
    assert "name" in result
    assert "MyFabric" in result


def test_query_params_00120():
    """
    # Summary

    Verify LuceneQueryParams max parameter

    ## Test

    - max can be set to an integer value
    - to_query_string() includes max parameter

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(max=100)
        result = params.to_query_string()
    assert result == "max=100"


def test_query_params_00130():
    """
    # Summary

    Verify LuceneQueryParams offset parameter

    ## Test

    - offset can be set to an integer value
    - to_query_string() includes offset parameter

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(offset=20)
        result = params.to_query_string()
    assert result == "offset=20"


def test_query_params_00140():
    """
    # Summary

    Verify LuceneQueryParams sort parameter

    ## Test

    - sort can be set to a valid string
    - to_query_string() includes sort parameter

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(sort="name:asc")
        result = params.to_query_string()
    assert "sort=" in result
    assert "name" in result


def test_query_params_00150():
    """
    # Summary

    Verify LuceneQueryParams fields parameter

    ## Test

    - fields can be set to a comma-separated string
    - to_query_string() includes fields parameter

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(fields="name,id,status")
        result = params.to_query_string()
    assert "fields=" in result


def test_query_params_00160():
    """
    # Summary

    Verify LuceneQueryParams URL encoding

    ## Test

    - Special characters in filter are URL-encoded by default

    ## Classes and Methods

    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(filter="name:Fabric* AND status:active")
        result = params.to_query_string(url_encode=True)
    # Check for URL-encoded characters
    assert "filter=" in result
    # Space should be encoded
    assert "%20" in result or "+" in result


def test_query_params_00170():
    """
    # Summary

    Verify LuceneQueryParams URL encoding can be disabled

    ## Test

    - url_encode=False preserves special characters

    ## Classes and Methods

    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(filter="name:Fabric* AND status:active")
        result = params.to_query_string(url_encode=False)
    assert result == "filter=name:Fabric* AND status:active"


def test_query_params_00180():
    """
    # Summary

    Verify LuceneQueryParams is_empty() method

    ## Test

    - is_empty() returns True when no params set
    - is_empty() returns False when params are set

    ## Classes and Methods

    - LuceneQueryParams.is_empty()
    """
    with does_not_raise():
        params = LuceneQueryParams()
        assert params.is_empty() is True

        params.max = 100
        assert params.is_empty() is False


def test_query_params_00190():
    """
    # Summary

    Verify LuceneQueryParams multiple parameters

    ## Test

    - Multiple parameters are joined with '&'
    - Parameters appear in expected order

    ## Classes and Methods

    - LuceneQueryParams.to_query_string()
    """
    with does_not_raise():
        params = LuceneQueryParams(filter="name:*", max=50, offset=10, sort="name:asc")
        result = params.to_query_string(url_encode=False)
    assert "filter=name:*" in result
    assert "max=50" in result
    assert "offset=10" in result
    assert "sort=name:asc" in result


# =============================================================================
# Test: LuceneQueryParams validation
# =============================================================================


def test_query_params_00200():
    """
    # Summary

    Verify LuceneQueryParams validates max range

    ## Test

    - max must be >= 1
    - max must be <= 10000

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    """
    # Valid values
    with does_not_raise():
        LuceneQueryParams(max=1)
        LuceneQueryParams(max=10000)
        LuceneQueryParams(max=500)

    # Invalid values
    with pytest.raises(ValueError):
        LuceneQueryParams(max=0)

    with pytest.raises(ValueError):
        LuceneQueryParams(max=10001)


def test_query_params_00210():
    """
    # Summary

    Verify LuceneQueryParams validates offset range

    ## Test

    - offset must be >= 0

    ## Classes and Methods

    - LuceneQueryParams.__init__()
    """
    # Valid values
    with does_not_raise():
        LuceneQueryParams(offset=0)
        LuceneQueryParams(offset=100)

    # Invalid values
    with pytest.raises(ValueError):
        LuceneQueryParams(offset=-1)


def test_query_params_00220():
    """
    # Summary

    Verify LuceneQueryParams validates sort format

    ## Test

    - sort direction must be 'asc' or 'desc'
    - Invalid directions are rejected

    ## Classes and Methods

    - LuceneQueryParams.validate_sort()
    """
    # Valid values
    with does_not_raise():
        LuceneQueryParams(sort="name:asc")
        LuceneQueryParams(sort="name:desc")
        LuceneQueryParams(sort="name:ASC")
        LuceneQueryParams(sort="name:DESC")

    # Invalid direction
    with pytest.raises(ValueError, match="Sort direction must be"):
        LuceneQueryParams(sort="name:invalid")


def test_query_params_00230():
    """
    # Summary

    Verify LuceneQueryParams allows sort without direction

    ## Test

    - sort can be set without ':' separator
    - Validation only applies when ':' is present

    ## Classes and Methods

    - LuceneQueryParams.validate_sort()
    """
    with does_not_raise():
        params = LuceneQueryParams(sort="name")
        result = params.to_query_string(url_encode=False)
    assert result == "sort=name"


# =============================================================================
# Test: CompositeQueryParams
# =============================================================================


def test_query_params_00300():
    """
    # Summary

    Verify CompositeQueryParams basic instantiation

    ## Test

    - Instance can be created
    - Starts with empty parameter groups

    ## Classes and Methods

    - CompositeQueryParams.__init__()
    """
    with does_not_raise():
        composite = CompositeQueryParams()
    assert composite.is_empty() is True


def test_query_params_00310():
    """
    # Summary

    Verify CompositeQueryParams add() method

    ## Test

    - Can add EndpointQueryParams
    - Returns self for method chaining

    ## Classes and Methods

    - CompositeQueryParams.add()
    """
    with does_not_raise():
        composite = CompositeQueryParams()
        endpoint_params = SampleEndpointParams(fabric_name="Fabric1")
        result = composite.add(endpoint_params)
    assert result is composite
    assert composite.is_empty() is False


def test_query_params_00320():
    """
    # Summary

    Verify CompositeQueryParams add() with LuceneQueryParams

    ## Test

    - Can add LuceneQueryParams
    - Parameters are combined correctly

    ## Classes and Methods

    - CompositeQueryParams.add()
    - CompositeQueryParams.to_query_string()
    """
    with does_not_raise():
        composite = CompositeQueryParams()
        lucene_params = LuceneQueryParams(max=100)
        composite.add(lucene_params)
        result = composite.to_query_string()
    assert result == "max=100"


def test_query_params_00330():
    """
    # Summary

    Verify CompositeQueryParams method chaining

    ## Test

    - Multiple add() calls can be chained
    - All parameters are included in final query string

    ## Classes and Methods

    - CompositeQueryParams.add()
    - CompositeQueryParams.to_query_string()
    """
    with does_not_raise():
        endpoint_params = SampleEndpointParams(fabric_name="Fabric1")
        lucene_params = LuceneQueryParams(max=50)

        composite = CompositeQueryParams()
        composite.add(endpoint_params).add(lucene_params)

        result = composite.to_query_string()
    assert "fabricName=Fabric1" in result
    assert "max=50" in result


def test_query_params_00340():
    """
    # Summary

    Verify CompositeQueryParams parameter ordering

    ## Test

    - Parameters appear in order they were added
    - EndpointQueryParams before LuceneQueryParams

    ## Classes and Methods

    - CompositeQueryParams.to_query_string()
    """
    with does_not_raise():
        endpoint_params = SampleEndpointParams(fabric_name="Fabric1")
        lucene_params = LuceneQueryParams(max=50)

        composite = CompositeQueryParams()
        composite.add(endpoint_params).add(lucene_params)

        result = composite.to_query_string()

    # fabricName should appear before max
    fabric_pos = result.index("fabricName")
    max_pos = result.index("max")
    assert fabric_pos < max_pos


def test_query_params_00350():
    """
    # Summary

    Verify CompositeQueryParams is_empty() method

    ## Test

    - is_empty() returns True when all groups are empty
    - is_empty() returns False when any group has params

    ## Classes and Methods

    - CompositeQueryParams.is_empty()
    """
    with does_not_raise():
        composite = CompositeQueryParams()
        assert composite.is_empty() is True

        # Add empty parameter group
        empty_params = SampleEndpointParams()
        composite.add(empty_params)
        assert composite.is_empty() is True

        # Add non-empty parameter group
        endpoint_params = SampleEndpointParams(fabric_name="Fabric1")
        composite.add(endpoint_params)
        assert composite.is_empty() is False


def test_query_params_00360():
    """
    # Summary

    Verify CompositeQueryParams clear() method

    ## Test

    - clear() removes all parameter groups
    - is_empty() returns True after clear()

    ## Classes and Methods

    - CompositeQueryParams.clear()
    - CompositeQueryParams.is_empty()
    """
    with does_not_raise():
        composite = CompositeQueryParams()
        endpoint_params = SampleEndpointParams(fabric_name="Fabric1")
        composite.add(endpoint_params)

        assert composite.is_empty() is False

        composite.clear()
        assert composite.is_empty() is True


def test_query_params_00370():
    """
    # Summary

    Verify CompositeQueryParams URL encoding propagation

    ## Test

    - url_encode parameter is passed to LuceneQueryParams
    - EndpointQueryParams not affected (no url_encode parameter)

    ## Classes and Methods

    - CompositeQueryParams.to_query_string()
    """
    with does_not_raise():
        endpoint_params = SampleEndpointParams(fabric_name="My Fabric")
        lucene_params = LuceneQueryParams(filter="name:Test Value")

        composite = CompositeQueryParams()
        composite.add(endpoint_params).add(lucene_params)

        # With URL encoding
        result_encoded = composite.to_query_string(url_encode=True)
        assert "filter=" in result_encoded

        # Without URL encoding
        result_plain = composite.to_query_string(url_encode=False)
        assert "filter=name:Test Value" in result_plain


def test_query_params_00380():
    """
    # Summary

    Verify CompositeQueryParams with empty groups

    ## Test

    - Empty parameter groups are skipped in query string
    - Only non-empty groups contribute to query string

    ## Classes and Methods

    - CompositeQueryParams.to_query_string()
    """
    with does_not_raise():
        empty_endpoint = SampleEndpointParams()
        non_empty_lucene = LuceneQueryParams(max=100)

        composite = CompositeQueryParams()
        composite.add(empty_endpoint).add(non_empty_lucene)

        result = composite.to_query_string()

    # Should only contain the Lucene params
    assert result == "max=100"


# =============================================================================
# Test: Integration scenarios
# =============================================================================


def test_query_params_00400():
    """
    # Summary

    Verify complex query string composition

    ## Test

    - Combine multiple EndpointQueryParams with LuceneQueryParams
    - All parameters are correctly formatted and encoded

    ## Classes and Methods

    - CompositeQueryParams.add()
    - CompositeQueryParams.to_query_string()
    """
    with does_not_raise():
        endpoint_params = SampleEndpointParams(force_show_run=BooleanStringEnum.TRUE, fabric_name="Production", switch_count=5)

        lucene_params = LuceneQueryParams(filter="status:active AND role:leaf", max=100, offset=0, sort="name:asc")

        composite = CompositeQueryParams()
        composite.add(endpoint_params).add(lucene_params)

        result = composite.to_query_string(url_encode=False)

    # Verify all parameters present
    assert "forceShowRun=true" in result
    assert "fabricName=Production" in result
    assert "switchCount=5" in result
    assert "filter=status:active AND role:leaf" in result
    assert "max=100" in result
    assert "offset=0" in result
    assert "sort=name:asc" in result
