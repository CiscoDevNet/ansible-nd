# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for NDEndpointBaseModel.__init_subclass__()

Tests the class_name enforcement logic that ensures concrete
subclasses of NDEndpointBaseModel define a class_name field.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

# pylint: disable=unused-import
# pylint: disable=unused-variable
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=too-few-public-methods

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: __init_subclass__ — concrete subclass with class_name
# =============================================================================


def test_base_model_00100():
    """
    # Summary

    Verify a concrete subclass with `class_name` defined is accepted.

    ## Test

    - Concrete subclass defines `class_name`, `path`, and `verb`
    - Class definition succeeds without error
    - Instance can be created and `class_name` is correct

    ## Classes and Methods

    - NDEndpointBaseModel.__init_subclass__()
    """

    class _GoodEndpoint(NDEndpointBaseModel):
        class_name: Literal["_GoodEndpoint"] = Field(default="_GoodEndpoint", frozen=True, description="Class name")

        @property
        def path(self) -> str:
            return "/api/v1/test/good"

        @property
        def verb(self) -> HttpVerbEnum:
            return HttpVerbEnum.GET

    with does_not_raise():
        instance = _GoodEndpoint()
    assert instance.class_name == "_GoodEndpoint"


# =============================================================================
# Test: __init_subclass__ — concrete subclass missing class_name
# =============================================================================


def test_base_model_00200():
    """
    # Summary

    Verify a concrete subclass without `class_name` raises `TypeError` at class definition time.

    ## Test

    - Concrete subclass defines `path` and `verb` but omits `class_name`
    - `TypeError` is raised when the class is defined (not when instantiated)

    ## Classes and Methods

    - NDEndpointBaseModel.__init_subclass__()
    """
    match = r"_BadEndpoint must define a 'class_name' field"
    with pytest.raises(TypeError, match=match):

        class _BadEndpoint(NDEndpointBaseModel):

            @property
            def path(self) -> str:
                return "/api/v1/test/bad"

            @property
            def verb(self) -> HttpVerbEnum:
                return HttpVerbEnum.GET


# =============================================================================
# Test: __init_subclass__ — intermediate abstract subclass skipped
# =============================================================================


def test_base_model_00300():
    """
    # Summary

    Verify an intermediate abstract subclass without `class_name` is allowed.

    ## Test

    - Intermediate ABC adds a new abstract method but does not define `class_name`
    - No `TypeError` is raised at class definition time
    - A concrete subclass of the intermediate ABC with `class_name` can be instantiated

    ## Classes and Methods

    - NDEndpointBaseModel.__init_subclass__()
    """

    class _MiddleABC(NDEndpointBaseModel, ABC):

        @property
        @abstractmethod
        def extra(self) -> str:
            """Return extra info."""

    class _ConcreteFromMiddle(_MiddleABC):
        class_name: Literal["_ConcreteFromMiddle"] = Field(default="_ConcreteFromMiddle", frozen=True, description="Class name")

        @property
        def path(self) -> str:
            return "/api/v1/test/middle"

        @property
        def verb(self) -> HttpVerbEnum:
            return HttpVerbEnum.GET

        @property
        def extra(self) -> str:
            return "extra"

    with does_not_raise():
        instance = _ConcreteFromMiddle()
    assert instance.class_name == "_ConcreteFromMiddle"
    assert instance.extra == "extra"


# =============================================================================
# Test: __init_subclass__ — concrete subclass of intermediate ABC missing class_name
# =============================================================================


def test_base_model_00310():
    """
    # Summary

    Verify a concrete subclass of an intermediate ABC without `class_name` raises `TypeError`.

    ## Test

    - Intermediate ABC adds a new abstract method
    - Concrete subclass implements all abstract methods but omits `class_name`
    - `TypeError` is raised at class definition time

    ## Classes and Methods

    - NDEndpointBaseModel.__init_subclass__()
    """

    class _MiddleABC2(NDEndpointBaseModel, ABC):

        @property
        @abstractmethod
        def extra(self) -> str:
            """Return extra info."""

    match = r"_BadConcreteFromMiddle must define a 'class_name' field"
    with pytest.raises(TypeError, match=match):

        class _BadConcreteFromMiddle(_MiddleABC2):

            @property
            def path(self) -> str:
                return "/api/v1/test/bad-middle"

            @property
            def verb(self) -> HttpVerbEnum:
                return HttpVerbEnum.GET

            @property
            def extra(self) -> str:
                return "extra"


# =============================================================================
# Test: __init_subclass__ — error message includes example
# =============================================================================


def test_base_model_00400():
    """
    # Summary

    Verify the `TypeError` message includes a helpful example with the class name.

    ## Test

    - Concrete subclass omits `class_name`
    - Error message contains the class name in the `Literal` and `Field` example

    ## Classes and Methods

    - NDEndpointBaseModel.__init_subclass__()
    """
    with pytest.raises(TypeError, match=r'Literal\["_ExampleEndpoint"\]') as exc_info:

        class _ExampleEndpoint(NDEndpointBaseModel):

            @property
            def path(self) -> str:
                return "/api/v1/test/example"

            @property
            def verb(self) -> HttpVerbEnum:
                return HttpVerbEnum.GET

    assert "_ExampleEndpoint" in str(exc_info.value)
    assert "frozen=True" in str(exc_info.value)
