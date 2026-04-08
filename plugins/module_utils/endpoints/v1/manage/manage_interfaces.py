# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Interfaces endpoint models.

This module contains endpoint definitions for interface operations
in the ND Manage API.

## Endpoints

- `EpManageInterfacesGet` - Get a specific interface
  (GET /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces/{interface_name})
- `EpManageInterfacesListGet` - List all interfaces on a switch
  (GET /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces)
- `EpManageInterfacesPost` - Create interfaces on a switch
  (POST /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces)
- `EpManageInterfacesPut` - Update a specific interface
  (PUT /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces/{interface_name})
- `EpManageInterfacesDelete` - Delete a virtual interface (loopback, SVI); not supported for physical ethernet
  (DELETE /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces/{interface_name})
- `EpManageInterfacesDeploy` - Deploy interface configurations
  (POST /api/v1/manage/fabrics/{fabric_name}/interfaceActions/deploy)
- `EpManageInterfacesNormalize` - Reset physical interface configurations to default
  (POST /api/v1/manage/fabrics/{fabric_name}/interfaceActions/normalize)
- `EpManageInterfacesRemove` - Bulk delete interfaces
  (POST /api/v1/manage/fabrics/{fabric_name}/interfaceActions/remove)
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
    InterfaceNameMixin,
    SwitchSerialNumberMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageInterfacesBase(FabricNameMixin, SwitchSerialNumberMixin, InterfaceNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Base class for ND Manage Interfaces endpoints.

    Provides common functionality for all HTTP methods on the
    `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces` endpoint.
    Subclasses define the HTTP verb and optionally override `_require_interface_name`.

    ## Raises

    ### ValueError

    - If `fabric_name` is not set before accessing `path`.
    - If `switch_sn` is not set before accessing `path`.
    - If `_require_interface_name` is True and `interface_name` is not set before accessing `path`.
    """

    _require_interface_name: ClassVar[bool] = True

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path for manage interfaces operations.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        - If `switch_sn` is not set before accessing `path`.
        - If `_require_interface_name` is True and `interface_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self.switch_sn is None:
            raise ValueError(f"{type(self).__name__}.path: switch_sn must be set before accessing path.")
        if self._require_interface_name and self.interface_name is None:
            raise ValueError(f"{type(self).__name__}.path: interface_name must be set before accessing path.")

        segments = ["fabrics", self.fabric_name, "switches", self.switch_sn, "interfaces"]
        if self.interface_name is not None:
            segments.append(self.interface_name)
        return BasePath.path(*segments)

    def set_identifiers(self, identifier: IdentifierKey = None):
        """
        # Summary

        Set `interface_name` from `identifier`. `fabric_name` and `switch_sn` must be set separately via `_configure_endpoint`.

        ## Raises

        None
        """
        self.interface_name = identifier


class EpManageInterfacesGet(_EpManageInterfacesBase):
    """
    # Summary

    Retrieve a specific interface by name.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces/{interface_name}`
    - Verb: GET

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name`, `switch_sn`, or `interface_name` is not set.
    """

    class_name: Literal["EpManageInterfacesGet"] = Field(default="EpManageInterfacesGet", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET


class EpManageInterfacesListGet(_EpManageInterfacesBase):
    """
    # Summary

    List all interfaces on a switch.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces`
    - Verb: GET

    Does not require `interface_name` to be set.

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name` or `switch_sn` is not set.
    """

    _require_interface_name: ClassVar[bool] = False

    class_name: Literal["EpManageInterfacesListGet"] = Field(
        default="EpManageInterfacesListGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET


class EpManageInterfacesPost(_EpManageInterfacesBase):
    """
    # Summary

    Create one or more interfaces on a switch.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces`
    - Verb: POST

    Does not require `interface_name` to be set.

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name` or `switch_sn` is not set.
    """

    _require_interface_name: ClassVar[bool] = False

    class_name: Literal["EpManageInterfacesPost"] = Field(default="EpManageInterfacesPost", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST


class EpManageInterfacesPut(_EpManageInterfacesBase):
    """
    # Summary

    Update a specific interface.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces/{interface_name}`
    - Verb: PUT

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name`, `switch_sn`, or `interface_name` is not set.
    """

    class_name: Literal["EpManageInterfacesPut"] = Field(default="EpManageInterfacesPut", frozen=True, description="Class name for backward compatibility")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.PUT`.

        ## Raises

        None
        """
        return HttpVerbEnum.PUT


class EpManageInterfacesDelete(_EpManageInterfacesBase):
    """
    # Summary

    Delete a specific interface configuration.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/interfaces/{interface_name}`
    - Verb: DELETE

    This endpoint works for virtual interfaces (loopback, SVI) only. For physical ethernet interfaces,
    the API returns HTTP 500 ("Interface cannot be deleted!!!"). Use `EpManageInterfacesNormalize` instead
    to reset physical interfaces to their default state.

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name`, `switch_sn`, or `interface_name` is not set.
    """

    class_name: Literal["EpManageInterfacesDelete"] = Field(
        default="EpManageInterfacesDelete", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.DELETE`.

        ## Raises

        None
        """
        return HttpVerbEnum.DELETE


class EpManageInterfacesDeploy(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Deploy interface configurations to switches.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/interfaceActions/deploy`
    - Verb: POST
    - Body: `{"interfaces": [{"interfaceName": "...", "switchId": "..."}]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpManageInterfacesDeploy"] = Field(
        default="EpManageInterfacesDeploy", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the deploy endpoint path.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", self.fabric_name, "interfaceActions", "deploy")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST


class EpManageInterfacesNormalize(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Normalize (reset) interface configurations on switches.

    For physical ethernet interfaces, this is the API equivalent of the NX-OS `default interface` CLI command.
    Unlike `interfaceActions/remove` (which silently does nothing for ethernet) and `DELETE` (which returns 500),
    normalize actually resets the interface configuration.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/interfaceActions/normalize`
    - Verb: POST
    - Body: `{"interfaceType": "ethernet", "configData": {...}, "switchInterfaces": [{"interfaceName": "...", "switchId": "..."}]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpManageInterfacesNormalize"] = Field(
        default="EpManageInterfacesNormalize", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the normalize endpoint path.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", self.fabric_name, "interfaceActions", "normalize")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST


class EpManageInterfacesRemove(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Bulk delete interfaces across one or more switches.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/interfaceActions/remove`
    - Verb: POST
    - Body: `{"interfaces": [{"interfaceName": "...", "switchId": "..."}]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpManageInterfacesRemove"] = Field(
        default="EpManageInterfacesRemove", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the bulk remove endpoint path.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", self.fabric_name, "interfaceActions", "remove")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST
