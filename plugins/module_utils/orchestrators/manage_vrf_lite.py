# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpFabricVrfsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_attachments import (
    EpFabricVrfsAttachmentsGet,
    EpFabricVrfsAttachmentsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    custom_vrf_lite_create,
    custom_vrf_lite_delete,
    custom_vrf_lite_update,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    custom_vrf_lite_query_all,
)


class _VrfLiteQueryContext:
    """Minimal context object exposing .module for custom query flows."""

    def __init__(self, module: Any) -> None:
        self.module = module


class ManageVrfLiteOrchestrator(NDBaseOrchestrator):
    """Orchestrator wiring NDStateMachine to VRF Lite action handlers."""

    model_class: ClassVar[type[NDBaseModel]] = VrfLiteModel

    # Endpoint classes document the controller surface used by the custom
    # handlers below.  VRF Lite attach/detach is a POST-based sub-resource API,
    # so generic CRUD methods are intentionally overridden.
    create_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsPost
    update_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsPost
    delete_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsPost
    query_one_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsGet

    def _module(self) -> Any:
        # TODO: Remove direct AnsibleModule access after custom orchestrator
        # hooks can pass runtime context without reaching through rest_send.
        return self.rest_send.sender.ansible_module

    def query_all(self) -> list[dict[str, Any]]:
        module = self._module()
        return custom_vrf_lite_query_all(_VrfLiteQueryContext(module))

    def create(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        module = self._module()
        return custom_vrf_lite_create(model_instance=model_instance, module=module)

    def update(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        module = self._module()
        return custom_vrf_lite_update(model_instance=model_instance, module=module)

    def delete(self, model_instance: Any, **kwargs: Any) -> bool:
        del kwargs
        module = self._module()
        return custom_vrf_lite_delete(model_instance=model_instance, module=module)
