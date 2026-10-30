# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from collections.abc import Sequence
from functools import wraps
from typing import Any, ClassVar, Generic, TypeVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import model_validator
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.request_base import NDRequestBase
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = TypeVar("ModelType", bound=NDBaseModel)


def requires_bulk_support(flag_name: str):
    """Decorator that restricts method access based on a ClassVar boolean flag."""

    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            if not getattr(self, flag_name, False):
                raise AttributeError(f"'{method.__name__}' is not available when '{flag_name}' is disabled on '{self.__class__.__name__}'.")
            return method(self, *args, **kwargs)

        return wrapper

    return decorator


class NDBaseOrchestrator(NDRequestBase, Generic[ModelType]):
    """
    # Summary

    Generic CRUD orchestrator for a resource-backed ND endpoint family. Inherits `rest_send`, `results`, `_request` and
    `_register_api_call` from `NDRequestBase` and adds the endpoint fields plus the create/update/delete/query operations.

    ## Raises

    ### RuntimeError

    - Via `_request` if the controller returns a non-success result.
    """

    model_class: ClassVar[type[NDBaseModel]] = NDBaseModel
    supports_bulk_create: ClassVar[bool] = False
    supports_bulk_delete: ClassVar[bool] = False

    # bulk_payload_key is the JSON wrapper key the bulk endpoint expects,
    # e.g. "links" for /api/v1/manage/links POST.
    bulk_payload_key: ClassVar[str] = "items"

    # NOTE: if not defined by subclasses, return an error as they are required
    create_endpoint: type[NDEndpointBaseModel]
    update_endpoint: type[NDEndpointBaseModel]
    delete_endpoint: type[NDEndpointBaseModel]
    query_one_endpoint: type[NDEndpointBaseModel]
    query_all_endpoint: type[NDEndpointBaseModel]

    # NOTE: Conditionally required
    create_bulk_endpoint: type[NDEndpointBaseModel] | None = None
    delete_bulk_endpoint: type[NDEndpointBaseModel] | None = None

    def preflight(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-mutation hook invoked by `NDStateMachine` before create/update operations — which are skipped in check
        mode — so subclasses can validate the proposed set during a dry-run. Base implementation is a no-op;
        interface orchestrators override to run capability preflight.

        ## Raises

        None
        """
        return

    def preflight_create(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-mutation hook invoked by `NDStateMachine` with only the items diffed as create (`new`) — before any
        create/update API call, so it fails fast in check mode too. Distinct from `preflight`, which receives the
        full proposed set; this hook sees the create-only subset so subclasses can enforce create-specific
        requirements without rejecting legitimate policy-less updates. Base implementation is a no-op; interface
        orchestrators override to require a policy on create.

        ## Raises

        None
        """
        return

    def preflight_delete(self, model_instances: Sequence[ModelType]) -> None:
        """
        # Summary

        Pre-mutation hook invoked by `NDStateMachine` for `state: deleted` with the existing items about to be deleted —
        before any delete API call, which is skipped in check mode — so subclasses can reject a delete during a dry-run
        exactly as a normal run would (e.g. ethernet refuses to normalize a port-channel member, or links reject an
        ambiguous controller identity). This is distinct from the capability `preflight` hook because deletion does not
        require switch capability validation. Not invoked for the fabric-wide `overridden` delete set. Base implementation
        is a no-op.

        ## Raises

        None
        """
        return

    def prepare_mutations(self, existing, proposed, check_mode: bool = False) -> None:
        """
        # Summary

        Optional hook invoked after all preflight checks succeed and immediately
        before create/update reconciliation begins.

        Subclasses can use this for ordered prerequisite mutations that cannot
        be represented as a single resource update. The base implementation is
        a no-op. Implementations must update ``existing`` in check mode as if
        the prerequisite mutation succeeded so the predicted ``after`` state
        remains accurate.

        ## Raises

        None
        """
        return

    def reconcile_no_diff(self, model_instances: Sequence[ModelType]) -> bool:
        """Reconcile execution-side state for proposed objects with no intent diff.

        Most resources have no action to perform when controller intent already
        matches the proposal.  Orchestrators whose requested action has a
        separate execution phase may override this hook.  Interface
        orchestrators use it to recover a prior accepted-but-not-yet-deployed
        intent when ``deploy: true`` is replayed.

        ## Raises

        None
        """
        return False

    def reconcile_absent_deletes(self, model_instances: Sequence[ModelType]) -> bool:
        """Reconcile execution-side state for explicitly deleted absent objects.

        Most resources have no action to perform after controller intent is
        already absent.  Resources with a separate deployment phase may
        override this hook to detect and recover an accepted-but-not-deployed
        deletion.  Return whether a normal run performs, or check mode would
        perform, an execution-side change.

        ## Raises

        None
        """

        return False

    # NOTE: Generic CRUD API operations for simple endpoints with single identifier (e.g. "api/v1/infra/aaa/LocalUsers/{loginID}")
    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.create_endpoint()
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload(), operation_type=OperationType.CREATE)
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=model_instance.to_payload(), operation_type=OperationType.UPDATE)
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.delete_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, operation_type=OperationType.DELETE)
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.query_one_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: ModelType | None = None, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.query_all_endpoint()
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            return result or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def prepare_config_data(self, raw_config):
        """Hook for subclasses to backfill or normalize raw user config before the proposed collection is built. Returns the list unchanged by default."""
        return raw_config

    @model_validator(mode="after")
    def validate_bulk_endpoints(self):
        if self.supports_bulk_create and self.create_bulk_endpoint is None:
            raise ValueError(f"'{self.__class__.__name__}' has 'supports_bulk_create=True' but 'create_bulk_endpoint' is not defined.")
        if self.supports_bulk_delete and self.delete_bulk_endpoint is None:
            raise ValueError(f"'{self.__class__.__name__}' has 'supports_bulk_delete=True' but 'delete_bulk_endpoint' is not defined.")
        return self

    def _post_bulk(self, endpoint: NDEndpointBaseModel, items: list[Any], operation_type: OperationType = OperationType.QUERY) -> dict[str, Any]:
        """POST a bulk payload as a single request through the RestSend pipeline.

        Wraps ``items`` under ``bulk_payload_key`` and sends one POST so the
        response_handler and result aggregation run as usual.  The response has
        the same shape the bulk endpoint returns
        (``{bulk_payload_key: [<items in input order>]}``), so the existing
        per-item failure surfacing (``_raise_on_bulk_failures``) works unchanged.

        ``operation_type`` is forwarded to ``_request`` so bulk writes are
        registered with the correct action (CREATE/DELETE) instead of QUERY.
        """
        if not items:
            return {}

        payload_key = self.bulk_payload_key
        return self._request(endpoint.path, endpoint.verb, data={payload_key: items}, operation_type=operation_type) or {}

    @requires_bulk_support("supports_bulk_create")
    def create_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        raise NotImplementedError

    @requires_bulk_support("supports_bulk_delete")
    def delete_bulk(self, model_instances: list[ModelType], **kwargs) -> ResponseType:
        raise NotImplementedError
