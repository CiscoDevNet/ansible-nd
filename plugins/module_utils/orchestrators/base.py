# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from typing import Any, ClassVar, Dict, Generic, List, Optional, Type, TypeVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results

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


class NDBaseOrchestrator(BaseModel, Generic[ModelType]):
    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    model_class: ClassVar[Type[NDBaseModel]] = NDBaseModel
    supports_bulk_create: ClassVar[bool] = False
    supports_bulk_delete: ClassVar[bool] = False

    # Subclasses override to opt in to parallel chunked bulk POSTs.
    # bulk_payload_key is the JSON wrapper key the bulk endpoint expects,
    # e.g. "links" for /api/v1/manage/links POST.  bulk_max_workers caps
    # concurrent in-flight chunks; 2 matches the per-fabric server-side
    # ceiling measured against the manage/links endpoint.
    bulk_payload_key: ClassVar[str] = "items"
    bulk_max_workers: ClassVar[int] = 2

    # NOTE: if not defined by subclasses, return an error as they are required
    create_endpoint: Type[NDEndpointBaseModel]
    update_endpoint: Type[NDEndpointBaseModel]
    delete_endpoint: Type[NDEndpointBaseModel]
    query_one_endpoint: Type[NDEndpointBaseModel]
    query_all_endpoint: Type[NDEndpointBaseModel]

    # NOTE: Conditionally required
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = None
    delete_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = None

    # REST infrastructure
    rest_send: RestSend
    results: Optional[Results] = None

    def _register_api_call(self, path: str, verb: HttpVerbEnum, operation_type: OperationType, payload: Optional[Dict[str, Any]] = None) -> None:
        """Register the most recent REST call with Results for observability."""
        if self.results is None:
            return
        self.results.action = operation_type.value
        self.results.operation_type = operation_type
        self.results.path_current = path
        self.results.verb_current = verb
        self.results.payload_current = payload
        self.results.response_current = self.rest_send.response_current
        self.results.result_current = self.rest_send.result_current
        self.results.diff_current = {}
        # Tag write operations as verbosity 2 (shown at -vv),
        # read operations as verbosity 3 (shown at -vvv).
        self.results.verbosity_level_current = 3 if operation_type == OperationType.QUERY else 2
        self.results.register_api_call()

    def _request(
        self,
        path: str,
        verb: HttpVerbEnum,
        data: Optional[Dict[str, Any]] = None,
        not_found_ok: bool = False,
        operation_type: OperationType = OperationType.QUERY,
    ) -> ResponseType:
        """
        # Summary

        Send a REST request via RestSend and return the response DATA.

        ## Raises

        ### Exception

        - If the request fails (non-success result from the controller).
        - If `not_found_ok` is False and the controller returns a 404.
        """
        self.rest_send.path = path
        self.rest_send.verb = verb
        if data is not None:
            self.rest_send.payload = data
        self.rest_send.commit()

        # Register with Results before success/error checks so that
        # both successful and failed calls are captured for troubleshooting.
        self._register_api_call(path, verb, operation_type, self.rest_send.committed_payload)

        # Check not_found_ok before success because ResponseHandler treats
        # GET 404 as success=True (found=False).  Without this early return,
        # a GET 404 would fall through and return the raw 404 DATA body.
        if not_found_ok and self.rest_send.return_code == 404:
            return {}

        if not self.rest_send.success:
            raise Exception(f"Request failed {self.rest_send.error_summary}")

        return self.rest_send.response_current.get("DATA", {})

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

    def query_all(self, model_instance: Optional[ModelType] = None, **kwargs) -> ResponseType:
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

    def _post_bulk_parallel(self, endpoint: NDEndpointBaseModel, items: List[Any], op: str) -> Dict[str, Any]:
        """Generic parallel chunked POST for bulk endpoints.

        Splits ``items`` into ``bulk_max_workers`` chunks and POSTs them
        concurrently via the underlying ``NDClient`` whose ``requests.Session``
        is thread-safe.  Falls back to a single POST through the standard
        RestSend path for one-item bulks, single-worker configs, or the
        httpapi connection (whose Unix-domain socket is not thread-safe).

        The merged response has the same shape as a single bulk response:
        ``{bulk_payload_key: [<concatenated items in input order>]}``, so the
        existing per-item failure surfacing (``_raise_on_bulk_failures``)
        works unchanged on the merged value.

        Raises ``Exception`` if any chunk fails at the HTTP level (non-207
        4xx/5xx) and surfaces which chunks landed on the controller versus
        which were lost — parallel chunking lowers the atomicity boundary
        from "whole bulk call" to "per chunk".
        """
        if not items:
            return {}

        payload_key = self.bulk_payload_key
        sender = self.rest_send.sender
        ansible_module = getattr(sender, "_ansible_module", None)
        nd_client = getattr(ansible_module, "_nd_client", None)
        workers = min(self.bulk_max_workers, len(items))

        # Single-POST fallback: N==1, capped at 1 worker, or httpapi path
        # (no NDClient → can't parallelize safely).  Goes through the normal
        # RestSend pipeline so response_handler / result aggregation still run.
        if len(items) == 1 or workers <= 1 or nd_client is None:
            return self._request(endpoint.path, endpoint.verb, data={payload_key: items}) or {}

        chunk_size = (len(items) + workers - 1) // workers  # ceil(N/workers)
        chunks = [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

        verb_str = endpoint.verb.value if hasattr(endpoint.verb, "value") else str(endpoint.verb)
        path = endpoint.path

        def _post_chunk(chunk: List[Any]) -> Dict[str, Any]:
            info = nd_client.request(verb_str, path, data=json.dumps({payload_key: chunk}))
            rc = info.get("RETURN_CODE") or info.get("status") or 0
            # 200/201 success, 207 multi-status (per-item failures are caught by
            # _raise_on_bulk_failures on the merged response).  Anything else fails.
            if rc and rc >= 400 and rc != 207:
                msg = info.get("MESSAGE") or info.get("msg") or "unknown error"
                raise Exception("HTTP {0} on bulk {1}: {2}".format(rc, op, msg))
            return info.get("DATA") or {}

        results: Dict[int, Dict[str, Any]] = {}
        errors: Dict[int, Any] = {}
        futures = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for idx, chunk in enumerate(chunks):
                futures[ex.submit(_post_chunk, chunk)] = (idx, chunk)
            # Wait for ALL chunks before deciding, never bail out early, or
            # we lose visibility into what the other in-flight chunk did.
            for fut in as_completed(futures):
                idx, chunk = futures[fut]
                try:
                    results[idx] = fut.result()
                except Exception as e:  # pragma: no cover - surfaced below
                    errors[idx] = (chunk, e)

        if errors:
            success_count = sum(
                len(((results.get(i) or {}).get(payload_key)) or []) for i in results
            )
            lines = [
                "Parallel bulk {0} failed in {1}/{2} chunk(s).  Successful chunks "
                "created/processed {3} item(s); these are now on the controller.".format(
                    op, len(errors), len(chunks), success_count
                ),
            ]
            for idx, (chunk, err) in sorted(errors.items()):
                lines.append("  Chunk {0} ({1} items): {2}".format(idx, len(chunk), err))
            raise Exception("\n".join(lines))

        # Merge in input chunk order so callers see the same shape as a single POST.
        merged: Dict[str, List[Any]] = {payload_key: []}
        for idx in sorted(results):
            chunk_items = (results[idx] or {}).get(payload_key)
            if isinstance(chunk_items, list):
                merged[payload_key].extend(chunk_items)
        return merged

    @requires_bulk_support("supports_bulk_create")
    def create_bulk(self, model_instances: List[ModelType], **kwargs) -> ResponseType:
        raise NotImplementedError

    @requires_bulk_support("supports_bulk_delete")
    def delete_bulk(self, model_instances: List[ModelType], **kwargs) -> ResponseType:
        raise NotImplementedError
