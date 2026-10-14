# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Shared REST + `Results` plumbing for orchestrators.

`NDRequestBase` carries exactly two fields, `rest_send` and `results`, plus the `_request` / `_register_api_call` pair that every
orchestrator uses to drive `RestSend` and record each call for verbosity-gated output. It deliberately carries no endpoint or CRUD
surface: `NDBaseOrchestrator` adds those for resource-backed orchestrators, while action-only orchestrators (for example
`FabricPrepareUpdateOrchestrator`) subclass `NDRequestBase` directly so they inherit the helpers without the CRUD obligations.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


class NDRequestBase(BaseModel):
    """
    # Summary

    Thin Pydantic base that owns the injected `RestSend` and optional `Results`, and provides the shared `_request` /
    `_register_api_call` helpers. Subclass it directly for action-only orchestrators; subclass `NDBaseOrchestrator` for CRUD resources.

    ## Raises

    ### RuntimeError

    - Via `_request` if the controller returns a non-success result.
    """

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
        # pydantic <2.10 defaults protected_namespaces to the whole `model_` prefix and applies the
        # check even to ClassVar annotations, so `model_class` would raise NameError at class
        # construction on user hosts running older pydantic 2.x. Pin pydantic >=2.10's narrower
        # default rather than () so the collision guard still covers genuinely dangerous names.
        protected_namespaces=("model_validate", "model_dump"),
    )

    # REST infrastructure
    rest_send: RestSend
    results: Results | None = None

    def _register_api_call(self, path: str, verb: HttpVerbEnum, operation_type: OperationType, payload: dict[str, Any] | None = None) -> None:
        """
        # Summary

        Register the most recent REST call with `Results` for verbosity-gated observability. No-op when no `Results` instance is attached.

        ## Raises

        None
        """
        if self.results is None:
            return
        # ``Results.register_api_call`` resets its current task after every
        # request. Reapply stable module context for each registration so a
        # paginated query (or any multi-call workflow) does not lose state and
        # check-mode metadata after page one.
        self.results.state = str(self.rest_send.params.get("state") or "")
        # ``rest_send.check_mode`` can be disabled temporarily for a read-only
        # POST (for example interface preview).  Metadata describes the module
        # invocation, not that transport override, so read the immutable input
        # captured when RestSend was constructed.
        self.results.check_mode = bool(self.rest_send.params.get("check_mode", False))
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
        data: dict[str, Any] | None = None,
        not_found_ok: bool = False,
        operation_type: OperationType = OperationType.QUERY,
    ) -> ResponseType:
        """
        # Summary

        Send a REST request via `RestSend`, register it with `Results`, and return the response `DATA`.

        ## Raises

        ### RuntimeError

        - If the request fails (non-success result from the controller).
        - If `not_found_ok` is False and the controller returns a 404 on a non-GET verb.
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
            raise RuntimeError(f"Request failed {self.rest_send.error_summary}")

        return self.rest_send.response_current.get("DATA", {})
