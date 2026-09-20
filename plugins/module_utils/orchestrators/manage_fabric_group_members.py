# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_group_member_surfaces import (
    FabricGroupMemberSurface,
    ManageSurface,
    OneManageSurface,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# ND refuses a Manage-surface membership write against a multi-cluster fabric group with
# "Cannot add member as the fabric 'x' is managed by OneManage" (and the removeMembers
# equivalent). It is the only signal that distinguishes the two kinds of group when OneManage
# could not be reached, so it is matched to replace an opaque HTTP 400 with the one action
# that actually fixes the run.
_ONEMANAGE_ONLY_ERROR = "is managed by OneManage"

_LOGIN_DOMAIN_HINT = (
    "Fabric group '{fabric_name}' is a multi-cluster fabric group, which can only be managed "
    "through the ND OneManage API. Authenticate through the multi-cluster login domain (set "
    "'login_domain', or ansible_httpapi_login_domain, to the domain configured for "
    "multi-cluster access) and run the task again."
)


class ManageFabricGroupMembersOrchestrator(ConfigActionsMixin, NDBaseOrchestrator[FabricGroupMemberModel]):
    """Manage the membership of a fabric group or a multi-cluster fabric group.

    ND models both kinds of group as a set of member fabrics with no mutable attributes, so
    membership only ever supports add and remove -- there is no update. Both surfaces accept
    exactly one member per request, so members are sent individually rather than in bulk.
    """

    model_class: ClassVar[type[NDBaseModel]] = FabricGroupMemberModel

    # Both surfaces reject a multi-member body, so there is no bulk path to opt into: the state
    # machine issues one create/delete per member, which is exactly what the API requires.
    supports_bulk_create: ClassVar[bool] = False
    supports_bulk_delete: ClassVar[bool] = False

    # Required by NDBaseOrchestrator. The endpoints actually used come from the resolved
    # surface, which is not known until the first API call; these name the Manage defaults so
    # the declaration stays truthful for the common case.
    create_endpoint: type[NDEndpointBaseModel] = ManageSurface.members_add_endpoint
    update_endpoint: type[NDEndpointBaseModel] = ManageSurface.members_add_endpoint
    delete_endpoint: type[NDEndpointBaseModel] = ManageSurface.members_remove_endpoint
    query_one_endpoint: type[NDEndpointBaseModel] = ManageSurface.members_get_endpoint
    query_all_endpoint: type[NDEndpointBaseModel] = ManageSurface.members_get_endpoint

    # Resolved once per run, on first use.
    _surface: type[FabricGroupMemberSurface] | None = None

    # Why OneManage was ruled out, when it was ruled out by a failed probe.
    _surface_note: str | None = None

    @property
    def fabric_name(self) -> str:
        """Return the parent fabric group name from module params (populated by NDStateMachine)."""
        return self.rest_send.params.get("fabric_name")

    @property
    def surface(self) -> type[FabricGroupMemberSurface]:
        """Return the ND API surface that owns this fabric group, resolving it once."""
        if self._surface is None:
            self._surface = self._resolve_surface()
        return self._surface

    @property
    def surface_note(self) -> str | None:
        """Return why OneManage was ruled out, when it was ruled out by a failed probe."""
        return self._surface_note

    # ------------------------------------------------------------------ surface resolution

    def _resolve_surface(self) -> type[FabricGroupMemberSurface]:
        """Determine which API owns ``fabric_name``, then check the config suits it.

        OneManage is asked first because it is the only authority for a multi-cluster fabric
        group: Manage reports one as category ``fabricGroup`` with a body that is
        field-for-field identical to a single-cluster group, and stops listing it at all once
        it has no member on the local cluster -- which is exactly the state a group is in
        before its first member is added.

        Manage is consulted only when OneManage does not claim the group, where it is the one
        surface guaranteed to be reachable and can confirm the target exists and is a group.
        """
        if self._probe_onemanage():
            surface: type[FabricGroupMemberSurface] = OneManageSurface
        else:
            self._assert_fabric_group()
            surface = ManageSurface
        self._validate_config_for_surface(surface)
        return surface

    def _assert_fabric_group(self) -> None:
        """Fail early unless ``fabric_name`` names a fabric group the Manage API can see.

        The members endpoint cannot do this itself: it answers 200 with an empty list for a
        plain fabric, and 500 "Failed to check fabric type" for a name it does not know, so
        without this check a typo becomes an opaque server error and a fabric becomes a silent
        no-op.

        A miss here is not proof the group does not exist. Manage stops reporting a
        multi-cluster fabric group once it holds no member on the local cluster, so a session
        that could not reach OneManage sees an empty multi-cluster group as absent -- hence
        the probe's reason is carried into the message.
        """
        api_endpoint = ManageSurface.fabric_get_endpoint(fabric_name=self.fabric_name)
        fabric = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        if not fabric:
            raise ValueError(
                f"Fabric group '{self.fabric_name}' was not found through the ND Manage API ({self._surface_note}). "
                f"If it is a multi-cluster fabric group, authenticate through the multi-cluster login domain; the "
                f"Manage API stops reporting one once it has no member fabric on the local cluster."
            )
        if fabric.get("category") == "fabric":
            raise ValueError(f"'{self.fabric_name}' is a fabric, not a fabric group, so it cannot have members.")

    def _probe_onemanage(self) -> bool:
        """Return True when OneManage reports ``fabric_name`` as a multi-cluster fabric group.

        Every way of saying "no" is a failure response, and the status code varies with why:
        400 "Multi-cluster environment must be configured" from a single-cluster controller,
        400 "fabric not found" for a single-cluster group on a multi-cluster controller, and
        500 "this API is allowed only for remote user" when the session did not authenticate
        through the multi-cluster login domain. None of them is fatal on its own -- Manage keeps
        working regardless -- so any failure selects Manage and the reason is kept in
        ``surface_note`` rather than discarded.

        The probe drives ``rest_send`` directly instead of going through ``_request`` so its
        expected failure is not registered with ``Results``, which would otherwise make a
        successful run report ``failed`` at ``-vv`` and above.

        It also runs with the retry window collapsed to a single attempt. ``RestSend`` retries a
        retryable failure for ``timeout`` seconds (300 by default, every 5 seconds), and the
        500 returned to a local-domain session on a federated controller is retryable -- so
        without this the probe would stall every task for five minutes before reaching the
        answer it already had.
        """
        api_endpoint = OneManageSurface.fabric_get_endpoint(fabric_name=self.fabric_name)
        self.rest_send.path = api_endpoint.path
        self.rest_send.verb = api_endpoint.verb
        self.rest_send.save_settings()
        self.rest_send.timeout = 1
        try:
            self.rest_send.commit()
        except Exception as error:
            self._surface_note = f"OneManage probe did not complete ({error}); using the Manage API."
            return False
        finally:
            self.rest_send.restore_settings()
        if not self.rest_send.success:
            self._surface_note = f"OneManage probe returned {self.rest_send.return_code}; using the Manage API."
            return False
        fabric = self.rest_send.response_current.get("DATA", {})
        if isinstance(fabric, dict) and fabric.get("category") == "multiClusterFabricGroup":
            return True
        # A GET that returns 404 counts as a successful "not found", so this also covers
        # OneManage answering that it does not know the fabric at all.
        self._surface_note = f"OneManage does not report '{self.fabric_name}' as a multi-cluster fabric group; using the Manage API."
        return False

    def _validate_config_for_surface(self, surface: type[FabricGroupMemberSurface]) -> None:
        """Reject member config whose identity does not match the resolved surface.

        The two surfaces identify a member differently and neither reports a mismatch usefully.
        OneManage rejects a member without ``clusterName`` with an unexplained HTTP 500. Manage
        accepts a ``clusterName`` and silently drops it, so the member ND stores never matches
        the one the module proposed: the member looks absent on every run, is re-added, and the
        second run fails with "already assigned to Fabric Group". Both are caught here, before
        anything is changed.
        """
        config = self.rest_send.params.get("config") or []
        with_cluster = [item.get("member_name") for item in config if item.get("cluster_name")]
        without_cluster = [item.get("member_name") for item in config if not item.get("cluster_name")]

        if surface.identifies_members_by_cluster and without_cluster:
            raise ValueError(
                f"'cluster_name' is required for every member of multi-cluster fabric group '{self.fabric_name}'; " f"it is missing for {without_cluster}."
            )
        if not surface.identifies_members_by_cluster and with_cluster:
            # Supplying cluster_name declares multi-cluster intent, and the probe could not
            # confirm it. Which of the two fixes applies depends on why the probe came back
            # empty-handed, which it does not reliably report, so both are offered with the
            # reason attached.
            raise ValueError(
                f"'cluster_name' was supplied for {with_cluster}, which identifies members of a multi-cluster "
                f"fabric group, but the ND OneManage API did not confirm '{self.fabric_name}' as one "
                f"({self._surface_note}). If it is a multi-cluster fabric group, authenticate through the "
                f"multi-cluster login domain; if it is a single-cluster fabric group, remove 'cluster_name'."
            )

    def _endpoint(self, endpoint_class: type[NDEndpointBaseModel]) -> NDEndpointBaseModel:
        """Instantiate a surface endpoint bound to the parent fabric group."""
        return endpoint_class(fabric_name=self.fabric_name)

    # --------------------------------------------------------------- ConfigActionsMixin hooks

    def config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self.surface.config_save_endpoint(fabric_name=fabric_name)

    def deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self.surface.deploy_global_endpoint(fabric_name)

    def switches_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self.surface.switches_endpoint(fabric_name=fabric_name)

    def switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return self.surface.switch_deploy_endpoint(fabric_name=fabric_name)

    # ------------------------------------------------------------------------------- CRUD

    def _send_member(
        self,
        endpoint_class: type[NDEndpointBaseModel],
        model_instance: FabricGroupMemberModel,
        operation_type: OperationType,
    ) -> ResponseType:
        """Send one membership change, translating ND's OneManage-only refusal."""
        api_endpoint = self._endpoint(endpoint_class)
        payload = self.surface.member_body(model_instance.to_payload())
        try:
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=operation_type)
        except Exception as error:
            if _ONEMANAGE_ONLY_ERROR in str(error):
                raise ValueError(_LOGIN_DOMAIN_HINT.format(fabric_name=self.fabric_name)) from error
            raise

    def create(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Add one member fabric to the group."""
        endpoint_class = self.surface.members_add_endpoint
        try:
            return self._send_member(endpoint_class, model_instance, OperationType.CREATE)
        except Exception as e:
            raise Exception(f"Add member failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Not reachable: a member has no attribute the module can change.

        Defined only so the base implementation, which would POST to addMembers with the member
        name substituted into the fabric path, can never run.
        """
        raise Exception(f"Fabric group membership cannot be updated in place; {model_instance.get_identifier_value()} must be removed and re-added.")

    def delete(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Remove one member fabric from the group."""
        endpoint_class = self.surface.members_remove_endpoint
        try:
            return self._send_member(endpoint_class, model_instance, OperationType.DELETE)
        except Exception as e:
            raise Exception(f"Remove member failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Return the named member from the group's member list, or None."""
        try:
            for member in self.query_all():
                if member.get("name") == model_instance.member_name:
                    return member
            return None
        except Exception as e:
            raise Exception(f"Query member failed for {model_instance.member_name}: {e}") from e

    def query_all(self, model_instance: FabricGroupMemberModel | None = None, **kwargs) -> ResponseType:
        """Return the group's members.

        Both surfaces wrap the members in a ``fabrics`` array; only OneManage reports a
        ``clusterName`` for each member.
        """
        # Resolved outside the try so a surface-resolution or validation failure keeps its own
        # message instead of being relabelled as a failed query.
        api_endpoint = self._endpoint(self.surface.members_get_endpoint)
        try:
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
            if isinstance(result, dict):
                return result.get("fabrics") or []
            return result or []
        except Exception as e:
            raise Exception(f"Query all members failed: {e}") from e
