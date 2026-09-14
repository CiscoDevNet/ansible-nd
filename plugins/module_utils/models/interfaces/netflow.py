# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared atomic NetFlow merge behavior for interface policy models."""

from __future__ import annotations

from contextvars import ContextVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.storm_control import StormControlMutexMixin

_NETFLOW_VALIDATION_SUSPENDED: ContextVar[bool] = ContextVar("netflow_validation_suspended", default=False)


def netflow_validation_suspended() -> bool:
    """Return whether an atomic NetFlow merge is in progress."""
    return _NETFLOW_VALIDATION_SUSPENDED.get()


class NetflowAtomicMergeMixin(StormControlMutexMixin):
    """Merge NetFlow enablement and its required monitor as one valid change."""

    def merge(self, other: NDBaseModel) -> NDBaseModel:
        """
        Merge NetFlow intent without exposing an invalid intermediate assignment.

        NDBaseModel.merge assigns explicit fields in model order. Since netflow
        precedes netflow_monitor, assignment validation would otherwise reject
        a valid proposal containing both before the monitor assignment occurs.
        Validate the final pair before mutation, then suspend only this
        invariant while the shared merge applies all fields.
        """
        if not isinstance(other, type(self)):
            return super().merge(other)

        final_netflow = (
            getattr(other, "netflow") if "netflow" in other.model_fields_set and getattr(other, "netflow") is not None else getattr(self, "netflow", None)
        )
        final_monitor = (
            getattr(other, "netflow_monitor")
            if "netflow_monitor" in other.model_fields_set and getattr(other, "netflow_monitor") is not None
            else getattr(self, "netflow_monitor", None)
        )
        if final_netflow is True and not final_monitor:
            raise ValueError("netflow_monitor must be provided when netflow is true.")

        token = _NETFLOW_VALIDATION_SUSPENDED.set(True)
        try:
            return super().merge(other)
        finally:
            _NETFLOW_VALIDATION_SUSPENDED.reset(token)
