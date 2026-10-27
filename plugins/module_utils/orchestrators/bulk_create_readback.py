# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared bulk-create recovery for orchestrators whose collection endpoint commits part of a failed array POST (issue #646).

`NDBaseOrchestrator.accepted_mutations` is the failure-path hook `NDStateMachine` consults after a bulk create raised, so only the items the
controller nevertheless accepted appear in the module's `after` and `sent` (issue #597). The base answer is "nothing accepted". That is wrong for
the community-list endpoints, which process the array in order, stop at the first commit-time failure and answer a flat error with no
`results[]`: the items ahead of the failing one exist on the controller. `NDBulkCreateReadBackOrchestrator` answers the hook from one re-read
of the collection instead, so both community-list orchestrators share one recovery and one workaround marker.
"""

from __future__ import annotations

from collections.abc import Sequence

from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import ModelType, NDBaseOrchestrator


class NDBulkCreateReadBackOrchestrator(NDBaseOrchestrator[ModelType]):  # pylint: disable=too-few-public-methods
    """
    # Summary

    Base class for orchestrators whose bulk create can commit part of the submitted array and still fail as a whole. A subclass calls
    `_created_despite_failure` from the `except` branch of its `create_bulk`; the result is remembered and `accepted_mutations` answers from
    it, so `NDStateMachine` reports the committed items in `after` / `changed` while the task still fails with the controller's message.

    The recovery compares the submitted identifiers with the collection as it is after the failure. Presence alone is proof here because
    `create_bulk` receives only items the pre-run inventory did not hold (`NDStateMachine` diffs them as `new`); a direct caller that submits
    an identifier which already existed would see it reported as created.

    ## Raises

    None
    """

    _readback_created: list[ModelType] | None = None

    def _created_despite_failure(self, model_instances: Sequence[ModelType]) -> list[ModelType]:
        """
        # Summary

        After a bulk create failed, re-read the collection once with `query_all` and return the submitted items that exist now, in request
        order. The result is remembered for `accepted_mutations`. The re-read never masks the create failure: if it or the row parsing fails,
        nothing is reported as created and the caller re-raises the original error.

        ## Raises

        None
        """
        # TODO(4.2.1) community-list-bulk-post-403-partial-commit
        # A bulk communityLists / extendedCommunityLists POST with one commit-time-invalid item (for example a tenantName that is not valid in
        # the fabric) answers a flat HTTP 403 with no results[] but has already created every item before the failing one; items after it are
        # not created. Lab-verified 2026-10-23 on 4.2.1.10 and 4.3.1.175 (identical). Re-read the collection and report the submitted names
        # that exist now as created, so the task does not claim nothing changed and a rerun's "no change" is not the first report of them.
        self._readback_created = []
        try:
            rows = self.query_all()
            collection = NDConfigCollection.from_api_response(response_data=rows if isinstance(rows, list) else [], model_class=self.model_class)
        except Exception:  # pylint: disable=broad-exception-caught
            return []
        created: list[ModelType] = []
        for item in model_instances:
            identifier = item.get_identifier_value()
            if identifier is not None and collection.get(identifier) is not None:
                created.append(item)
        self._readback_created = list(created)
        return created

    def accepted_mutations(self, model_instances: Sequence[ModelType]) -> list[ModelType]:
        """
        # Summary

        Return the subset of `model_instances` the last `_created_despite_failure` read back as existing, in `model_instances` order. Empty
        when no recovery ran or the re-read failed, which is the conservative answer (issue #597).

        ## Raises

        None
        """
        if not self._readback_created:
            return []
        created = {item.get_identifier_value() for item in self._readback_created}
        return [item for item in model_instances if item.get_identifier_value() in created]
