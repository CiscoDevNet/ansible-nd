# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Dict, Any, Optional, List, Union
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


class NDOutput:
    def __init__(self, output_level: str):
        self._output_level: str = output_level
        self._changed: bool = False
        self._before: Union[NDConfigCollection, List] = []
        self._after: Union[NDConfigCollection, List] = []
        self._diff: Union[NDConfigCollection, List] = []
        self._proposed: Union[NDConfigCollection, List] = []
        self._logs: List = []
        self._extra: Dict[str, Any] = {}

    def format(self, **kwargs) -> Dict[str, Any]:
        if isinstance(self._before, NDConfigCollection) and isinstance(self._after, NDConfigCollection) and self._before.get_diff_collection(self._after):
            self._changed = True

        output = {
            "output_level": self._output_level,
            "changed": self._changed,
            "after": self._after.to_ansible_config() if isinstance(self._after, NDConfigCollection) else self._after,
            "before": self._before.to_ansible_config() if isinstance(self._before, NDConfigCollection) else self._before,
            "diff": self._diff.to_ansible_config() if isinstance(self._diff, NDConfigCollection) else self._diff,
        }

        if self._output_level in ("debug", "info"):
            output["proposed"] = self._proposed.to_ansible_config() if isinstance(self._proposed, NDConfigCollection) else self._proposed
            if self._output_level == "debug":
                output["logs"] = self._logs

        if self._extra:
            output.update(self._extra)

        output.update(**kwargs)

        return output

    def format_with_verbosity(self, verbosity: int, results: Optional[Results] = None, **kwargs) -> Dict[str, Any]:
        """
        Build output dict filtered by CLI verbosity level.

        Level 0-1 (default / -v): changed, failed only.
        Level 2 (-vv): Add API call summary (path, verb) for write operations.
        Level 3+ (-vvv): Add full controller detail (response, result, diff,
                         metadata, payload) for all operations.

        The ``results`` argument should be a Results instance that has had
        ``build_final_result()`` called.  If *None*, only config-level output
        from :meth:`format` is returned.
        """
        output = self.format(**kwargs)

        if results is None or verbosity < 2:
            return output

        # Build the final aggregated result if not already built.
        try:
            final = results.final_result
        except ValueError:
            results.build_final_result()
            final = results.final_result

        # Merge changed/failed from Results (API-level) with NDOutput (config-level).
        if final.get("changed"):
            output["changed"] = True
        if final.get("failed"):
            output["failed"] = True

        # Filter tasks by verbosity: only include tasks whose
        # verbosity_level <= the requested display verbosity.
        verbosity_levels = final.get("verbosity_level", [])
        indices = [i for i, vl in enumerate(verbosity_levels) if vl <= verbosity]

        if not indices:
            return output

        # Level 2 (-vv): endpoint summary for qualifying tasks.
        paths = final.get("path", [])
        verbs = final.get("verb", [])
        output["api_paths"] = [paths[i] for i in indices]
        output["api_verbs"] = [verbs[i] for i in indices]

        # Level 3+ (-vvv): full controller detail for qualifying tasks.
        if verbosity >= 3:
            for key in ("response", "result", "diff", "metadata", "payload"):
                values = final.get(key, [])
                output["api_{0}".format(key)] = [values[i] for i in indices]

        return output

    def assign(
        self,
        after: Optional[NDConfigCollection] = None,
        before: Optional[NDConfigCollection] = None,
        diff: Optional[NDConfigCollection] = None,
        proposed: Optional[NDConfigCollection] = None,
        logs: Optional[List] = None,
        **kwargs
    ) -> None:
        if isinstance(after, NDConfigCollection):
            self._after = after
        if isinstance(before, NDConfigCollection):
            self._before = before
        if isinstance(diff, NDConfigCollection):
            self._diff = diff
        if isinstance(proposed, NDConfigCollection):
            self._proposed = proposed
        if isinstance(logs, List):
            self._logs = logs
        self._extra.update(**kwargs)
