# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Dict, Any, Optional, List, Union
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection


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
                output["logs"] = "Not yet implemented"

        if self._extra:
            output.update(self._extra)

        output.update(**kwargs)

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
