# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED


# TODO: Maybe make it an all new module class with request, etc.
# TODO: Add description to functions and clean the code
# TODO: Add exception cases
# NOTE: ONLY works for new API endpoints introduced in ND v4.1.0 and later
class NDNetworkResourceModule(NDModule):
    def __init__(self, module, path, identifier_key):
        super().__init__(module)
        self.path = path
        self.identifier_key = identifier_key
        # normal output
        self.existing = NDConfigCollection(identifier_key)

        # info output
        self.previous = NDConfigCollection(identifier_key)
        self.proposed = NDConfigCollection(identifier_key)
        self.sent = NDConfigCollection(identifier_key)
        self.init_all_existing = NDConfigCollection(identifier_key, data=self.query_obj(path=path, ignore_not_found_error=True))

    def merge_configs(self, new_configs):
        self.proposed = NDConfigCollection(self.identifier_key, data=new_configs).sanitze()
        self.existing = self.previous = self.init_all_existing.copy()

        for identifier, config in self.proposed.items():
            if identifier in self.existing:
                self.existing.merge(config)
                # TODO: leverage a get_diff_config instead
                if self.existing != self.previous:
                    object_path = "{0}/{1}".format(self.path, identifier)
                    self.request(path=object_path, method="PUT", data=self.existing[identifier])
                    self.sent[identifier] = config
            else:
                self.request(path=self.path, method="POST", data=config)
                self.existing[identifier] = config
                self.sent[identifier] = config

    def replace_configs(self, new_configs):
        self.proposed = NDConfigCollection(self.identifier_key, data=new_configs).sanitze()
        self.existing = self.previous = self.init_all_existing.copy()

        for identifier, config in self.proposed.items():
            # TODO: leverage a get_diff_config instead
            if identifier in self.existing and config != self.existing.get(identifier):
                object_path = "{0}/{1}".format(self.path, identifier)
                self.request(path=object_path, method="PUT", data=config)
                self.sent[identifier] = config
            else:
                self.request(path=self.path, method="POST", data=config)
                self.sent[identifier] = config
            self.existing[identifier] = config

    def override_configs(self, new_configs):
        self.replace_configs(new_configs)

        diff_identifiers = self.previous.get_diff_identifiers(self.proposed)
        for identifier in diff_identifiers:
            object_path = "{0}/{1}".format(self.path, identifier)
            self.request(path=object_path, method="DELETE")
            del self.existing[identifier]

    def delete_configs(self, new_configs):
        self.proposed = NDConfigCollection(self.identifier_key, data=new_configs).sanitze()
        self.existing = self.previous = self.init_all_existing.copy()

        for identifier in self.proposed_map:
            object_path = "{0}/{1}".format(self.path, identifier)
            self.request(path=object_path, method="DELETE")
            del self.existing[identifier]

        self.proposed.clear()

    # TODO: Make further modifications to fail_json and exit_json
    def nrm_fail_json(self, msg, **kwargs):
        if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous.list_view
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        if self.params.get("output_level") == "debug":
            if self.url is not None:
                self.result["method"] = self.method
                self.result["response"] = self.response
                self.result["status"] = self.status
                self.result["url"] = self.url
                self.result["httpapi_logs"] = self.httpapi_logs

            if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent.list_view
                self.result["proposed"] = self.proposed.list_view

        self.result["current"] = self.existing.list_view

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def nrm_exit_json(self, **kwargs):
        if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous.list_view
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        if self.params.get("output_level") == "debug":
            self.result["method"] = self.method
            self.result["response"] = self.response
            self.result["status"] = self.status
            self.result["url"] = self.url
            self.result["httpapi_logs"] = self.httpapi_logs

            if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent.list_view
                self.result["proposed"] = self.proposed.list_view

        self.result["current"] = self.existing.list_view

        if self.module._diff and self.result.get("changed") is True:
            self.result["diff"] = dict(
                before=self.previous.list_view,
                after=self.existing.list_view,
            )

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)
