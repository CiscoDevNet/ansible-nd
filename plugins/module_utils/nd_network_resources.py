# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED

# TODO: Make further enhancement to logs and outputs
# NOTE: ONLY works for new API endpoints introduced in ND v4.1.0 and later
class NDNetworkResourceModule(NDModule):

    def __init__(self, module, path, identifier_keys, use_composite_keys=False, actions_overwrite_map=None):
        super().__init__(module)

        # Initial variables
        self.path = path
        self.actions_overwrite_map = actions_overwrite_map or {}
        self.identifier_keys = identifier_keys
        self.use_composite_keys = use_composite_keys

        # Initial data
        self.init_all_data = self._query_all()
        
        # Info ouput
        self.existing = NDConfigCollection(identifier_keys, data=self.init_all_data)
        self.previous = NDConfigCollection(identifier_keys)
        self.proposed = NDConfigCollection(identifier_keys)
        self.sent = NDConfigCollection(identifier_keys)

        # Debug output
        self.nd_logs = []

        # Helper variables
        self.current_identifier = ""
        self.existing_config = {}
        self.proposed_config = {}

    # Actions Operations
    def actions_overwrite(action):
        def decorator(func):
            def wrapper(self, *args, **kwargs):
                overwrite_action = self.actions_overwrite_map.get(action)
                if callable(overwrite_action):
                    return overwrite_action(self)
                else:
                    return func(self, *args, **kwargs)
            return wrapper
        return decorator

    @actions_overwrite("create")
    def _create(self):
        if not self.module.check_mode:
            return self.request(path=self.path, method="POST", data=self.proposed_config)

    @actions_overwrite("update")
    def _update(self):
        if not self.module.check_mode:
            object_path = "{0}/{1}".format(self.path, self.current_identifier)
            return self.request(path=object_path, method="PUT", data=self.proposed_config)

    @actions_overwrite("delete")
    def _delete(self):
        if not self.module.check_mode:
            object_path = "{0}/{1}".format(self.path, self.current_identifier)
            self.request(path=object_path, method="DELETE")
    
    @actions_overwrite("query_all")
    def _query_all(self):
        return self.query_obj(self.path)

    def format_log(self, identifier, status, after_data, sent_payload_data=None):
        item_result = {
            "identifier": identifier,
            "status": status,
            "before": self.existing_config,
            "after": deepcopy(after_data) if after_data is not None else self.existing_config,
            "sent_payload": deepcopy(sent_payload_data) if sent_payload_data is not None else {},
        }

        if not self.module.check_mode and self.url is not None:
            item_result.update(
                {
                    "method": self.method,
                    "response": self.response,
                    "status": self.status,
                    "url": self.url,
                }
            )
        
        self.nd_logs.append(item_result)

    # Logs and Outputs formating Operations
    def add_logs_and_ouputs(self):
        if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous.to_list()
            if not self.has_modified and self.previous.get_diff_collection(self.existing):
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        if self.params.get("output_level") == "debug":
            self.result["nd_logs"] = self.nd_logs
            if self.url is not None:
                self.result["httpapi_logs"] = self.httpapi_logs

            if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent.to_list()
                self.result["proposed"] = self.proposed.to_list()

        self.result["current"] = self.existing.to_list()

    # Manage State Operations
    def manage_state(self, state, new_configs, unwanted_keys=None, override_exceptions=None):
        unwanted_keys = unwanted_keys or []
        override_exceptions = override_exceptions or []

        self.proposed = NDConfigCollection(self.identifier_keys, data=new_configs)
        self.proposed.sanitize()
        self.previous = self.existing.copy()

        if state in ["merged", "replaced", "overidden"]:
            for identifier, config in self.proposed.items():

                diff_config_info = self.existing.get_diff_config(config, unwanted_keys)
                self.current_identifier = identifier
                self.existing_config = deepcopy(self.existing.get_by_key(identifier, {}))
                self.proposed_config = config
                request_response = None
                sent_payload = None
                status = "no_change"

                if diff_config_info != "no_diff":
                    if state == "merged":
                        self.existing.merge(config)
                        self.proposed_config = self.existing[identifier]
                    else:
                        self.existing.replace(config)

                    if diff_config_info == "changed":
                        request_response = self._update()
                        status = "updated"
                    else:
                        request_response = self._create()
                        status= "created"

                    if not self.module.check_mode:
                        self.sent.add(self.proposed_config)
                        sent_payload = self.proposed_config
                    else:
                        request_response = self.proposed_config

                    self.format_log(identifier, status, request_response, sent_payload)

            
            if state == "overidden":
                diff_identifiers = self.previous.get_diff_identifiers(self.proposed)
                for identifier in diff_identifiers:
                    if identifier not in override_exceptions:
                        self.current_identifier = identifier
                        self.existing_config = deepcopy(self.existing.get_by_key(identifier, {}))
                        self._delete()
                        del self.existing[identifier]
                        self.format_log(identifier, "deleted", after_data={})
        

        elif state == "deleted":
            for identifier, config in self.proposed.items():
                if identifier in self.existing.keys():
                    self.current_identifier = identifier
                    self.existing_config = deepcopy(self.existing.get_by_key(identifier, {}))
                    self.proposed_config = config
                    self._delete()
                    del self.existing[identifier]
                    self.format_log(identifier, "deleted", after_data={})

    # Outputs Operations
    def fail_json(self, msg, **kwargs):
        self.add_logs_and_ouputs()

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def exit_json(self, **kwargs):
        self.add_logs_and_ouputs()

        if self.module._diff and self.result.get("changed") is True:
            self.result["diff"] = dict(
                before=self.previous.to_list(),
                after=self.existing.to_list(),
            )

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)
