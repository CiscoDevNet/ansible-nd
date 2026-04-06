# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Base action plugin for cisco.nd modules using the fast (in process) path.

Per module stub:

    class ActionModule(NDActionBase):
        MODULE_NAME = "nd_links"

Cross worker "one login per play" is achieved via the on disk session cache
in ``NDClient.ensure_session()``; the class level ``_client_cache`` only
covers the current worker's in process reuse.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import importlib
import traceback

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ansible_collections.cisco.nd.plugins.module_utils.client.build_module import (
    clear_inline_context,
    set_inline_context,
)
from ansible_collections.cisco.nd.plugins.module_utils.client.nd_client import (
    NDClient,
    NDClientError,
)
from ansible_collections.cisco.nd.plugins.module_utils.client.nd_inline_module import (
    NDInlineModuleExit,
    NDInlineModuleFail,
)


class NDActionBase(ActionBase):
    """Shared base for every cisco.nd action plugin. Subclasses set ``MODULE_NAME``."""

    MODULE_NAME = None

    _client_cache = {}

    def run(self, tmp=None, task_vars=None):
        """Run the module in process with a shared NDClient instead of forking."""
        result = super(NDActionBase, self).run(tmp, task_vars)
        del tmp
        task_vars = task_vars or {}

        if not self.MODULE_NAME:
            raise AnsibleActionFail("NDActionBase subclass did not set MODULE_NAME")

        host = (
            task_vars.get("ansible_host")
            or task_vars.get("ansible_httpapi_host")
            or task_vars.get("inventory_hostname")
        )
        user = task_vars.get("ansible_user")
        password = (
            task_vars.get("ansible_password")
            or task_vars.get("ansible_httpapi_password")
            or task_vars.get("ansible_httpapi_pass")
        )
        port = task_vars.get("ansible_httpapi_port", 443)
        verify_certs = task_vars.get("ansible_httpapi_validate_certs", True)
        login_domain = task_vars.get("ansible_httpapi_login_domain", "DefaultAuth")
        timeout = task_vars.get("ansible_command_timeout", 30)

        if not (host and user and password):
            raise AnsibleActionFail(
                "Missing ND connection info. Inventory must define "
                "ansible_host, ansible_user, and ansible_password."
            )

        try:
            client = self._get_or_create_client(
                host=host,
                user=user,
                password=password,
                port=int(port),
                login_domain=login_domain,
                verify_certs=bool(verify_certs),
                timeout=int(timeout),
            )
        except NDClientError as e:
            raise AnsibleActionFail("Failed to connect to ND: {0}".format(e))

        module_path = "ansible_collections.cisco.nd.plugins.modules." + self.MODULE_NAME
        try:
            module_pkg = importlib.import_module(module_path)
        except ImportError as e:
            raise AnsibleActionFail("Cannot import module {0}: {1}".format(module_path, e))

        if not hasattr(module_pkg, "main"):
            raise AnsibleActionFail("Module {0} has no main() function".format(module_path))

        try:
            rendered_args = self._templar.template(
                copy.deepcopy(self._task.args),
                fail_on_undefined=True,
            )
        except Exception as e:
            raise AnsibleActionFail(
                "Failed to render Jinja in task args for {0}: {1}".format(self.MODULE_NAME, e)
            )

        set_inline_context(
            params=rendered_args,
            nd_client=client,
            check_mode=self._task.check_mode,
            diff=task_vars.get("ansible_diff_mode", False),
        )

        try:
            module_pkg.main()
            result["failed"] = True
            result["msg"] = (
                "Module {0} returned without calling exit_json or fail_json".format(self.MODULE_NAME)
            )
        except NDInlineModuleExit as e:
            result.update(e.result or {})
        except NDInlineModuleFail as e:
            result["failed"] = True
            result["msg"] = e.msg
            result.update(e.result or {})
        except Exception as e:
            result["failed"] = True
            result["msg"] = "Unexpected error in {0}: {1}".format(self.MODULE_NAME, e)
            result["exception"] = traceback.format_exc()
        finally:
            clear_inline_context()

        return result

    @classmethod
    def _get_or_create_client(cls, host, user, password, port,
                              login_domain, verify_certs, timeout):
        """Return a cached NDClient (in process) or build a new one and ensure its session."""
        key = (host, user, port)
        if key not in cls._client_cache:
            client = NDClient(
                host=host,
                username=user,
                password=password,
                port=port,
                login_domain=login_domain,
                verify_certs=verify_certs,
                timeout=timeout,
            )
            client.ensure_session()
            cls._client_cache[key] = client
        return cls._client_cache[key]
