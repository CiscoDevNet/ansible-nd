# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""AnsibleModule compatible shim for in process module execution."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import tempfile

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.validation import check_type_bool


class NDInlineModuleExit(BaseException):
    """Raised by ``NDInlineModule.exit_json``; action plugin unwraps to the task result.

    Inherits from ``BaseException`` (same pattern as ``SystemExit``) so that a
    module's broad ``except Exception`` around ``main()`` cannot swallow this
    control-flow signal.
    """

    def __init__(self, result):
        super(NDInlineModuleExit, self).__init__("exit_json")
        self.result = result


class NDInlineModuleFail(BaseException):
    """Raised by ``NDInlineModule.fail_json``; action plugin unwraps to a failure result."""

    def __init__(self, msg, result):
        super(NDInlineModuleFail, self).__init__(msg)
        self.msg = msg
        self.result = result


class NDInlineModule(object):
    """Duck typed AnsibleModule used when the action plugin runs a module in process."""

    def __init__(
        self,
        raw_params,
        argument_spec,
        nd_client,
        check_mode=False,
        diff=False,
        mutually_exclusive=None,
        required_together=None,
        required_one_of=None,
        required_if=None,
        required_by=None,
    ):
        """Validate ``raw_params`` against ``argument_spec`` and capture task context."""
        validator = ArgumentSpecValidator(
            argument_spec or {},
            mutually_exclusive=mutually_exclusive,
            required_together=required_together,
            required_one_of=required_one_of,
            required_if=required_if,
            required_by=required_by,
        )
        result = validator.validate(raw_params or {})

        if result.error_messages:
            raise NDInlineModuleFail(
                msg="argument validation failed: {0}".format("; ".join(result.error_messages)),
                result={"validated_parameters": result.validated_parameters},
            )

        self.params = result.validated_parameters
        self.check_mode = bool(check_mode)
        self._diff = bool(diff)
        self._debug = False
        self._socket_path = None
        self._nd_client = nd_client
        self.tmpdir = tempfile.gettempdir()

        self._warnings = []
        self._deprecations = []
        self._inline_marker = "nd-inline"

    def exit_json(self, **kwargs):
        """Raise an ``NDInlineModuleExit`` carrying the success result."""
        self._attach_warnings(kwargs)
        raise NDInlineModuleExit(kwargs)

    def fail_json(self, msg, **kwargs):
        """Raise an ``NDInlineModuleFail`` carrying the failure message."""
        self._attach_warnings(kwargs)
        raise NDInlineModuleFail(msg, kwargs)

    def _attach_warnings(self, kwargs):
        """Fold any queued warnings/deprecations into the exit/fail result dict."""
        if self._warnings:
            kwargs.setdefault("warnings", []).extend(self._warnings)
        if self._deprecations:
            kwargs.setdefault("deprecations", []).extend(self._deprecations)

    def warn(self, msg):
        """Queue a warning message for the final task result."""
        self._warnings.append(msg)

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        """Queue a deprecation notice for the final task result."""
        self._deprecations.append(
            {"msg": msg, "version": version, "date": date, "collection_name": collection_name}
        )

    def sha1(self, path):
        """Return the SHA1 hex digest of a file (matches AnsibleModule.sha1)."""
        h = hashlib.sha1()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def boolean(self, value):
        """Coerce ``value`` to a bool using Ansible's standard rules."""
        return check_type_bool(value)
