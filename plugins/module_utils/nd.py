# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from functools import reduce

__metaclass__ = type

from copy import deepcopy
import os
import shutil
import tempfile
from ansible.module_utils.basic import json
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import PY3
from ansible.module_utils.six.moves import filterfalse
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.connection import Connection
from ansible_collections.cisco.nd.plugins.module_utils.constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED


def sanitize_dict(dict_to_sanitize, keys=None, values=None, recursive=True, remove_none_values=True):
    if keys is None:
        keys = []
    if values is None:
        values = []

    result = deepcopy(dict_to_sanitize)
    for k, v in dict_to_sanitize.items():
        if k in keys:
            del result[k]
        elif v in values or (v is None and remove_none_values):
            del result[k]
        elif isinstance(v, dict) and recursive:
            result[k] = sanitize_dict(v, keys, values)
        elif isinstance(v, list) and recursive:
            for index, item in enumerate(v):
                if isinstance(item, dict):
                    result[k][index] = sanitize_dict(item, keys, values)
    return result


def sanitize_list(list_to_sanitize, keys=None, values=None, list_recursive=True, dict_recursive=True, remove_none_values=True):
    result = deepcopy(list_to_sanitize)
    for index, item in enumerate(list_to_sanitize):
        if isinstance(item, dict):
            result[index] = sanitize_dict(item, keys, values, dict_recursive, remove_none_values)
        elif isinstance(item, list) and list_recursive:
            result[index] = sanitize_list(item, keys, values, list_recursive, dict_recursive, remove_none_values)
    return result


if PY3:

    def cmp(a, b):
        return (a > b) - (a < b)


def issubset(subset, superset):
    """Recurse through nested dictionary and compare entries"""

    # Both objects are the same object
    if subset is superset:
        return True

    # Both objects are identical
    if subset == superset:
        return True

    # Both objects have a different type
    if isinstance(subset) is not isinstance(superset):
        return False

    for key, value in subset.items():
        # Ignore empty values
        if value is None:
            return True

        # Item from subset is missing from superset
        if key not in superset:
            return False

        # Item has different types in subset and superset
        if isinstance(superset.get(key)) is not isinstance(value):
            return False

        # Compare if item values are subset
        if isinstance(value, dict):
            if not issubset(superset.get(key), value):
                return False
        elif isinstance(value, list):
            try:
                # NOTE: Fails for lists of dicts
                if not set(value) <= set(superset.get(key)):
                    return False
            except TypeError:
                # Fall back to exact comparison for lists of dicts
                diff = list(filterfalse(lambda i: i in value, superset.get(key))) + list(filterfalse(lambda j: j in superset.get(key), value))
                if diff:
                    return False
        elif isinstance(value, set):
            if not value <= superset.get(key):
                return False
        else:
            if not value == superset.get(key):
                return False

    return True


def update_qs(params):
    """Append key-value pairs to self.filter_string"""
    accepted_params = dict((k, v) for (k, v) in params.items() if v is not None)
    return "?" + urlencode(accepted_params)


def nd_argument_spec():
    return dict(
        host=dict(type="str", required=False, aliases=["hostname"], fallback=(env_fallback, ["ND_HOST"])),
        port=dict(type="int", required=False, fallback=(env_fallback, ["ND_PORT"])),
        username=dict(type="str", fallback=(env_fallback, ["ND_USERNAME", "ANSIBLE_NET_USERNAME"])),
        password=dict(type="str", required=False, no_log=True, fallback=(env_fallback, ["ND_PASSWORD", "ANSIBLE_NET_PASSWORD"])),
        output_level=dict(type="str", default="normal", choices=["debug", "info", "normal"], fallback=(env_fallback, ["ND_OUTPUT_LEVEL"])),
        timeout=dict(type="int", default=30, fallback=(env_fallback, ["ND_TIMEOUT"])),
        use_proxy=dict(type="bool", fallback=(env_fallback, ["ND_USE_PROXY"])),
        use_ssl=dict(type="bool", fallback=(env_fallback, ["ND_USE_SSL"])),
        validate_certs=dict(type="bool", fallback=(env_fallback, ["ND_VALIDATE_CERTS"])),
        login_domain=dict(type="str", fallback=(env_fallback, ["ND_LOGIN_DOMAIN"])),
    )


# Copied from ansible's module uri.py (url): https://github.com/ansible/ansible/blob/cdf62edc65f564fff6b7e575e084026fa7faa409/lib/ansible/modules/uri.py
def write_file(module, dest, content):
    # create a tempfile with some test content
    fd, tmpsrc = tempfile.mkstemp(dir=module.tmpdir)
    f = open(tmpsrc, "wb")
    try:
        f.write(content)
    except Exception as e:
        os.remove(tmpsrc)
        module.fail_json(msg="Failed to create temporary content file: {0}".format(to_native(e)))
    f.close()

    checksum_src = None
    checksum_dest = None

    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        os.remove(tmpsrc)
        module.fail_json(msg="Source '{0}' does not exist".format(tmpsrc))
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        module.fail_json(msg="Source '{0}' is not readable".format(tmpsrc))
    checksum_src = module.sha1(tmpsrc)

    # check if there is no dest file
    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination '{0}' not writable".format(dest))
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination '{0}' not readable".format(dest))
        checksum_dest = module.sha1(dest)
    else:
        if not os.access(os.path.dirname(dest), os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination dir '{0}' not writable".format(os.path.dirname(dest)))

    if checksum_src != checksum_dest:
        try:
            shutil.copyfile(tmpsrc, dest)
        except Exception as e:
            os.remove(tmpsrc)
            module.fail_json(msg="failed to copy {0} to {1}: {2}".format(tmpsrc, dest, to_native(e)))

    os.remove(tmpsrc)


class NDModule(object):
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = {"Content-Type": "application/json"}

        # normal output
        self.existing = dict()

        # nd_rest output
        self.jsondata = None
        self.error = dict(code=None, message=None, info=None)

        # info output
        self.previous = dict()
        self.proposed = dict()
        self.sent = dict()
        self.stdout = None

        # debug output
        self.has_modified = False
        self.filter_string = ""
        self.method = None
        self.path = None
        self.response = None
        self.status = None
        self.url = None
        self.httpapi_logs = list()

        if self.module._debug:
            self.module.warn("Enable debug output because ANSIBLE_DEBUG was set.")
            self.params["output_level"] = "debug"

    def request(self, path, method=None, data=None, file=None, qs=None, prefix="", file_key="file", output_format="json", ignore_not_found_error=False):
        """Generic HTTP method for ND requests."""
        self.path = path

        if method is not None:
            self.method = method

        # If we PATCH with empty operations, return
        if method == "PATCH" and not data:
            return {}

        conn = Connection(self.module._socket_path)
        conn.set_params(self.params)
        uri = self.path
        if prefix != "":
            uri = "{0}/{1}".format(prefix, self.path)
        if qs is not None:
            uri = uri + update_qs(qs)
        try:
            if file is not None:
                info = conn.send_file_request(method, uri, file, data, None, file_key)
            else:
                if data:
                    info = conn.send_request(method, uri, json.dumps(data))
                else:
                    info = conn.send_request(method, uri)
            self.result["data"] = data

            self.url = info.get("url")
            self.httpapi_logs.extend(conn.pop_messages())
            info.pop("date", None)
        except Exception as e:
            try:
                error_obj = json.loads(to_text(e))
            except Exception:
                error_obj = dict(error=dict(code=-1, message="Unable to parse error output as JSON. Raw error message: {0}".format(e), exception=to_text(e)))
                pass
            self.fail_json(msg=error_obj["error"]["message"])

        self.response = info.get("msg")
        self.status = info.get("status", -1)

        self.result["socket"] = self.module._socket_path

        # Get change status from HTTP headers
        if "modified" in info:
            self.has_modified = True
            if info.get("modified") == "false":
                self.result["changed"] = False
            elif info.get("modified") == "true":
                self.result["changed"] = True

        # 200: OK, 201: Created, 202: Accepted, 204: No Content
        if self.status in (200, 201, 202, 204):
            if output_format == "raw":
                return info.get("raw")
            return info.get("body")

        # 404: Not Found
        elif self.method == "DELETE" and self.status == 404:
            return {}

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status >= 400:
            self.result["status"] = self.status
            body = info.get("body")
            if body is not None:
                try:
                    if isinstance(body, dict):
                        payload = body
                    else:
                        payload = json.loads(body)
                except Exception as e:
                    self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
                    self.result["raw"] = body
                    self.fail_json(msg="ND Error: {0}".format(self.error.get("message")), data=data, info=info)
                self.error = payload
                if "code" in payload:
                    self.fail_json(msg="ND Error {code}: {message}".format(**payload), data=data, info=info, payload=payload)
                elif "messages" in payload and len(payload.get("messages")) > 0:
                    self.fail_json(msg="ND Error {code} ({severity}): {message}".format(**payload["messages"][0]), data=data, info=info, payload=payload)
                elif "errors" in payload and len(payload.get("errors", [])) > 0:
                    if ignore_not_found_error:
                        return {}
                    self.fail_json(msg="ND Error: {0}".format(payload["errors"][0]), data=data, info=info, payload=payload)
                else:
                    if ignore_not_found_error:
                        return {}
                    self.fail_json(msg="ND Error: Unknown error no error code in decoded payload".format(**payload), data=data, info=info, payload=payload)
            else:
                self.result["raw"] = info.get("raw")
                # Connection error
                msg = "Connection failed for {0}. {1}".format(info.get("url"), info.get("msg"))
                self.error = msg
                self.fail_json(msg=msg)
            return {}

    def query_objs(self, path, key=None, **kwargs):
        """Query the ND REST API for objects in a path"""
        found = []
        objs = self.request(path, method="GET", ignore_not_found_error=kwargs.pop("ignore_not_found_error", False))

        if objs == {}:
            return found

        if key is None:
            key = path

        if key not in objs:
            self.fail_json(msg="Key '{0}' missing from data".format(objs))

        for obj in objs.get(key):
            for kw_key, kw_value in kwargs.items():
                if kw_value is None:
                    continue
                if obj.get(kw_key) != kw_value:
                    break
            else:
                found.append(obj)
        return found

    def query_obj(self, path, **kwargs):
        """Query the ND REST API for the whole object at a path"""
        prefix = kwargs.pop("prefix", "")
        obj = self.request(path, method="GET", prefix=prefix, ignore_not_found_error=kwargs.pop("ignore_not_found_error", False))
        if obj == {}:
            return {}
        for kw_key, kw_value in kwargs.items():
            if kw_value is None:
                continue
            if obj.get(kw_key) != kw_value:
                return {}
        return obj

    def get_obj(self, path, **kwargs):
        """Get a specific object from a set of ND REST objects"""
        objs = self.query_objs(path, **kwargs)
        if len(objs) == 0:
            return {}
        if len(objs) > 1:
            self.fail_json(msg="More than one object matches unique filter: {0}".format(kwargs))
        return objs[0]

    def sanitize(self, updates, collate=False, required=None, unwanted=None):
        """Clean up unset keys from a request payload"""
        if required is None:
            required = []
        if unwanted is None:
            unwanted = []
        if isinstance(self.existing, dict):
            self.proposed = deepcopy(self.existing)
            self.sent = deepcopy(self.existing)

            for key in self.existing:
                # Remove References
                if key.endswith("Ref"):
                    del self.proposed[key]
                    del self.sent[key]
                    continue

                # Removed unwanted keys
                elif key in unwanted:
                    del self.proposed[key]
                    del self.sent[key]
                    continue

            # Clean up self.sent
            for key in updates:
                # Always retain 'id'
                if key in required:
                    if key in self.existing or updates.get(key) is not None:
                        self.sent[key] = updates.get(key)
                    continue

                # Remove unspecified values
                elif not collate and updates.get(key) is None:
                    if key in self.existing:
                        del self.sent[key]
                    continue

                # Remove identical values
                elif not collate and updates.get(key) == self.existing.get(key):
                    del self.sent[key]
                    continue

                # Add everything else
                if updates.get(key) is not None:
                    self.sent[key] = updates.get(key)

            # Update self.proposed
            self.proposed.update(self.sent)
        else:
            self.module.warn("Unable to sanitize the proposed and sent attributes because the current object is not a dictionary")
            self.proposed = self.sent = deepcopy(updates)

    def exit_json(self, **kwargs):
        """Custom written method to exit from module."""

        if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            self.result["method"] = self.method
            self.result["response"] = self.response
            self.result["status"] = self.status
            self.result["url"] = self.url
            self.result["httpapi_logs"] = self.httpapi_logs

            if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent
                self.result["proposed"] = self.proposed

        self.result["current"] = self.existing

        if self.module._diff and self.result.get("changed") is True:
            self.result["diff"] = dict(
                before=self.previous,
                after=self.existing,
            )

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        """Custom written method to return info on failure."""

        if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            if self.url is not None:
                self.result["method"] = self.method
                self.result["response"] = self.response
                self.result["status"] = self.status
                self.result["url"] = self.url
                self.result["httpapi_logs"] = self.httpapi_logs

            if self.params.get("state") in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent
                self.result["proposed"] = self.proposed

        self.result["current"] = self.existing

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def check_changed(self):
        """Check if changed by comparing new values from existing"""
        existing = self.existing
        if "password" in existing:
            existing["password"] = self.sent.get("password")
        return not issubset(self.sent, existing)

    def get_diff(self, unwanted=None):
        """Check if existing payload and sent payload and removing keys that are not required"""
        if unwanted is None:
            unwanted = []
        if not self.existing and self.sent:
            return True

        existing = self.existing
        sent = self.sent

        for key in unwanted:
            if isinstance(key, str):
                if key in existing:
                    try:
                        del existing[key]
                    except KeyError:
                        pass
                    try:
                        del sent[key]
                    except KeyError:
                        pass
            elif isinstance(key, list):
                key_path, last = key[:-1], key[-1]
                try:
                    existing_parent = reduce(dict.get, key_path, existing)
                    del existing_parent[last]
                except KeyError:
                    pass
                try:
                    sent_parent = reduce(dict.get, key_path, sent)
                    del sent_parent[last]
                except KeyError:
                    pass
        return not issubset(sent, existing)

    def set_to_empty_string_when_none(self, val):
        return val if val is not None else ""
