# Copyright (c) 2020 Cisco and/or its affiliates.
#
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
author:
- Lionel Hercot (@lhercot)
name: nd
short_description: Nexus Dashboard Ansible HTTPAPI Plugin.
description:
- This ND plugin provides the HTTPAPI transport methods needed to initiate
  a connection to ND, send API requests and process the response.
version_added: "0.0.1"
options:
  login_domain:
    description:
    - The login domain name to use for authentication.
    - The default value is DefaultAuth.
    type: string
    env:
    - name: ANSIBLE_HTTPAPI_LOGIN_DOMAIN
    vars:
    - name: ansible_httpapi_login_domain
"""

import os
import io
import re
import json
import pickle
import traceback
import mimetypes

from ansible.module_utils.six import PY3
from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase

try:
    from requests_toolbelt.multipart.encoder import MultipartEncoder

    HAS_MULTIPART_ENCODER = True
except ImportError:
    HAS_MULTIPART_ENCODER = False


class HttpApi(HttpApiBase):
    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.platform = "cisco.nd"
        self.headers = {"Content-Type": "application/json"}
        self.params = {}
        self.backup_hosts = None
        self.host_counter = 0

        self.error = None
        self.method = "GET"
        self.path = ""
        self.status = -1
        self.info = {}

    def get_platform(self):
        return self.platform

    def set_params(self, params):
        self.params = params

    def set_backup_hosts(self):
        try:
            list_of_hosts = re.sub(r"[[\]]", "", self.connection.get_option("host")).split(",")
            # ipaddress.ip_address(list_of_hosts[0])
            return list_of_hosts
        except Exception:
            return []

    def login(self, username, password):
        """Log in to ND"""
        # Perform login request
        self.connection.queue_message("info", "login() - login method called for {0}".format(self.connection.get_option("host")))
        if self.connection._auth is None:
            self.connection.queue_message("info", "login() - previous auth not found sending login POST to {0}".format(self.connection.get_option("host")))
            method = "POST"
            path = "/login"
            full_path = self.connection.get_option("host") + path

            payload = {
                "userName": self.connection.get_option("remote_user"),
                "userPasswd": self.connection.get_option("password"),
                "domain": self.get_option("login_domain"),
            }

            # Override the global username/password with the ones specified per task
            if self.params.get("username") is not None:
                payload["userName"] = self.params.get("username")
            if self.params.get("password") is not None:
                payload["userPasswd"] = self.params.get("password")

            data = json.dumps(payload)
            try:
                self.connection.queue_message("info", "login() - connection.send({0}, LOGIN_PAYLOAD_NOT_SHOWN, {1}, {2})".format(path, method, self.headers))
                response, response_data = self.connection.send(path, data, method=method, headers=self.headers)

                # Handle ND response
                self.status = response.getcode()
                if self.status not in [200, 201] or (self.status == 200 and response_data.getbuffer().nbytes == 0):
                    self.connection.queue_message("error", "login() - login status incorrect or response empty. HTTP status={0}".format(self.status))
                    json_response = "Most likely a wrong login domain was provided, the provided login_domain was {0}".format(self.get_option("login_domain"))
                    if self.status not in [200, 201]:
                        json_response = self._response_to_json(response_data)
                    self.error = dict(code=self.status, message="Authentication failed: {0}".format(json_response))
                    raise ConnectionError(json.dumps(self._verify_response(response, method, full_path, response_data)))
                self.connection._auth = {"Authorization": "Bearer {0}".format(self._response_to_json(response_data).get("token"))}

            except ConnectionError as connection_err:
                self.connection.queue_message("error", "login() - ConnectionError Exception: {0}".format(connection_err))
                raise
            except Exception as e:
                self.connection.queue_message("error", "login() - Generic Exception: {0}".format(e))
                self.error = dict(code=self.status, message="Authentication failed: Request failed: {0}".format(e))
                raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))

    def logout(self):
        self.connection.queue_message("info", "logout() - logout method called for {0}".format(self.connection.get_option("host")))
        method = "POST"
        path = "/logout"

        try:
            self.connection.queue_message("info", "logout() - connection.send({0}, {1}, {2})".format(path, method, self.headers))
            response, response_data = self.connection.send(path, {}, method=method, headers=self.headers)
        except Exception as e:
            self.connection.queue_message("error", "logout() - Generic Exception: {0}".format(e))
            self.error = dict(code=self.status, message="Error on attempt to logout from ND. {0}".format(e))
            raise ConnectionError(json.dumps(self._verify_response(None, method, self.connection.get_option("host") + path, None)))
        self.connection._auth = None

    def send_request(self, method, path, data=None):
        """This method handles all ND REST API requests other than login"""

        self.error = None
        self.path = ""
        self.status = -1
        self.info = {}
        self.method = "GET"
        if method is not None:
            self.method = method

        self.connection.queue_message("info", "send_request() - send_request method called")
        # # Case1: List of hosts is provided
        # self.backup_hosts = self.set_backup_hosts()
        # if not self.backup_hosts:

        if self.params.get("host") is not None:
            if self.connection._connected is True and self.params.get("host") != self.connection.get_option("host"):
                self.connection._connected = False
                self.connection.queue_message(
                    "info",
                    "send_request() - reseting connection as host has changed from {0} to {1}".format(
                        self.connection.get_option("host"), self.params.get("host")
                    ),
                )
            self.connection.set_option("host", self.params.get("host"))

        if self.params.get("login_domain") is not None:
            self.set_option("login_domain", self.params.get("login_domain"))
        elif self.get_option("login_domain") is None:
            self.set_option("login_domain", "DefaultAuth")

        if self.params.get("port") is not None:
            self.connection.set_option("port", self.params.get("port"))

        if self.params.get("username") is not None:
            self.connection.set_option("remote_user", self.params.get("username"))

        if self.params.get("password") is not None:
            self.connection.set_option("password", self.params.get("password"))

        if self.params.get("use_proxy") is not None:
            self.connection.set_option("use_proxy", self.params.get("use_proxy"))

        if self.params.get("use_ssl") is not None:
            self.connection.set_option("use_ssl", self.params.get("use_ssl"))

        if self.params.get("validate_certs") is not None:
            self.connection.set_option("validate_certs", self.params.get("validate_certs"))

        if self.params.get("timeout") is not None:
            self.connection.set_option("persistent_command_timeout", self.params.get("timeout"))

        # Perform some very basic path input validation.
        path = str(path)
        if path[0] != "/":
            self.error = dict(code=self.status, message="Value of <path> does not appear to be formated properly")
            raise ConnectionError(json.dumps(self._verify_response(None, method, path, None)))
        full_path = self.connection.get_option("host") + path
        try:
            self.connection.queue_message("info", "send_request() - connection.send({0}, {1}, {2}, {3})".format(path, data, method, self.headers))
            response, rdata = self.connection.send(path, data, method=method, headers=self.headers)
        except ConnectionError as connection_err:
            self.connection.queue_message("info", "send_request() - ConnectionError Exception: {0}".format(connection_err))
            raise
        except Exception as e:
            self.connection.queue_message("info", "send_request() - Generic Exception: {0}".format(e))
            if self.error is None:
                self.error = dict(code=self.status, message="ND HTTPAPI send_request() Exception: {0} - {1}".format(e, traceback.format_exc()))
            raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))
        return self._verify_response(response, method, full_path, rdata)

    def send_file_request(self, method, path, file=None, data=None):
        """This method handles all ND REST API requests other than login"""

        self.error = None
        self.path = ""
        self.status = -1
        self.info = {}
        self.method = "GET"
        if method is not None:
            self.method = method

        try:
            # create data field
            data["uploadedFileName"] = os.path.basename(file)
            data_str = io.StringIO()
            json.dump(data, data_str)
        except Exception as e:
            self.error = dict(code=self.status, message="ND HTTPAPI create data field Exception: {0} - {1}".format(e, traceback.format_exc()))
            raise ConnectionError(json.dumps(self._verify_response(None, method, path, None)))

        try:
            # create fields for MultipartEncoder
            fields = dict(data=("data.json", data_str, "application/json"), file=(os.path.basename(file), open(file, "rb"), mimetypes.guess_type(file)))
            if not HAS_MULTIPART_ENCODER:
                self.nd.fail_json(msg="Cannot use requests_toolbelt MultipartEncoder() because requests_toolbelt module is not available")
            mp_encoder = MultipartEncoder(fields=fields)
            multiheader = {"Content-Type": mp_encoder.content_type, "Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"}
            response, rdata = self.connection.send(path, mp_encoder.to_string(), method=method, headers=multiheader)
        except Exception as e:
            self.error = dict(code=self.status, message="ND HTTPAPI MultipartEncoder Exception: {0} - {1} ".format(e, traceback.format_exc()))
            raise ConnectionError(json.dumps(self._verify_response(None, method, path, None)))
        return self._verify_response(response, method, path, rdata)

    def handle_error(self):
        self.connection.queue_message("info", "handle_error() - handle_error method called")
        self.host_counter += 1
        if self.host_counter == len(self.backup_hosts):
            raise ConnectionError("No hosts left in cluster to continue operation")
        with open("my_hosts.pk", "wb") as host_file:
            pickle.dump(self.host_counter, host_file)
        try:
            self.connection.set_option("host", self.backup_hosts[self.host_counter])
        except IndexError:
            pass
        self.connection.queue_message("info", "handle_error() - clearing auth and calling login() again")
        self.connection._auth = None
        self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))
        return True

    def _verify_response(self, response, method, path, data):
        """Process the return code and response object from ND"""
        response_data = None
        response_code = -1
        self.info.update(dict(url=path))
        if data is not None:
            response_data = self._response_to_json(data)
        if response is not None:
            response_code = response.getcode()
            path = response.geturl()
            self.info.update(self._get_formated_info(response))

            # Handle possible ND error information
            if response_code not in [200, 201, 202, 204]:
                self.error = dict(code=self.status, message=response_data)

        self.info["method"] = method
        if self.error is not None:
            self.info["error"] = self.error
        # if msg is None:
        #     self.info['msg'] = str(self.info)
        # else:
        #     self.info['msg'] = msg
        self.info["body"] = response_data

        return self.info

    def _response_to_json(self, response_data):
        """Convert response_data to json format"""
        try:
            response_value = response_data.getvalue()
        except Exception:
            response_value = response_data
        response_text = to_text(response_value)
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except Exception as e:
            # Expose RAW output for troubleshooting
            self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
            self.info["raw"] = response_text
            return

    def _get_formated_info(self, response):
        """The code in this function is based on Ansible fetch_url code at https://github.com/ansible/ansible/blob/devel/lib/ansible/module_utils/urls.py"""
        info = dict(msg="OK (%s bytes)" % response.headers.get("Content-Length", "unknown"), url=response.geturl(), status=response.getcode())
        # Lowercase keys, to conform to py2 behavior, so that py3 and py2 are predictable
        info.update(dict((k.lower(), v) for k, v in response.info().items()))

        # Don't be lossy, append header values for duplicate headers
        # In Py2 there is nothing that needs done, py2 does this for us
        if PY3:
            temp_headers = {}
            for name, value in response.headers.items():
                # The same as above, lower case keys to match py2 behavior, and create more consistent results
                name = name.lower()
                if name in temp_headers:
                    temp_headers[name] = ", ".join((temp_headers[name], value))
                else:
                    temp_headers[name] = value
            info.update(temp_headers)
        return info
