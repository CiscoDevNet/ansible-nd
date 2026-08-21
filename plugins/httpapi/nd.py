# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: nd
short_description: Nexus Dashboard Ansible HTTPAPI Plugin.
description:
- This ND plugin provides the HTTPAPI transport methods needed to initiate
  a connection to ND, send API requests and process the response.
version_added: "0.1.0"
options:
  login_domain:
    description:
    - The login domain name to use for authentication.
    - The O(login_domain) is ignored when using an API Key in C(ansible_httpapi_session_key).
    - The default value is DefaultAuth.
    type: string
    env:
    - name: ANSIBLE_HTTPAPI_LOGIN_DOMAIN
    vars:
    - name: ansible_httpapi_login_domain
"""

import json
import mimetypes
import os
import pickle
import re
import sys
import tempfile
import traceback
from typing import Optional, Tuple

from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase

# Auth endpoint constants
AUTH_BASE_PATH_NEW = "/api/v1/infra"
LOGIN_ENDPOINT = "/login"
LOGOUT_ENDPOINT = "/logout"

try:
    from requests_toolbelt.multipart.encoder import MultipartEncoder

    HAS_MULTIPART_ENCODER = True
except ImportError:
    HAS_MULTIPART_ENCODER = False

if sys.version_info.major == 2:
    from StringIO import StringIO  # For Python 2+
else:
    from io import StringIO  # For Python 3+


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
        self.version = None

        # Cached auth endpoint base path, set after first successful login to new endpoint.
        # "" (default) means not yet detected or legacy, "/api/v1/infra" means ND 4.2.1+.
        self.auth_base_path: str = ""

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

    # Required for cisco.dcnm modules
    # The cisco.nd HTTPAPI provider only supports NDFC 12+
    # TODO Add support for more platforms.
    def get_version(self, platform="ndfc"):
        if platform == "ndfc":
            if self.version is None:
                self.version = 12
            return self.version
        elif platform == "nd":
            if self.version is None:
                # Unified ND 4.2.1+ reports the build version (e.g. "4.2.1.10") from /api/v1/infra/about.
                response_json = self._send_nd_request("GET", "/api/v1/infra/about", self.headers)
                self.version = response_json.get("body", {}).get("buildVersion")
            return self.version
        else:
            raise ValueError("Unknown platform type: {0}".format(platform))

    # Required for cisco.dcnm modules
    def get_token(self):
        return self.connection._auth

    # Required for cisco.dcnm modules
    def get_url_connection(self):
        return self.connection._url

    def _attempt_login(self, path: str, payload: dict) -> Tuple[Optional[str], int]:
        """Attempt a login POST to the given path.

        Args:
            path: The API path to send the login request to.
            payload: The login credentials payload.

        Returns:
            A tuple of (token, http_status). Token is None if the response
            status is not 200/201 or the response body is empty.

        Raises:
            Exception: Propagates any exception raised by the underlying
                connection send (e.g. socket errors, SSL errors).
        """
        method = "POST"
        data = json.dumps(payload)
        self.connection.queue_message("info", "login() - connection.send({0}, LOGIN_PAYLOAD_NOT_SHOWN, {1}, {2})".format(path, method, self.headers))
        response, response_data = self.connection.send(path, data, method=method, headers=self.headers)
        status = response.getcode()
        if status not in [200, 201] or (status == 200 and response_data.seek(0, 2) == 0):
            return None, status
        response_json = self._response_to_json(response_data)
        token = response_json.get("jwttoken") or response_json.get("token")
        return token, status

    def login(self, username: str, password: str) -> None:
        """Authenticate to Nexus Dashboard and store the bearer token.

        Supports both ND 4.2.1+ (``/api/v1/infra/login``) and legacy (``/login``)
        auth endpoints. On first call the method auto-detects which endpoint is
        available and caches the result in ``self.auth_base_path`` so subsequent
        re-authentications skip detection.

        Args:
            username: The username (unused directly; credentials are read from
                connection options or task params).
            password: The password (unused directly; see above).

        Raises:
            ConnectionError: When authentication fails on all attempted endpoints.
        """
        # Perform login request
        self.connection.queue_message("info", "login() - login method called for {0}".format(self.connection.get_option("host")))
        if self.connection._auth is None:
            self.connection.queue_message("info", "login() - previous auth not found sending login POST to {0}".format(self.connection.get_option("host")))

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

            try:
                # Auto-detect auth endpoint: try new path first (ND 4.2.1+), fall back to legacy
                if self.auth_base_path:
                    # Previously detected new endpoint, use cached path
                    path = self.auth_base_path + LOGIN_ENDPOINT
                    token, self.status = self._attempt_login(path, payload)
                else:
                    # Try new endpoint first (ND 4.2.1+)
                    path = AUTH_BASE_PATH_NEW + LOGIN_ENDPOINT
                    try:
                        token, self.status = self._attempt_login(path, payload)
                    except Exception as e:
                        self.connection.queue_message(
                            "debug",
                            "login() - new auth endpoint {0} failed ({1}), falling back to legacy endpoint".format(AUTH_BASE_PATH_NEW + LOGIN_ENDPOINT, e),
                        )
                        token, self.status = None, -1

                    if token is not None:
                        self.auth_base_path = AUTH_BASE_PATH_NEW
                        self.connection.queue_message("info", "login() - detected new auth endpoint: {0}".format(AUTH_BASE_PATH_NEW))
                    else:
                        # Fall back to legacy endpoint
                        path = LOGIN_ENDPOINT
                        token, self.status = self._attempt_login(path, payload)
                        if token is not None:
                            self.connection.queue_message("info", "login() - detected legacy auth endpoint: {0}".format(LOGIN_ENDPOINT))

                if token is None:
                    full_path = self.connection.get_option("host") + path
                    self.connection.queue_message("error", "login() - login status incorrect or response empty. HTTP status={0}".format(self.status))
                    json_response = "Most likely a wrong login domain was provided, the provided login_domain was {0}".format(self.get_option("login_domain"))
                    self.error = dict(code=self.status, message="Authentication failed: {0}".format(json_response))
                    raise ConnectionError(json.dumps(self._verify_response(None, "POST", full_path, None)))

                self.connection._auth = {
                    "Authorization": "Bearer {0}".format(token),
                    "Cookie": "AuthCookie={0}".format(token),
                }

            except ConnectionError as connection_err:
                self.connection.queue_message("error", "login() - ConnectionError Exception: {0}".format(connection_err))
                raise
            except Exception as e:
                self.connection.queue_message("error", "login() - Generic Exception: {0}".format(e))
                self.error = dict(code=self.status, message="Authentication failed: Request failed: {0}".format(e))
                raise ConnectionError(json.dumps(self._verify_response(None, "POST", self.connection.get_option("host") + LOGIN_ENDPOINT, None)))

    def logout(self) -> None:
        self.connection.queue_message("info", "logout() - logout method called for {0}".format(self.connection.get_option("host")))
        method = "POST"
        if self.auth_base_path:
            path = self.auth_base_path + LOGOUT_ENDPOINT
        else:
            path = LOGOUT_ENDPOINT

        try:
            self.connection.queue_message("info", "logout() - connection.send({0}, {1}, {2})".format(path, method, self.headers))
            response, response_data = self.connection.send(path, {}, method=method, headers=self.headers)
        except Exception as e:
            self.connection.queue_message("error", "logout() - Generic Exception: {0}".format(e))
            self.error = dict(code=self.status, message="Error on attempt to logout from ND. {0}".format(e))
            raise ConnectionError(json.dumps(self._verify_response(None, method, self.connection.get_option("host") + path, None)))
        self.connection._auth = None

    def send_request(self, method, path, data=None):
        """This method handles all json ND REST API requests other than login"""
        json_headers = {"Content-Type": "application/json"}
        return self._send_nd_request(method, path, json_headers, data)

    # Required for cisco.dcnm modules
    def send_txt_request(self, method, path, txt=None):
        """This method handles all text ND REST API requests"""
        txt_headers = {"Content-Type": "text/plain"}
        if txt is None:
            txt = ""
        return self._send_nd_request(method, path, txt_headers, txt)

    def _send_nd_request(self, method, path, headers, data=None):
        self.error = None
        self.path = ""
        self.status = -1
        self.info = {}
        self.method = "GET"
        if method is not None:
            self.method = method
        self.headers = headers

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

        # Support ND User API Key authorization within the session_key option.
        session_key = self.connection.get_option("session_key")
        user = self.connection.get_option("remote_user")
        if session_key and "X-Nd-Username" not in session_key.keys():
            self._queue_message_if_disconnected(
                "debug", "send_request() - authorizing with API key defined in `ansible_httpapi_session_key` and inserting username: {0}".format(user)
            )
            session_key_header = {
                "X-Nd-Username": user,
                "X-Nd-Apikey": list(session_key.values())[0],
            }
            self.connection.set_option("session_key", session_key_header)
        elif session_key:
            self._queue_message_if_disconnected(
                "debug",
                "send_request() - authorizing with ND API Key header defined in `ansible_httpapi_session_key` while ignoring username and password options.",
            )
        else:
            self._queue_message_if_disconnected("debug", "send_request() - authorizing with username and password options.")

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

    def send_file_request(self, method, path, file=None, data=None, remote_path=None, file_key="file", file_ext=None):
        """This method handles file download and upload operations
        :arg method (str): Method can be GET or POST
        :arg path (str): Path should be the resource path
        :arg file (str): The absolute file path of the target file
        :arg file_ext (str): The file extension, with leading dot, to be used for the file. If file has already an extension, it will be replaced
        :arg data (dict): Data should be the dictionary object
        :arg remote_path (str): Remote directory path to download/upload the file object

        :returns: Dict object which contains the status of the REST API call.
        The **response** contains the 'status' and other metadata. When a HttpError (status >= 400)
        occurred then ``response['body']`` contains the error response data:

        Example:
            response = send_file_request(
                            method="POST",
                            path="/mso/api/v1/backups/remoteUpload/63a018e587d6e5f7A",
                            file="/tmp/log.txt",
                            data={},
                            remote_path="/temp",
                        )
        """
        if data is None:
            data = dict()

        self.error = None
        self.path = ""
        self.status = -1
        self.info = {}
        self.method = "GET"
        if method is not None:
            self.method = method

        # If file_ext is provided, replace the file extension (if present) or add it
        if file_ext is not None:
            if not file_ext.startswith(".") or file_ext not in set(mimetypes.types_map.keys()):
                raise ValueError("Invalid file extension provided. Please provide a valid file extension, with leading dot")
            filename = os.path.splitext(os.path.basename(file))[0] + file_ext
        else:
            filename = os.path.basename(file)

        try:
            # create data field
            data["uploadedFileName"] = os.path.basename(file)
            data_str = StringIO()
            json.dump(data, data_str)
        except Exception as e:
            self.error = dict(code=self.status, message="ND HTTPAPI create data field Exception: {0} - {1}".format(e, traceback.format_exc()))
            raise ConnectionError(json.dumps(self._verify_response(None, method, path, None)))

        try:
            fields = None
            # create fields for MultipartEncoder
            if remote_path:
                fields = dict(rdir=remote_path, name=(filename, open(file, "rb"), mimetypes.guess_type(filename)))
            elif file_key in ["importfile", "files"]:
                fields = {file_key: (filename, open(file, "rb"), mimetypes.guess_type(filename))}
                if file_key == "importfile":
                    fields["spec"] = json.dumps(data)
            else:
                fields = dict(data=("data.json", data_str, "application/json"), file=(filename, open(file, "rb"), mimetypes.guess_type(filename)))

            if not HAS_MULTIPART_ENCODER:
                if sys.version_info.major == 2:
                    raise ImportError("Cannot use requests_toolbelt MultipartEncoder() because requests_toolbelt module is not available")
                else:
                    raise ModuleNotFoundError("Cannot use requests_toolbelt MultipartEncoder() because requests_toolbelt module is not available")

            mp_encoder = MultipartEncoder(fields=fields)
            multiheader = {"Content-Type": mp_encoder.content_type, "Accept": "*/*", "Accept-Encoding": "gzip, deflate, br"}
            self.connection.queue_message("debug", "send_file_request() - connection.send({0}, {1}, {2}, {3})".format(path, method, fields, multiheader))
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
        response_msg = None
        self.info.update(dict(url=path))
        if data is not None:
            response_data = self._response_to_json(data)
        if response is not None:
            response_code = response.getcode()
            response_msg = response.msg
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

        # Set info keys required for cisco.dcnm modules
        self.info["RETURN_CODE"] = response_code
        self.info["METHOD"] = method
        self.info["REQUEST_PATH"] = path
        self.info["DATA"] = response_data
        self.info["MESSAGE"] = response_msg

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
        temp_headers = {}
        for name, value in response.headers.items():
            # Lower case keys to create more consistent results
            name = name.lower()
            if name in temp_headers:
                temp_headers[name] = ", ".join((temp_headers[name], value))
            else:
                temp_headers[name] = value
        info.update(temp_headers)
        return info

    def get_remote_file_io_stream(self, path, tmpdir, method="GET"):
        """This method handles file download and upload operations
        :arg path (str): Path should be the resource path
        :arg tmpdir (str): Ansible module temporary execution directory which is used to create the temporary file object
        :arg method (str): Method can be GET or POST

        :returns: Dict object which contains the status of the REST API call.
        The **response** contains the 'status' and other metadata. When a HttpError (status >= 400)
        occurred then ``response['body']`` contains the error response data:

        Example:
            response = get_remote_file_io_stream(
                            path="/mso/api/v1/backups/remoteUpload/63a018e587d6e5f7A",
                            tmpdir="/tmp",
                            method="GET",
                        )
        """

        self.error = None
        self.path = ""
        self.status = -1
        self.info = {}

        try:
            response, rdata = self.connection.send(path, {}, method=method, headers=self.headers)
            verified_response = self._verify_response(response, method, path, rdata)
        except Exception as error:
            raise ConnectionError("File download operation failed due to: {0}".format(error))

        if verified_response["status"] in (301, 302, 303, 307):
            return verified_response
        elif verified_response["status"] == 404:
            raise ConnectionError(json.dumps(verified_response))

        fd, tmpsrc = tempfile.mkstemp(dir=tmpdir)
        f = open(tmpsrc, "wb")
        try:
            f.write(rdata.getvalue())
        except Exception as e:
            os.remove(tmpsrc)
            f.close()
            raise ConnectionError("Failed to the create temporary content file: {0}".format(to_native(e)))

        f.close()

        verified_response["tmpsrc"] = tmpsrc
        return verified_response

    def _queue_message_if_disconnected(self, level, msg):
        if not self.connection._connected:
            self.connection.queue_message(level, msg)
