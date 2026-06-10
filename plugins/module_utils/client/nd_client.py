# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Persistent REST client for Cisco Nexus Dashboard.

Holds a ``requests.Session`` with the Bearer token in session headers so every
request reuses the same TCP/TLS connection. Features: one login per client,
401 auto re-login, transient-network retry, and an on-disk session cache so
Ansible workers that fork per task can still share a single login.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import json as json_lib
import os
import time

try:
    import requests
    import urllib3
    from requests.adapters import HTTPAdapter

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class NDClientError(Exception):
    """Raised for any ND client level error (connection, auth, parsing)."""


class NDClient(object):
    """REST client that persists one authenticated ``requests.Session`` per instance."""

    MAX_NETWORK_ATTEMPTS = 3
    NETWORK_BACKOFF_BASE = 0.5

    SESSION_CACHE_TTL = 900

    def __init__(
        self,
        host,
        username,
        password,
        port=443,
        login_domain="DefaultAuth",
        verify_certs=True,
        timeout=30,
    ):
        if not HAS_REQUESTS:
            raise NDClientError(
                "NDClient requires the 'requests' library. Install with: pip install requests"
            )

        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.login_domain = login_domain
        self.verify_certs = bool(verify_certs)
        self.timeout = int(timeout)

        self.base_url = "https://{0}:{1}".format(host, self.port)

        self._session = None
        self._token = None

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def ensure_session(self):
        """Prefer in process session, then on disk cache, then a fresh /login."""
        if self._session is not None:
            return
        if self._try_load_session():
            return
        self._connect()

    def _connect(self):
        """Perform a /login, store the Bearer token, and persist to the on disk cache."""
        if not self.verify_certs:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if self._session is not None:
            self._session.close()

        session = requests.Session()
        session.verify = self.verify_certs
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=10)
        session.mount("https://", adapter)
        session.headers.update({"Content-Type": "application/json"})

        payload = {
            "userName": self.username,
            "userPasswd": self.password,
            "domain": self.login_domain,
        }

        try:
            resp = session.post(self.base_url + "/login", json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise NDClientError("ND login request failed: {0}".format(e))

        if resp.status_code not in (200, 201):
            raise NDClientError(
                "ND login failed: HTTP {0}: {1}".format(resp.status_code, resp.text[:500])
            )

        try:
            body = resp.json()
        except ValueError:
            raise NDClientError("ND login response was not JSON")

        token = body.get("token") or body.get("jwttoken")
        if not token:
            raise NDClientError(
                "ND login response contained no token. Response: {0}".format(body)
            )

        self._token = token
        session.headers.update(
            {
                "Authorization": "Bearer {0}".format(token),
                "Cookie": "AuthCookie={0}".format(token),
            }
        )

        self._session = session
        self._save_session()

    def close(self):
        """Logout from ND and close the local HTTP session (leaves the shared cache alone)."""
        if self._session is not None:
            try:
                self._session.post(self.base_url + "/logout", timeout=5)
            except Exception:
                pass
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None
            self._token = None

    def invalidate_session_cache(self):
        """Delete the shared on disk session cache (explicit logout only)."""
        self._invalidate_session_cache()

    @classmethod
    def _session_cache_dir(cls):
        """Return the per user cache directory under XDG_CACHE_HOME (or ~/.cache)."""
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
        return os.path.join(base, "ansible-cisco-nd")

    def _cache_file_path(self):
        """Return the cache file path for this (host, user, port) triple."""
        key = "{0}:{1}:{2}".format(self.host, self.username, self.port)
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        return os.path.join(self._session_cache_dir(), "nd_session_{0}.json".format(digest))

    def _try_load_session(self):
        """Hydrate ``self._session`` from the on disk cache; return True on success."""
        path = self._cache_file_path()
        try:
            with open(path) as f:
                data = json_lib.load(f)
        except (OSError, ValueError):
            return False

        token = data.get("token")
        ts = data.get("ts", 0)
        if not token or (time.time() - ts) > self.SESSION_CACHE_TTL:
            return False

        if not self.verify_certs:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = requests.Session()
        session.verify = self.verify_certs
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=10)
        session.mount("https://", adapter)
        session.headers.update(
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer {0}".format(token),
                "Cookie": "AuthCookie={0}".format(token),
            }
        )

        self._session = session
        self._token = token
        return True

    def _save_session(self):
        """Atomically write the current (token, timestamp) to the cache file."""
        if not self._token:
            return
        cache_dir = self._session_cache_dir()
        try:
            os.makedirs(cache_dir, mode=0o700, exist_ok=True)
            try:
                os.chmod(cache_dir, 0o700)
            except OSError:
                pass
        except OSError:
            return

        path = self._cache_file_path()
        tmp_path = path + ".{0}.tmp".format(os.getpid())
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w") as f:
                    json_lib.dump({"ts": time.time(), "token": self._token}, f)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            os.replace(tmp_path, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError:
            pass

    def _invalidate_session_cache(self):
        """Remove the on disk cache file (best effort)."""
        try:
            os.unlink(self._cache_file_path())
        except OSError:
            pass

    def request(self, method, path, data=None):
        """Issue an HTTP request to ND and return an info dict matching httpapi shape.

        Retries once on HTTP 401 (silent re-login) and up to MAX_NETWORK_ATTEMPTS
        on transient ``ConnectionError`` / ``Timeout`` with linear backoff. Any
        other request exception is wrapped as ``ConnectionError`` with a JSON
        body to mirror what the httpapi plugin raises.
        """
        if self._session is None:
            self._connect()

        if path.startswith("/"):
            url = self.base_url + path
        else:
            url = self.base_url + "/" + path

        request_kwargs = {"timeout": self.timeout}
        if isinstance(data, (str, bytes)):
            request_kwargs["data"] = data
        elif data is not None:
            request_kwargs["json"] = data

        resp = None
        auth_retried = False
        attempt = 0
        while attempt < self.MAX_NETWORK_ATTEMPTS:
            try:
                resp = self._session.request(method, url, **request_kwargs)
            except (requests.ConnectionError, requests.Timeout) as e:
                attempt += 1
                if attempt >= self.MAX_NETWORK_ATTEMPTS:
                    err = {
                        "error": {
                            "code": -1,
                            "message": "Network error contacting ND after {0} attempts: {1}".format(
                                attempt, e
                            ),
                        }
                    }
                    raise ConnectionError(json_lib.dumps(err))
                time.sleep(self.NETWORK_BACKOFF_BASE * attempt)
                continue
            except requests.RequestException as e:
                err = {
                    "error": {
                        "code": -1,
                        "message": "Network error contacting ND: {0}".format(e),
                    }
                }
                raise ConnectionError(json_lib.dumps(err))

            if resp.status_code == 401 and not auth_retried:
                self._connect()
                auth_retried = True
                continue
            break

        return self._build_info(resp, method, url)

    def get_version(self, platform="nd"):
        """Mirror of httpapi ``get_version`` used by ``NDModule.version``."""
        if platform == "ndfc":
            return 12
        info = self.request("GET", "/version.json")
        body = info.get("body")
        if isinstance(body, dict):
            try:
                return "{0}.{1}.{2}".format(body["major"], body["minor"], body["maintenance"])
            except KeyError:
                pass
        return "unknown"

    def _build_info(self, resp, method, url):
        """Convert a ``requests.Response`` into the dict shape NDModule expects."""
        raw_text = resp.text if resp.content else ""
        body_json = None
        if resp.content:
            try:
                body_json = resp.json()
            except Exception:
                body_json = None

        info = {
            "url": url,
            "status": resp.status_code,
            "msg": "OK ({0} bytes)".format(len(resp.content)),
            "method": method,
            "body": body_json if body_json is not None else raw_text,
            "raw": raw_text,
            "RETURN_CODE": resp.status_code,
            "METHOD": method,
            "REQUEST_PATH": url,
            "DATA": body_json,
            "MESSAGE": resp.reason or "OK",
        }

        for k, v in resp.headers.items():
            info[k.lower()] = v

        return info
