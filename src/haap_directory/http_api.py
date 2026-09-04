# -*- coding: utf-8 -*-
"""HTTP surface — stdlib ``ThreadingHTTPServer`` (SPEC §4, §4.9).

Canonical routes live under ``/v1``; thin legacy aliases keep the unmodified
``haap`` client (``registry_client.py``) working:

    POST /register            -> submit registration (legacy body shape)
    POST /register/complete   -> complete proof-of-endpoint
    POST /heartbeat           -> unsigned {fingerprint} heartbeat
    GET  /search              -> bare-manifest results
    GET  /agents/{fp}         -> bare manifest
    GET  /health

Every response carries ``X-Request-Id``; rejections use the stable error
envelope ``{"error": {code, message, request_id}}``; 429s carry ``Retry-After``.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from .config import DirectoryConfig
from .crypto import KeyPair, b64e
from .errors import DirectoryError
from .rate_limit import RateLimiterSet
from .service import DirectoryService, SearchQuery
from .store import Store
from .timeutil import Clock, system_clock

_AGENT_RE = re.compile(r"^/(?:v1/)?agents/(HF-[0-9a-f]{16})$")


class DirectoryHTTPServer:
    """Owns the service, store and HTTP server for one directory instance."""

    def __init__(
        self,
        service: DirectoryService,
        config: DirectoryConfig,
        clock: Clock = system_clock,
    ):
        self.service = service
        self.config = config
        self.limiters = RateLimiterSet(config, clock)
        self._started_at = clock()
        self._clock = clock
        self._http: Optional[ThreadingHTTPServer] = None

    # -- construction ------------------------------------------------------
    @classmethod
    def build(
        cls,
        config: DirectoryConfig,
        keypair: KeyPair,
        clock: Clock = system_clock,
    ) -> "DirectoryHTTPServer":
        store = Store(config.db_path, clock=clock)
        service = DirectoryService(store, keypair, config, clock=clock)
        return cls(service, config, clock=clock)

    def uptime_s(self) -> float:
        return self._clock() - self._started_at

    # -- lifecycle ---------------------------------------------------------
    def start(self, host: Optional[str] = None, port: Optional[int] = None) -> ThreadingHTTPServer:
        host = host if host is not None else self.config.host
        port = port if port is not None else self.config.port
        self._http = ThreadingHTTPServer((host, port), self._make_handler())
        self._http.daemon_threads = True
        threading.Thread(target=self._http.serve_forever, daemon=True).start()
        return self._http

    def serve_forever(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        host = host if host is not None else self.config.host
        port = port if port is not None else self.config.port
        self._http = ThreadingHTTPServer((host, port), self._make_handler())
        self._http.daemon_threads = True
        self._http.serve_forever()

    def stop(self) -> None:
        if self._http is not None:
            self._http.shutdown()
            self._http.server_close()
            self._http = None
        self.service.store.close()

    # -- handler -----------------------------------------------------------
    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):  # silence default stderr logging
                pass

            # -- response helpers -----------------------------------------
            def _request_id(self) -> str:
                return self.headers.get("X-Request-Id") or ("req_" + secrets.token_hex(8))

            def _send(self, code: int, obj: dict, request_id: str, extra_headers=None):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Request-Id", request_id)
                for key, value in (extra_headers or {}).items():
                    self.send_header(key, str(value))
                self.end_headers()
                self.wfile.write(body)

            def _error(self, err: DirectoryError, request_id: str):
                headers = {}
                if err.retry_after is not None:
                    headers["Retry-After"] = err.retry_after
                self._send(err.status, err.to_wire(request_id), request_id, headers)

            def _rate_limit(self, limiter, key: str, request_id: str) -> bool:
                allowed, retry_after = limiter.check(key)
                if not allowed:
                    self._error(
                        DirectoryError("RATE_LIMITED", retry_after=retry_after), request_id
                    )
                    return False
                return True

            def _read_json(self, request_id: str) -> Optional[dict]:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length > server.config.max_body_bytes:
                    self._error(DirectoryError("PAYLOAD_TOO_LARGE"), request_id)
                    return None
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    data = json.loads(raw or b"{}")
                except (ValueError, json.JSONDecodeError):
                    self._error(DirectoryError("INVALID_JSON"), request_id)
                    return None
                if not isinstance(data, dict):
                    self._error(DirectoryError("INVALID_SCHEMA"), request_id)
                    return None
                return data

            def _client_ip(self) -> str:
                return self.client_address[0] if self.client_address else "unknown"

            # -- GET ------------------------------------------------------
            def do_GET(self):
                request_id = self._request_id()
                parsed = urlsplit(self.path)
                path = parsed.path
                try:
                    if path == "/health":
                        return self._send(
                            200, server.service.health(server.uptime_s()), request_id
                        )
                    if path in ("/v1/search", "/search"):
                        if not self._rate_limit(
                            server.limiters.search, self._client_ip(), request_id
                        ):
                            return None
                        return self._handle_search(parsed.query, path == "/v1/search", request_id)
                    if path == "/v1/audit/head":
                        return self._send(200, server.service.store.audit_head(), request_id)
                    if path == "/v1/audit/log":
                        return self._handle_audit_log(parsed.query, request_id)
                    m = _AGENT_RE.match(path)
                    if m:
                        return self._handle_agent(m.group(1), path.startswith("/v1/"), request_id)
                    return self._error(DirectoryError("NOT_FOUND"), request_id)
                except DirectoryError as err:
                    return self._error(err, request_id)
                except Exception:  # noqa: BLE001 - never leak internals
                    return self._error(DirectoryError("INTERNAL_ERROR"), request_id)

            def _handle_search(self, query_string: str, versioned: bool, request_id: str):
                qs = parse_qs(query_string)

                def one(name: str, default: str = "") -> str:
                    return (qs.get(name) or [default])[0]

                dv_raw = one("domain_verified")
                domain_verified = None
                if dv_raw:
                    domain_verified = dv_raw.lower() in ("1", "true", "yes")
                rr_raw = one("recent_reports_max")
                query = SearchQuery(
                    capability=one("capability"),
                    q=one("q"),
                    geo=one("geo"),
                    limit=int(one("limit", "20") or 20),
                    offset=int(one("offset", "0") or 0),
                    min_age_hours=float(one("min_age_hours", "0") or 0),
                    domain_verified=domain_verified,
                    not_suspended=(one("not_suspended", "true").lower() != "false"),
                    min_vouches_in=int(one("min_vouches_in", "0") or 0),
                    recent_reports_max=int(rr_raw) if rr_raw else None,
                )
                result = server.service.search(query)
                if versioned:
                    payload = {
                        "results": result["results"],
                        "total": result["total"],
                        "limit": result["limit"],
                        "offset": result["offset"],
                        "directory_fingerprint": result["directory_fingerprint"],
                    }
                else:
                    # Legacy shape: a bare list of manifests under "results".
                    payload = {"results": result["manifests"]}
                return self._send(200, payload, request_id)

            def _handle_agent(self, fingerprint: str, versioned: bool, request_id: str):
                try:
                    data = server.service.get_agent(fingerprint)
                except DirectoryError as err:
                    return self._error(err, request_id)
                if versioned:
                    return self._send(200, data, request_id)
                return self._send(200, data["manifest"], request_id)

            def _handle_audit_log(self, query_string: str, request_id: str):
                qs = parse_qs(query_string)
                after = int((qs.get("after") or ["-1"])[0])
                limit = int((qs.get("limit") or ["100"])[0])
                entries = server.service.store.audit_entries(after=after, limit=limit)
                head = server.service.store.audit_head()
                next_after = entries[-1]["seq"] if entries else after
                return self._send(
                    200,
                    {"entries": entries, "next_after": next_after, "head": head},
                    request_id,
                )

            # -- POST -----------------------------------------------------
            def do_POST(self):
                request_id = self._request_id()
                parsed = urlsplit(self.path)
                path = parsed.path
                try:
                    if path in ("/v1/register", "/register"):
                        if not self._rate_limit(
                            server.limiters.register, self._client_ip(), request_id
                        ):
                            return None
                        return self._handle_register(path == "/v1/register", request_id)
                    if path in (
                        "/v1/register/complete",
                        "/v1/register/challenge",
                        "/register/complete",
                    ):
                        return self._handle_complete(path.startswith("/v1/"), request_id)
                    if path in ("/v1/heartbeat", "/heartbeat"):
                        return self._handle_heartbeat(path == "/v1/heartbeat", request_id)
                    return self._error(DirectoryError("NOT_FOUND"), request_id)
                except DirectoryError as err:
                    return self._error(err, request_id)
                except Exception:  # noqa: BLE001
                    return self._error(DirectoryError("INTERNAL_ERROR"), request_id)

            def _handle_register(self, versioned: bool, request_id: str):
                data = self._read_json(request_id)
                if data is None:
                    return None
                result = server.service.submit_registration(
                    data.get("manifest"),
                    str(data.get("public_key_b64", "")),
                    str(data.get("manifest_signature", "")),
                )
                if versioned:
                    return self._send(202, result, request_id)
                # Legacy body: the client reads only ``challenge_nonce``.
                nonce = result["nonce"]
                signature = b64e(server.service.keypair.sign(nonce.encode("ascii")))
                legacy = {
                    "challenge_nonce": nonce,
                    "nonce": nonce,
                    "challenge_id": result["challenge_id"],
                    "registry_fingerprint": result["registry_fingerprint"],
                    "directory_fingerprint": result["directory_fingerprint"],
                    "registry_signature": signature,
                    "expires_at": result["expires_at"],
                }
                return self._send(200, legacy, request_id)

            def _handle_complete(self, versioned: bool, request_id: str):
                data = self._read_json(request_id)
                if data is None:
                    return None
                result = server.service.complete_registration(
                    fingerprint=str(data.get("fingerprint", "")),
                    endpoint_proof_b64=str(data.get("endpoint_proof", "")),
                    challenge_id=data.get("challenge_id"),
                    public_key_b64=str(data.get("public_key_b64", "")),
                )
                return self._send(201 if versioned else 200, result, request_id)

            def _handle_heartbeat(self, versioned: bool, request_id: str):
                data = self._read_json(request_id)
                if data is None:
                    return None
                fingerprint = str(data.get("fingerprint", ""))
                signed = bool(data.get("signature")) and bool(data.get("timestamp"))
                if versioned or signed:
                    result = server.service.heartbeat_v1(
                        fingerprint,
                        str(data.get("timestamp", "")),
                        str(data.get("signature", "")),
                    )
                    return self._send(200, result, request_id)
                # Legacy unsigned heartbeat.
                ok = server.service.heartbeat_legacy(fingerprint)
                if ok:
                    return self._send(200, {"status": "ok"}, request_id)
                return self._error(DirectoryError("UNKNOWN_OR_EXPIRED"), request_id)

        return Handler
