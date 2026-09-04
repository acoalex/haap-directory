# -*- coding: utf-8 -*-
"""Stable directory error codes (SPEC §4.10).

Every rejection surfaces a stable ``UPPER_SNAKE`` code with a fixed HTTP
status. Codes are API: never rename, never remove, add only. The human
``message`` is short and MUST NOT leak internals (SPEC §2.7.6).

Wire envelope:

    {"error": {"code": "<CODE>", "message": "<short>", "request_id": "<id>"}}
"""

from __future__ import annotations

from typing import Optional

# code -> HTTP status. This table IS the §4.10 master table; keep in sync.
ERROR_STATUS = {
    "INVALID_JSON": 400,
    "INVALID_SCHEMA": 400,
    "FORBIDDEN_FIELD": 400,
    "FLOAT_FORBIDDEN": 400,
    "SIGNATURE_MISMATCH": 400,
    "FINGERPRINT_MISMATCH": 400,
    "ENDPOINT_INVALID": 400,
    "DOMAIN_INVALID": 400,
    "MANIFEST_TOO_LARGE": 413,
    "PAYLOAD_TOO_LARGE": 413,
    "CHALLENGE_NOT_FOUND": 404,
    "CHALLENGE_EXPIRED": 410,
    "CHALLENGE_USED": 409,
    "KEY_MISMATCH": 400,
    "PROOF_INVALID": 400,
    "STALE_TIMESTAMP": 400,
    "UNKNOWN_OR_EXPIRED": 404,
    "AGENT_NOT_FOUND": 404,
    "AGENT_NOT_LISTED": 404,
    "DIRECTORY_FULL": 503,
    "RATE_LIMITED": 429,
    # L2/L3/L4 codes are reserved here so the table stays complete and
    # add-only as later phases wire their handlers in.
    "VOUCHER_NOT_LISTED": 400,
    "VOUCHEE_NOT_LISTED": 404,
    "VOUCH_INVALID": 400,
    "VOUCH_EXISTS": 409,
    "VOUCH_NOT_FOUND": 404,
    "VOUCH_LIMIT_REACHED": 429,
    "REPORT_INVALID": 400,
    "REPORT_EXISTS": 409,
    "REPORT_LIMIT_REACHED": 429,
    "REPORTER_NOT_ELIGIBLE": 403,
    "TARGET_NOT_LISTED": 404,
    "VERIFICATION_NOT_FOUND": 404,
    "VERIFICATION_EXPIRED": 410,
    "VERIFICATION_USED": 409,
    "VERIFICATION_LIMIT_REACHED": 429,
    "DNS_TXT_NOT_FOUND": 422,
    "WELL_KNOWN_NOT_FOUND": 422,
    "WELL_KNOWN_MISMATCH": 422,
    "DOMAIN_ENDPOINT_MISMATCH": 422,
    "DNS_ERROR_TEMPORARY": 503,
    "TAKEDOWN_UNAUTHORIZED": 403,
    "MODERATOR_UNKNOWN": 403,
    "METHOD_NOT_ALLOWED": 405,
    "UNSUPPORTED_VERSION": 400,
    "NOT_FOUND": 404,
    "INTERNAL_ERROR": 500,
    "UNAVAILABLE": 503,
}


class DirectoryError(Exception):
    """A rejection carrying a stable code, HTTP status and short message.

    Business logic raises these; the HTTP layer turns them into the wire
    error envelope. ``retry_after`` (seconds) is attached to 429 responses.
    """

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        retry_after: Optional[int] = None,
    ):
        self.code = code
        self.status = ERROR_STATUS.get(code, 400)
        self.message = message or _DEFAULT_MESSAGES.get(code, code.lower())
        self.retry_after = retry_after
        super().__init__(f"{code}: {self.message}")

    def to_wire(self, request_id: str) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "request_id": request_id,
            }
        }


_DEFAULT_MESSAGES = {
    "INVALID_JSON": "request body is not valid JSON",
    "INVALID_SCHEMA": "request does not match the expected schema",
    "FORBIDDEN_FIELD": "manifest contains a forbidden field",
    "FLOAT_FORBIDDEN": "floats are not allowed inside a signed object",
    "SIGNATURE_MISMATCH": "signature verification failed",
    "FINGERPRINT_MISMATCH": "fingerprint does not match the public key",
    "ENDPOINT_INVALID": "endpoint must be http(s) with no query or fragment",
    "MANIFEST_TOO_LARGE": "manifest exceeds the maximum size",
    "PAYLOAD_TOO_LARGE": "request body exceeds the maximum size",
    "CHALLENGE_NOT_FOUND": "no such challenge",
    "CHALLENGE_EXPIRED": "challenge has expired",
    "CHALLENGE_USED": "challenge already used",
    "KEY_MISMATCH": "public key does not match the registered challenge",
    "PROOF_INVALID": "endpoint proof is not signed by the bound key",
    "STALE_TIMESTAMP": "timestamp is outside the accepted clock skew",
    "UNKNOWN_OR_EXPIRED": "unknown or expired",
    "AGENT_NOT_FOUND": "no such agent",
    "AGENT_NOT_LISTED": "not currently listed",
    "DIRECTORY_FULL": "the directory has reached its agent capacity",
    "RATE_LIMITED": "too many requests",
    "METHOD_NOT_ALLOWED": "method not allowed for this route",
    "NOT_FOUND": "not found",
    "INTERNAL_ERROR": "internal error",
}
