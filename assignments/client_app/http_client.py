from __future__ import annotations

import time
from typing import Any, Callable

import requests


class APIError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class HTTPClient:
    def __init__(self, base_url: str, network_logger: Callable[..., None] | None = None):
        self.base_url = base_url.rstrip("/")
        self.network_logger = network_logger

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _request_json(self, method: str, path: str, json_body: dict) -> tuple[requests.Response, Any]:
        started_ts = int(time.time())
        started_perf = time.perf_counter()
        resp = requests.request(
            method=method,
            url=self._url(path),
            json=json_body,
            timeout=5,
        )
        duration_ms = int((time.perf_counter() - started_perf) * 1000)
        try:
            resp_json: Any = resp.json()
        except ValueError:
            resp_json = {"raw_text": resp.text}

        if self.network_logger is not None:
            self.network_logger(
                method.upper(),
                path,
                json_body,
                resp.status_code,
                resp_json,
                started_ts=started_ts,
                duration_ms=duration_ms,
                request_headers_obj={
                    "content_type": "application/json",
                    "authorization_present": False,
                },
                response_headers_obj={
                    "content_type": resp.headers.get("Content-Type", ""),
                },
            )
        return resp, resp_json

    def channel_open(self, client_hello: dict) -> dict:
        r, data = self._request_json(
            method="POST",
            path="/api/channel/open",
            json_body={"client_hello": client_hello},
        )
        if r.status_code == 400:
            raise APIError("bad_client_hello")
        r.raise_for_status()
        return dict(data["server_hello"])

    def post_record(self, path: str, session_id_b64: str, record_obj: dict) -> dict:
        r, data = self._request_json(
            method="POST",
            path=path,
            json_body={"session_id_b64": session_id_b64, "record": record_obj},
        )
        if r.status_code == 401:
            raise APIError(str(data.get("error") or "unauthorized"))
        if r.status_code == 400:
            raise APIError(str(data.get("error") or "bad_record"))
        r.raise_for_status()
        return dict(data["record"])
