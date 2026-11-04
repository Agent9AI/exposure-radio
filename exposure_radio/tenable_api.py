"""Pull a Tenable Vulnerability Management export into a snapshot directory.

Uses the documented export APIs, read-only, with your own API keys:

    POST /vulns/export                  -> export_uuid
    GET  /vulns/export/{uuid}/status    -> export-status.json
    GET  /vulns/export/{uuid}/chunks/N  -> vulns/chunk-N.json
    POST /assets/export, status, chunks -> assets.json

Keys come from TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in the environment,
or from the station host's private settings file. They are sent only to the
configured Tenable host over HTTPS, and never written into a snapshot.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path

DEFAULT_HOST = "https://cloud.tenable.com"
STATES = ["OPEN", "REOPENED", "FIXED"]


class TenableError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, access_key: str, secret_key: str, host: str = DEFAULT_HOST, timeout: float = 60.0):
        parsed = urllib.parse.urlsplit(host)
        if (parsed.scheme != "https" or parsed.hostname != "cloud.tenable.com"
                or parsed.port not in (None, 443) or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise TenableError("the Tenable host must be https://cloud.tenable.com")
        if not access_key or not secret_key:
            raise TenableError("Tenable access and secret keys are required")
        self.host, self.timeout = host.rstrip("/"), timeout
        self._auth = f"accessKey={access_key}; secretKey={secret_key}"

    @classmethod
    def from_env(cls, host: str | None = None) -> "Client":
        return cls(os.environ.get("TENABLE_ACCESS_KEY", ""), os.environ.get("TENABLE_SECRET_KEY", ""),
                   host or os.environ.get("TENABLE_HOST", DEFAULT_HOST))

    def request(self, method: str, path: str, body: dict | None = None, attempts: int = 6):
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(attempts):
            req = urllib.request.Request(self.host + path, data=data, method=method, headers={
                "X-ApiKeys": self._auth, "Accept": "application/json", "Content-Type": "application/json",
                "User-Agent": "ExposureRadio/0.6 (Integration/1.0)"})
            try:
                with urllib.request.build_opener(_NoRedirect()).open(req, timeout=self.timeout) as resp:  # noqa: S310 - https only
                    return json.loads(resp.read() or b"null")
            except urllib.error.HTTPError as exc:
                if exc.code == 429 or exc.code >= 500:
                    wait = float(exc.headers.get("Retry-After") or 2 ** attempt)
                    time.sleep(min(wait, 60))
                    continue
                if exc.code in (401, 403):
                    raise TenableError(f"Tenable refused the keys (HTTP {exc.code}); "
                                       "they need Vulnerability Management read access") from None
                raise TenableError(f"Tenable returned HTTP {exc.code} for {path}") from None
        raise TenableError(f"Tenable kept rate-limiting {path}; try again later")


def _wait(client: Client, kind: str, uuid: str, poll: float, limit: float) -> dict:
    deadline = time.monotonic() + limit
    while True:
        status = client.request("GET", f"/{kind}/export/{uuid}/status")
        state = str(status.get("status", "")).upper()
        if state == "FINISHED":
            return status
        if state in ("ERROR", "CANCELLED"):
            raise TenableError(f"the {kind} export ended with status {state}")
        if time.monotonic() > deadline:
            raise TenableError(f"the {kind} export did not finish within {int(limit)} seconds")
        time.sleep(poll)


def pull(out_dir: str | Path, client: Client, poll: float = 10.0, limit: float = 1800.0) -> dict:
    """Write one complete snapshot directory and return a short summary."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)
    (out / "vulns").mkdir(exist_ok=True, mode=0o700)
    os.chmod(out / "vulns", 0o700)

    def write_private(path: Path, content: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                fh.write(content)
        finally:
            if fd >= 0:
                os.close(fd)
    vuln_uuid = client.request("POST", "/vulns/export", {
        "num_assets": 50, "include_unlicensed": False,
        "filters": {"state": STATES, "severity": ["low", "medium", "high", "critical"]}})["export_uuid"]
    asset_uuid = client.request("POST", "/assets/export", {"chunk_size": 1000})["export_uuid"]

    status = _wait(client, "vulns", vuln_uuid, poll, limit)
    findings = 0
    for n in status.get("chunks_available", []):
        chunk = client.request("GET", f"/vulns/export/{vuln_uuid}/chunks/{int(n)}")
        findings += len(chunk or [])
        write_private(out / "vulns" / f"chunk-{int(n)}.json", json.dumps(chunk))
    astatus = _wait(client, "assets", asset_uuid, poll, limit)
    assets = []
    for n in astatus.get("chunks_available", []):
        assets.extend(client.request("GET", f"/assets/export/{asset_uuid}/chunks/{int(n)}") or [])
    write_private(out / "assets.json", json.dumps(assets))
    status.setdefault("filters", {"state": STATES})
    # The loader treats this file as the completion record; write it last.
    write_private(out / "export-status.json", json.dumps(status, indent=1))
    return {"out": str(out), "findings": findings, "assets": len(assets),
            "chunks": len(status.get("chunks_available", []))}
