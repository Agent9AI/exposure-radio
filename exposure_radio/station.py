"""Station host: serves the listener and console, and keeps settings private.

    python3 -m exposure_radio station serve            # http://127.0.0.1:8080
    python3 -m exposure_radio station keys set tenable
    python3 -m exposure_radio station pull             # fresh Tenable export

Settings and keys live in one private file (mode 600) under
``$EXPOSURE_RADIO_HOME`` (default ``~/.config/exposure-radio``). The browser
never receives a key: the console only learns whether one is configured.
Every write needs the admin token printed when the host starts.
"""

from __future__ import annotations

import copy
import getpass
import hmac
import json
import os
import secrets
import sys
from datetime import date
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "web"
SEGMENT_KINDS = ("exposure", "wins", "blindspots", "learn", "weather", "news", "music")
DEFAULTS = {
    "station": {"name": "Exposure Radio", "address": "", "edition": "Synthetic sample"},
    "segments": {
        "exposure": {"enabled": True, "per_hour": 2}, "wins": {"enabled": True, "per_hour": 1},
        "blindspots": {"enabled": True, "per_hour": 1}, "learn": {"enabled": True, "per_hour": 2},
        "weather": {"enabled": True, "per_hour": 1}, "news": {"enabled": True, "per_hour": 1},
        "music": {"enabled": True, "per_hour": 6},
    },
    "quiet_hours": {"start": "", "end": ""},
    "priority_interrupts": True,
    "gemini": {"tier": "free"},
    "voices": {"engine": "kokoro", "cloud_seconds_per_day": 900},
    "tenable": {"host": "https://cloud.tenable.com"},
    "learn": {"topics": []},
    "queue": {"order": []},
}
KEY_FIELDS = {"tenable": ("access_key", "secret_key"), "gemini": ("api_key",)}
MAX_BODY = 64 * 1024


def home() -> Path:
    return Path(os.environ.get("EXPOSURE_RADIO_HOME", Path.home() / ".config" / "exposure-radio"))


def _merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or home()
        self.path = self.root / "settings.json"

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write(self, doc: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        os.replace(tmp, self.path)

    def settings(self) -> dict:
        doc = self._read()
        out = _merge(DEFAULTS, {k: v for k, v in doc.items() if k != "secrets"})
        out["keys"] = {p: {"configured": all(doc.get("secrets", {}).get(p, {}).get(f) for f in fields)}
                       for p, fields in KEY_FIELDS.items()}
        return out

    def update(self, patch: dict) -> dict:
        clean = validate_settings(patch)
        doc = self._read()
        secret = doc.pop("secrets", {})
        doc = _merge(doc, clean)
        doc["secrets"] = secret
        self._write(doc)
        return self.settings()

    def set_keys(self, provider: str, values: dict) -> None:
        if provider not in KEY_FIELDS:
            raise ValueError(f"unknown provider {provider!r}")
        fields = KEY_FIELDS[provider]
        if set(values) - set(fields) or not all(isinstance(values.get(f), str) and 8 <= len(values[f]) <= 256
                                                for f in fields):
            raise ValueError(f"{provider} needs {', '.join(fields)}")
        doc = self._read()
        doc.setdefault("secrets", {})[provider] = {f: values[f].strip() for f in fields}
        self._write(doc)

    def secret(self, provider: str) -> dict:
        return dict(self._read().get("secrets", {}).get(provider, {}))


def validate_settings(patch: object) -> dict:
    """Accept only known settings with sane types; anything else is an error."""
    if not isinstance(patch, dict):
        raise ValueError("settings must be an object")
    out: dict = {}
    for key, value in patch.items():
        if key == "keys":
            continue   # read-only status; keys are set through /api/keys
        if key not in DEFAULTS or key in ("queue",):
            raise ValueError(f"unknown setting {key!r}")
        default = DEFAULTS[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
            out[key] = value
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be an object")
        section = {}
        for sub, v in value.items():
            if key == "segments":
                if sub not in SEGMENT_KINDS or not isinstance(v, dict):
                    raise ValueError(f"unknown segment {sub!r}")
                enabled, per_hour = v.get("enabled", True), v.get("per_hour", 1)
                if not isinstance(enabled, bool) or not isinstance(per_hour, int) or not 0 <= per_hour <= 12:
                    raise ValueError(f"segment {sub} needs enabled true/false and per_hour 0-12")
                section[sub] = {"enabled": enabled, "per_hour": per_hour}
            elif key == "learn":
                if sub != "topics" or not isinstance(v, list) or len(v) > 50:
                    raise ValueError("learn.topics must be a list of up to 50 topics")
                section[sub] = [{"title": str(t.get("title", ""))[:120],
                                 "status": t.get("status") if t.get("status") in ("aired", "queued", "suggested")
                                 else "suggested"} for t in v if isinstance(t, dict) and t.get("title")]
            else:
                if sub not in default:
                    raise ValueError(f"unknown setting {key}.{sub}")
                expected = type(default[sub])
                if expected is int and (not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 86400):
                    raise ValueError(f"{key}.{sub} must be a whole number")
                if expected is str and (not isinstance(v, str) or len(v) > 200):
                    raise ValueError(f"{key}.{sub} must be short text")
                section[sub] = v
        if key == "gemini" and section.get("tier", "free") not in ("free", "paid"):
            raise ValueError("gemini.tier must be free or paid")
        if key == "voices" and section.get("engine", "kokoro") not in ("kokoro", "gemini"):
            raise ValueError("voices.engine must be kokoro or gemini")
        if key == "tenable" and not str(section.get("host", "https://")).startswith("https://"):
            raise ValueError("tenable.host must be an https URL")
        out[key] = section
    return out


def cloud_voice_allowed(settings: dict, kind: str) -> bool:
    """Exposure segments reach a cloud voice only on a paid Gemini project."""
    if settings.get("voices", {}).get("engine") != "gemini" or not settings["keys"]["gemini"]["configured"]:
        return False
    if kind in ("exposure", "wins", "blindspots"):
        return settings.get("gemini", {}).get("tier") == "paid"
    return True


class Handler(SimpleHTTPRequestHandler):
    store: Store
    token: str
    allowed_hosts: set[str]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def log_message(self, fmt, *args):  # quieter; never logs headers or bodies
        sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data: https://i.ytimg.com; media-src 'self'; "
                         "script-src 'self' https://www.youtube.com https://s.ytimg.com; "
                         "frame-src https://www.youtube.com https://www.youtube-nocookie.com; "
                         "style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        super().end_headers()

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        return host in self.allowed_hosts

    def _json(self, status: int, doc: object) -> None:
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> object:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Admin-Token", "")
        return bool(supplied) and hmac.compare_digest(supplied, self.token)

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "unexpected host"})
        path = self.path.split("?")[0]
        if path == "/api/station":
            return self._json(200, station_document(self.store))
        if path == "/api/settings":
            return self._json(200, self.store.settings())
        if path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        return super().do_GET()

    def _write_api(self, method: str):
        if not self._host_ok():
            return self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "unexpected host"})
        if not self._authorized():
            return self._json(401, {"error": "admin token required"})
        path = self.path.split("?")[0]
        try:
            body = self._body()
            if method == "PUT" and path == "/api/settings":
                return self._json(200, self.store.update(body))
            if method == "POST" and path == "/api/keys":
                self.store.set_keys(str(body.get("provider")), body.get("values") or {})
                return self._json(200, self.store.settings()["keys"])
            if method == "POST" and path == "/api/queue":
                return self._json(200, update_queue(self.store, body))
            if method == "POST" and path == "/api/learn/suggest":
                from .gemini import GeminiError, suggest_topics
                key = self.store.secret("gemini").get("api_key", "")
                try:
                    found = suggest_topics(key)
                except GeminiError as exc:
                    return self._json(503, {"error": str(exc)})
                topics = self.store.settings()["learn"]["topics"] + [
                    {"title": t["title"], "status": "suggested"} for t in found["topics"]]
                self.store.update({"learn": {"topics": topics}})
                return self._json(200, found)
            if method == "POST" and path == "/api/learn":
                title = str(body.get("title", "")).strip()[:120]
                if not title:
                    raise ValueError("a topic title is required")
                topics = self.store.settings()["learn"]["topics"] + [{"title": title, "status": "queued"}]
                return self._json(200, self.store.update({"learn": {"topics": topics}}))
        except (ValueError, AttributeError, TypeError) as exc:
            return self._json(400, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        self._write_api("PUT")

    def do_POST(self):  # noqa: N802
        self._write_api("POST")


def station_document(store: Store) -> dict:
    path = WEB / "station" / "station.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    settings = store.settings()
    order = settings["queue"]["order"]
    if order:
        by_id = {s["id"]: s for s in doc["rundown"]}
        doc["rundown"] = [by_id[i] for i in order if i in by_id]
    enabled = {k for k, v in settings["segments"].items() if v.get("enabled", True)}
    doc["rundown"] = [s for s in doc["rundown"] if s["kind"] in ("ident",) or s["kind"] in enabled]
    if settings["station"].get("name"):
        doc["station"]["name"] = settings["station"]["name"]
    doc["host"] = {"mode": "station-host", "today": date.today().isoformat()}
    return doc


def update_queue(store: Store, body: dict) -> dict:
    doc = json.loads((WEB / "station" / "station.json").read_text(encoding="utf-8"))
    ids = [s["id"] for s in doc["rundown"]]
    order = [i for i in store.settings()["queue"]["order"] if i in ids] or ids
    order += [i for i in ids if i not in order]
    action, seg = body.get("action"), body.get("id")
    if seg not in order:
        raise ValueError("unknown segment")
    if action == "remove":
        order.remove(seg)
    elif action in ("move", "play_next"):
        order.remove(seg)
        to = body.get("to", 1 if action == "play_next" else 0)
        if not isinstance(to, int):
            raise ValueError("'to' must be a position")
        order.insert(max(0, min(to, len(order))), seg)
    else:
        raise ValueError("action must be play_next, move or remove")
    doc_settings = store._read()
    doc_settings.setdefault("queue", {})["order"] = order
    store._write(doc_settings)
    return {"order": order}


def serve(host: str = "127.0.0.1", port: int = 8080, allow_lan: bool = False) -> None:
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_lan:
        raise SystemExit("refusing to listen beyond loopback without --allow-lan")
    store = Store()
    token = secrets.token_urlsafe(24)
    store.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_file = store.root / "admin-token"
    fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    handler = type("StationHandler", (Handler,), {
        "store": store, "token": token,
        "allowed_hosts": {"127.0.0.1", "localhost", "::1", host.lower()} | set(
            os.environ.get("EXPOSURE_RADIO_HOSTS", "").lower().split(",")) - {""}})
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"Exposure Radio on http://{host}:{port}/  console: http://{host}:{port}/admin.html")
    print(f"Admin token (also in {token_file}): {token}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def keys_set(provider: str) -> None:
    store = Store()
    fields = KEY_FIELDS.get(provider)
    if not fields:
        raise SystemExit(f"provider must be one of {', '.join(KEY_FIELDS)}")
    values = {f: getpass.getpass(f"{provider} {f.replace('_', ' ')}: ") for f in fields}
    store.set_keys(provider, values)
    print(f"Saved {provider} keys to {store.path} (mode 600).")


def pull(out: str | None = None) -> dict:
    from .tenable_api import Client, pull as pull_export
    store = Store()
    keys = store.secret("tenable")
    client = Client(keys.get("access_key") or os.environ.get("TENABLE_ACCESS_KEY", ""),
                    keys.get("secret_key") or os.environ.get("TENABLE_SECRET_KEY", ""),
                    store.settings()["tenable"]["host"])
    target = Path(out) if out else store.root / "exports" / date.today().isoformat()
    return pull_export(target, client)
