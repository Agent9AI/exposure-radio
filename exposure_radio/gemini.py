"""Optional Google Gemini adapter, used only with the operator's own key.

- ``suggest_topics``: asks a Gemini text model, grounded with Google Search, for
  security topics worth a sixty-second Learn segment this week. Suggestions are
  queued for an operator to approve; they never air unreviewed. The prompt
  contains no tenant data.
- ``GeminiVoice``: Gemini text-to-speech for broadcast voices. The station only
  sends exposure segments here when the operator marks the project as paid (see
  ``station.cloud_voice_allowed``), because free-tier content may be used to
  improve Google products.

Standard library only. See docs/GOOGLE.md.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request

API = "https://generativelanguage.googleapis.com/v1beta/models"
TEXT_MODEL = "gemini-flash-latest"
TTS_MODEL = "gemini-3.8-flash-tts"


class GeminiError(RuntimeError):
    pass


def _post(model: str, body: dict, api_key: str, timeout: float = 60.0) -> dict:
    if not api_key:
        raise GeminiError("no Gemini API key configured")
    req = urllib.request.Request(f"{API}/{model}:generateContent", data=json.dumps(body).encode(), method="POST",
                                 headers={"x-goog-api-key": api_key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise GeminiError("Gemini quota reached; the station falls back to local voices and bundled topics") \
                from None
        try:
            detail = json.loads(exc.read() or b"{}").get("error", {}).get("message", "")[:200]
        except ValueError:
            detail = ""
        raise GeminiError(f"Gemini returned HTTP {exc.code}{': ' + detail if detail else ''}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise GeminiError("Gemini is unreachable") from exc


SUGGEST_PROMPT = (
    "You help a small IT team's internal radio station pick sixty-second educational segments. "
    "Search for cybersecurity topics that practitioners are actively discussing this week "
    "(new attack techniques, widely exploited vulnerabilities, notable incidents, useful defensive practices). "
    "Return exactly {n} topics as JSON lines, one object per line, with keys "
    '"title" (under 60 characters, plain), "why" (one sentence on why a small IT team should care) and '
    '"url" (one reputable source you found). No markdown, no other text.')


def suggest_topics(api_key: str, n: int = 3, model: str = TEXT_MODEL) -> dict:
    doc = _post(model, {"contents": [{"parts": [{"text": SUGGEST_PROMPT.format(n=n)}]}],
                        "tools": [{"google_search": {}}]}, api_key)
    candidate = (doc.get("candidates") or [{}])[0]
    text = "".join(p.get("text", "") for p in candidate.get("content", {}).get("parts", []))
    topics = []
    for line in text.splitlines():
        line = line.strip().strip(",")
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        title = re.sub(r"\s+", " ", str(item.get("title", ""))).strip()[:80]
        url = str(item.get("url", ""))
        if title:
            topics.append({"title": title, "why": str(item.get("why", ""))[:240],
                           "url": url if url.startswith("https://") else "", "status": "suggested"})
    grounding = candidate.get("groundingMetadata", {})
    return {"topics": topics[:n], "model": model,
            # Google's grounding terms require showing these Search Suggestions with grounded results.
            "search_suggestions_html": grounding.get("searchEntryPoint", {}).get("renderedContent", ""),
            "sources": [c.get("web", {}).get("uri") for c in grounding.get("groundingChunks", []) if c.get("web")]}


INTERACTIONS = "https://generativelanguage.googleapis.com/v1beta/interactions"


class GeminiVoice:
    """Gemini 3.8 Flash TTS, one request per turn so captions keep exact timing."""

    STYLE = {"ava": "warm, upbeat morning radio host talking to her own team",
             "cole": "calm, friendly security analyst explaining to colleagues"}

    def __init__(self, api_key: str, voices: dict[str, str], model: str = TTS_MODEL,
                 max_seconds: float = 900.0, retries: int = 6, backoff: float = 10.0):
        if not api_key:
            raise GeminiError("no Gemini API key configured")
        self.api_key, self.voices, self.model, self.max_seconds = api_key, voices, model, max_seconds
        self.seconds = 0.0
        self.retries, self.backoff = retries, backoff

    def speak(self, host: str, text: str):
        import io
        import numpy as np
        import soundfile as sf
        if self.seconds >= self.max_seconds:
            raise GeminiError("daily cloud-voice limit reached")
        body = {"model": self.model,
                "input": [{"type": "user_input", "content": [{"type": "text", "text": text, "annotations": [
                    {"type": "speech_metadata", "style": self.STYLE.get(host, "natural")}]}]}],
                "response_format": {"type": "audio"},
                "generation_config": {"speech_config": [{"voice": self.voices[host]}]}}
        req = urllib.request.Request(INTERACTIONS, data=json.dumps(body).encode(), method="POST",
                                     headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"})
        # Free-tier keys are limited per minute: back off and retry before giving up.
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https host
                    doc = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                if exc.code != 429:
                    raise GeminiError(f"Gemini voice returned HTTP {exc.code}") from None
                if attempt == self.retries:
                    raise GeminiError("Gemini voice quota reached") from None
                time.sleep(self.backoff * (attempt + 1))
        for step in doc.get("steps", []):
            for block in step.get("content", []):
                if block.get("type") == "audio" and block.get("data"):
                    raw = base64.b64decode(block["data"])
                    if block.get("mime_type", "audio/wav") == "audio/wav":
                        samples, rate = sf.read(io.BytesIO(raw), dtype="float32")
                    else:
                        samples, rate = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0, 24000
                    if samples.ndim > 1:
                        samples = samples.mean(axis=1)
                    self.seconds += len(samples) / rate
                    return samples, rate
        raise GeminiError("Gemini returned no audio")
