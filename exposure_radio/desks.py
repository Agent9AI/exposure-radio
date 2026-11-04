"""Public desks: weather and local alerts, security news, and Learn.

These segments use public sources only and never see tenant data. Each desk
writes its script from feed fields with fixed phrasing, so it needs no model
and no key. Every segment carries the sources it was written from.

- Weather and local alerts: US National Weather Service (api.weather.gov) and
  the US Census geocoder. Both are free, keyless public-domain services.
- News: the CISA Known Exploited Vulnerabilities feed and Cloudflare Zero Wire briefings.
- Learn: bundled topics, or topics a Gemini key suggests (see ``gemini.py``).

Snapshots are written next to the station so a build can be replayed offline.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta
from pathlib import Path

from .numbers import spoken as words
from .sanitize import clean_text
from .zero_wire import URL as ZERO_WIRE_URL, parse_feed

UA = "ExposureRadio/0.6 (+https://github.com/Agent9AI/exposure-radio)"
DATA = Path(__file__).parent / "data"
LEARN_TOPICS = DATA / "learn" / "topics.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"


class DeskError(RuntimeError):
    pass


def fetch(url: str, timeout: float = 20.0, accept: str = "application/json") -> bytes:
    if not url.startswith("https://"):
        raise DeskError("public desks only fetch https sources")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only, fixed hosts
        return resp.read(8_000_000)


def _say(text: str) -> str:
    """Spell small numbers so both voices read them naturally."""
    return re.sub(r"\b\d{1,3}\b", lambda m: words(int(m.group(0))), text)


# --- weather and local alerts ----------------------------------------------------------------

def geocode(address: str) -> dict:
    q = urllib.parse.urlencode({"address": address, "benchmark": "Public_AR_Current", "format": "json"})
    doc = json.loads(fetch(f"https://geocoding.geo.census.gov/geocoder/locations/onelineaddress?{q}"))
    matches = doc.get("result", {}).get("addressMatches", [])
    if not matches:
        raise DeskError("the Census geocoder found no US match for that address")
    m = matches[0]
    comp = m.get("addressComponents", {})
    city = str(comp.get("city", "")).title()
    return {"lat": round(m["coordinates"]["y"], 4), "lon": round(m["coordinates"]["x"], 4),
            "label": f"{city}, {comp.get('state', '')}".strip(", ")}


def fetch_weather(lat: float, lon: float) -> dict:
    point = json.loads(fetch(f"https://api.weather.gov/points/{lat},{lon}", accept="application/geo+json"))
    props = point["properties"]
    forecast = json.loads(fetch(props["forecast"], accept="application/geo+json"))
    alerts = json.loads(fetch(f"https://api.weather.gov/alerts/active?point={lat},{lon}",
                              accept="application/geo+json"))
    rel = props.get("relativeLocation", {}).get("properties", {})
    return {
        "fetched": datetime.now().astimezone().isoformat(timespec="minutes"),
        "place": f"{rel.get('city', '')}, {rel.get('state', '')}".strip(", "),
        "periods": [{k: p.get(k) for k in ("name", "isDaytime", "temperature", "temperatureUnit",
                                           "shortForecast", "windSpeed", "windDirection")}
                    for p in forecast["properties"]["periods"][:3]],
        "alerts": [{k: a["properties"].get(k) for k in ("event", "headline", "severity", "ends")}
                   for a in alerts.get("features", [])][:3],
        "source": props["forecast"],
    }


def weather_segment(snapshot: dict, label: str) -> dict:
    periods = snapshot["periods"][:2]
    turns = [("avery", f"Weather and local for {label}.")]
    for p in periods:
        kind = "high" if p["isDaytime"] else "low"
        wind = str(p.get("windSpeed") or "")
        name = clean_text(p["name"], 40)
        text = f"{name[:1].upper()}{name[1:].lower()}: {clean_text(p['shortForecast'], 80).lower()}, with a {kind} near {p['temperature']}."
        if wind and re.search(r"\b(1[5-9]|[2-9]\d)\b", wind):
            text = text[:-1] + f", and wind {wind.replace('mph', 'miles an hour')}."
        turns.append(("avery", _say(text)))
    if snapshot["alerts"]:
        events = sorted({clean_text(a["event"], 60) for a in snapshot["alerts"] if a.get("event")})
        turns.append(("avery", "The National Weather Service has " + _join([f"a {e}" for e in events]) +
                      " in effect for the area."))
    else:
        turns.append(("avery", "No active Weather Service alerts for the area."))
    return {"kind": "weather", "title": f"Weather and local: {label}",
            "subtitle": f"National Weather Service, {snapshot['fetched'][:16].replace('T', ' ')}",
            "turns": _turns(turns),
            "sources": [{"label": "National Weather Service forecast", "url": snapshot["source"]}]}


# --- security news -----------------------------------------------------------------------------

def fetch_news(days: int = 7) -> dict:
    kev = json.loads(fetch(KEV_URL))
    released = str(kev.get("dateReleased", ""))[:10] or date.today().isoformat()
    cutoff = (date.fromisoformat(released) - timedelta(days=days)).isoformat()
    recent = sorted((v for v in kev.get("vulnerabilities", []) if str(v.get("dateAdded", "")) > cutoff),
                    key=lambda v: v["dateAdded"], reverse=True)
    zero_wire, zero_wire_status = [], "unavailable"
    try:
        zero_wire = parse_feed(fetch(ZERO_WIRE_URL, accept="application/rss+xml"))
        zero_wire_status = "connected" if zero_wire else "empty"
    except (ET.ParseError, OSError, ValueError):
        pass  # KEV still airs; offline builds reuse the saved snapshot explicitly.
    return {"fetched": datetime.now().astimezone().isoformat(timespec="minutes"),
            "catalog_version": kev.get("catalogVersion"), "released": released, "days": days,
            "kev_recent": [{"cve": v["cveID"], "vendor": clean_text(v.get("vendorProject"), 60),
                            "product": clean_text(v.get("product"), 80), "added": v["dateAdded"],
                            "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
                           for v in recent],
            "advisories": [], "zero_wire": zero_wire,
            "zero_wire_status": zero_wire_status,
            "zero_wire_fetched": datetime.now().astimezone().isoformat(timespec="minutes")}


def _product(v: dict) -> str:
    product = v["product"]
    if v["vendor"] and not product.lower().startswith(v["vendor"].lower()):
        product = f"{v['vendor']} {product}"
    return re.sub(r"\s+and\s+.*$", "", product)   # "Cisco ASA and Cisco FTD" reads as "Cisco ASA"


def news_segment(snapshot: dict) -> dict:
    recent = snapshot["kev_recent"]
    turns = [("avery", "Security news. Here's what CISA flagged this week.")]
    if recent:
        n = len(recent)
        names = list(dict.fromkeys(_product(v) for v in recent))
        turns.append(("avery", f"{words(n).capitalize()} {'vulnerability' if n == 1 else 'vulnerabilities'} "
                             f"joined the known exploited list in the last {words(snapshot['days'])} days."))
        turns.append(("cole", "On the list: " + _join(names[:5]) + "."))
        if len(names) > 5:
            turns.append(("cole", f"Plus {words(len(names) - 5)} more on screen."))
        if any(v["ransomware"] for v in recent):
            turns.append(("cole", "At least one is tied to known ransomware campaigns."))
        turns.append(("avery", "If any of those are in your environment, your exposure desk will call it out."))
    else:
        turns.append(("avery", "Nothing new joined the known exploited list this week."))
    briefs = snapshot.get("zero_wire", [])
    active = [b for b in briefs if b.get("status") == "Needs attention"]
    if active:
        turns.append(("cole", f"Cloudflare Zero Wire has {words(len(active))} {'briefing' if len(active) == 1 else 'briefings'} marked needs attention: " +
                      _join([b["title"] for b in active[:5]]) + "."))
        turns.append(("avery", "Those are public briefings, not findings on our network. Open the news desk for "
                      "the sources and patch guidance. Matching open findings get context on their action cards."))
        turns.append(("cole", "Cloudflare coverage is a compensating control. It does not replace the vendor "
                      "patch or a rescan, and we have not verified coverage for this environment."))
    elif snapshot.get("zero_wire_status") == "unavailable":
        turns.append(("cole", "Zero Wire is unavailable for this edition. The CISA briefing is still here."))
    sources = [{"label": f"CISA KEV catalog {snapshot['catalog_version']}",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]
    sources += [{"label": "Zero Wire: " + b["title"], "url": b["url"]} for b in active]
    fetched = snapshot.get("zero_wire_fetched", "")
    return {"kind": "news", "title": "Security news: CISA + Zero Wire",
            "subtitle": f"Public context · KEV {snapshot['catalog_version']} · Zero Wire {fetched[:16]}",
            "turns": _turns(turns), "sources": sources,
            "zero_wire": briefs, "zero_wire_fetched": fetched,
            "items": [{"cve": v["cve"], "product": _product(v), "added": v["added"]} for v in recent[:10]]}


# --- learn -------------------------------------------------------------------------------------

def learn_topics(path: Path = LEARN_TOPICS) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["topics"]


def learn_segment(topic: dict) -> dict:
    return {"kind": "learn", "title": f"Learn: {topic['title']}", "subtitle": topic.get("subtitle", ""),
            "turns": _turns([(t["host"], t["text"]) for t in topic["turns"]]), "sources": topic["sources"]}


# --- station framing ---------------------------------------------------------------------------

def ident_segment(text: str, title: str = "Exposure Radio", subtitle: str = "") -> dict:
    return {"kind": "ident", "title": title, "subtitle": subtitle, "turns": _turns([("avery", text)]),
            "sources": []}


def _turns(pairs) -> list[dict]:
    return [{"host": h, "text": t, "caption": t, "template": None, "subject": None, "cites": [],
             "banter": None} for h, t in pairs]


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + (", and " if len(items) > 2 else " and ") + items[-1]
