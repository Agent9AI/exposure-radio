"""Bounded public RSS context. Never executes feed prompts or fetches by tenant CVE."""
from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import urlsplit

URL = "https://radar.cloudflare.com/security/zero-wire/rss"
BOUNDARY = "Compensating control only. Vendor patch and Tenable rescan still required. Coverage is not verified for this environment."


def briefing_url(value: str) -> str:
    p = urlsplit(value)
    if (p.scheme == "https" and p.netloc == "radar.cloudflare.com"
            and re.fullmatch(r"/security/zero-wire/[a-z0-9-]+", p.path)
            and not p.query and not p.fragment):
        return value
    return ""


class _Content(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.sections = [], {}
        self.heading, self.section, self.skip = None, "", 0
        self.has_prompt = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        if tag in ("h2", "h3"):
            self.heading, self.parts = tag, []
        if tag == "pre":
            self.has_prompt = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        if tag == self.heading:
            key = " ".join(self.parts).strip().lower()
            self.section = key if key not in self.sections else "__duplicate__"
            self.heading, self.parts = None, []
        elif tag in ("p", "li", "br"):
            self.sections.setdefault(self.section, []).append(" ")

    def handle_data(self, data):
        if self.skip:
            return
        if self.heading:
            self.parts.append(data)
        else:
            self.sections.setdefault(self.section, []).append(data)

    def text(self, key):
        return " ".join("".join(self.sections.get(key, [])).split())[:1800]


def parse_feed(raw: bytes) -> list[dict]:
    if len(raw) > 2_000_000 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("unsupported Zero Wire document")
    root = ET.fromstring(raw)
    if root.tag != "rss":
        raise ValueError("Zero Wire must be RSS")
    result, seen = [], set()
    for item in root.findall("./channel/item")[:50]:
        url = briefing_url((item.findtext("link") or "").strip())
        if not url or url in seen:
            continue
        seen.add(url)
        categories = [(c.text or "").strip() for c in item.findall("category")]
        status = next((c for c in categories if c in ("Needs attention", "Reference")), "Unclassified")
        content = _Content()
        content.feed((item.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or "")[:200000])
        result.append({
            "title": " ".join((item.findtext("title") or "Untitled briefing").split())[:120],
            "url": url, "status": status,
            "cves": sorted({c for c in categories if re.fullmatch(r"CVE-\d{4}-\d{4,8}", c)}),
            "summary": " ".join((item.findtext("description") or "").split())[:1800],
            "cloudflare_coverage": content.text("product coverage"),
            "has_agent_prompt": content.has_prompt,
            "published": (item.findtext("pubDate") or "")[:80],
        })
    return result


def enrich_card(card: dict, snapshot: dict) -> dict:
    """Local exact-CVE join. Public context never changes evidence or priorities."""
    result = copy.deepcopy(card)
    briefings = snapshot.get("zero_wire", [])
    for item in result.get("items", []):
        item.pop("zero_wire", None)
        if not item.get("open_assets", 0):
            continue
        matches = []
        for b in briefings:
            if item.get("cve") in b.get("cves", []) and briefing_url(b.get("url", "")):
                matches.append({k: b.get(k) for k in
                                ("title", "url", "status", "summary", "cloudflare_coverage", "has_agent_prompt")})
        if matches:
            item["zero_wire"] = {"briefings": matches, "boundary": BOUNDARY,
                                 "fetched": snapshot.get("zero_wire_fetched"),
                                 "source": "Cloudflare Zero Wire public context"}
    return result
