"""Offline public feeds and the citation ledger.

Three snapshots live under ``data/feeds``:

* ``kev.json``: the CISA Known Exploited Vulnerabilities catalogue in its
  published JSON schema (``vulnerabilities[]`` with ``cveID``,
  ``vendorProject``, ``product``, ``dateAdded``, ``dueDate``, ...).
* ``epss.csv``: FIRST EPSS scores in the published CSV schema (a
  ``#model_version:...,score_date:...`` comment line, then
  ``cve,epss,percentile``).
* ``tenable_research.json``: Tenable Research publications (blog posts and
  advisories) with the CVE IDs each one covers.

``MANIFEST.json`` records where each snapshot came from and when. Every
fact built from a feed cites the ledger entry for that snapshot, so a
listener can follow a claim back to a file with a hash.

Reading the snapshots never touches the network. ``refresh`` does, and only
when a human runs it.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

from .sanitize import clean_cve, clean_date, clean_name, clean_text, to_float

MAX_FEED_BYTES = 64 * 1024 * 1024
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

DEFAULT_URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path: str) -> str:
    """Digest of a file, or of a directory's files (names and contents, sorted)."""
    if not os.path.isdir(path):
        return sha256_file(path)
    digest = hashlib.sha256()
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            digest.update(os.path.relpath(full, path).encode("utf-8"))
            digest.update(b"\0")
            digest.update(sha256_file(full).encode("ascii"))
            digest.update(b"\n")
    return digest.hexdigest()


_URL_RE = re.compile(r"https?://\S+")


def clean_required_action(text: object, max_len: int = 500) -> str:
    """CISA's requiredAction text without URLs, cut at a sentence end."""
    without_urls = _URL_RE.sub("", str(text or ""))
    cleaned = clean_text(without_urls, max_len)
    if len(cleaned) >= max_len:
        cut = cleaned.rfind(". ")
        if cut > 80:
            cleaned = cleaned[: cut + 1]
    return cleaned


def _read_capped(path: str) -> bytes:
    size = os.path.getsize(path)
    if size > MAX_FEED_BYTES:
        raise ValueError(f"feed file {path} is {size} bytes; limit is {MAX_FEED_BYTES}")
    with open(path, "rb") as handle:
        return handle.read()


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    source_id: str
    kind: str
    title: str
    path: str
    sha256: str
    captured: str
    version: str = ""
    url: str = ""
    coverage: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "id": self.source_id,
            "kind": self.kind,
            "title": self.title,
            "path": self.path,
            "sha256": self.sha256,
            "captured": self.captured,
            "version": self.version,
            "url": self.url,
            "coverage": self.coverage,
            "note": self.note,
        }


class Ledger:
    """Registry of everything a fact may cite."""

    def __init__(self) -> None:
        self.sources: Dict[str, Source] = {}

    def add(self, source: Source) -> str:
        self.sources[source.source_id] = source
        return source.source_id

    def has(self, source_id: str) -> bool:
        return source_id in self.sources

    def get(self, source_id: str) -> Optional[Source]:
        return self.sources.get(source_id)

    def to_list(self) -> List[Dict[str, str]]:
        return [self.sources[k].to_dict() for k in sorted(self.sources)]


# --------------------------------------------------------------------------
# KEV
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: Optional[str]
    ransomware: Optional[bool]
    cwes: Tuple[str, ...] = ()
    required_action: str = ""


@dataclass
class KevSnapshot:
    entries: Dict[str, KevEntry] = field(default_factory=dict)
    catalog_version: str = ""
    date_released: str = ""
    count: int = 0
    source_id: str = ""

    @property
    def listed(self) -> FrozenSet[str]:
        return frozenset(self.entries)

    def get(self, cve: str) -> Optional[KevEntry]:
        return self.entries.get(cve)

    def added_between(self, after: Optional[str], up_to: str) -> List[KevEntry]:
        """Entries with ``after < dateAdded <= up_to`` (ISO dates)."""
        out = []
        for entry in self.entries.values():
            if entry.date_added <= up_to and (after is None or entry.date_added > after):
                out.append(entry)
        return sorted(out, key=lambda e: (e.date_added, e.cve))

    @classmethod
    def load(cls, path: str) -> KevSnapshot:
        data = json.loads(_read_capped(path).decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ValueError("KEV snapshot is not in the CISA JSON schema")
        snap = cls(
            catalog_version=clean_name(data.get("catalogVersion") or ""),
            date_released=clean_name(data.get("dateReleased") or "")[:25],
            count=int(data.get("count") or 0),
        )
        for item in data["vulnerabilities"]:
            if not isinstance(item, dict):
                continue
            cve = clean_cve(item.get("cveID"))
            date_added = clean_date(item.get("dateAdded"))
            if not cve or not date_added:
                continue
            ransomware_raw = str(item.get("knownRansomwareCampaignUse") or "").strip().lower()
            ransomware: Optional[bool]
            if ransomware_raw == "known":
                ransomware = True
            elif ransomware_raw == "unknown":
                ransomware = False
            else:
                ransomware = None
            cwes = tuple(
                c for c in (clean_name(x) for x in (item.get("cwes") or []) if isinstance(x, str)) if re.fullmatch(r"CWE-\d+", c)
            )
            snap.entries[cve] = KevEntry(
                cve=cve,
                vendor=clean_name(item.get("vendorProject") or ""),
                product=clean_name(item.get("product") or ""),
                name=clean_name(item.get("vulnerabilityName") or ""),
                date_added=date_added,
                due_date=clean_date(item.get("dueDate")),
                ransomware=ransomware,
                cwes=cwes,
                required_action=clean_required_action(item.get("requiredAction")),
            )
        if not snap.count:
            snap.count = len(snap.entries)
        return snap


# --------------------------------------------------------------------------
# EPSS
# --------------------------------------------------------------------------


@dataclass
class EpssSnapshot:
    scores: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    model_version: str = ""
    score_date: str = ""
    source_id: str = ""

    def score(self, cve: str) -> Optional[float]:
        pair = self.scores.get(cve)
        return pair[0] if pair else None

    def percentile(self, cve: str) -> Optional[float]:
        pair = self.scores.get(cve)
        return pair[1] if pair else None

    @property
    def score_map(self) -> Dict[str, float]:
        return {k: v[0] for k, v in self.scores.items()}

    @classmethod
    def _load_json(cls, data: object) -> EpssSnapshot:
        """Two JSON shapes: the FIRST API response and the bundled snapshot.

        FIRST API: ``{"data": [{"cve": ..., "epss": "0.94", "percentile": "0.99", "date": "2026-10-30"}]}``.
        Snapshot:  ``{"score_date": "2026-10-30", "scores": {"CVE-...": {"epss": 0.94, "percentile": 0.99}}}``.
        """
        snap = cls()
        if not isinstance(data, dict):
            raise ValueError("EPSS JSON must be an object")
        snap.model_version = clean_name(data.get("model_version") or data.get("model") or "")[:40]
        match = _DATE_RE.search(str(data.get("score_date") or ""))
        snap.score_date = match.group(0) if match else ""
        rows = data.get("data")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve = clean_cve(row.get("cve"))
                score = to_float(row.get("epss"), 0.0, 1.0)
                if cve is None or score is None:
                    continue
                pct = to_float(row.get("percentile"), 0.0, 1.0)
                snap.scores[cve] = (score, pct if pct is not None else 0.0)
                if not snap.score_date:
                    date_match = _DATE_RE.search(str(row.get("date") or ""))
                    snap.score_date = date_match.group(0) if date_match else ""
            return snap
        scores = data.get("scores")
        if isinstance(scores, dict):
            for key, value in scores.items():
                cve = clean_cve(key)
                if cve is None or not isinstance(value, dict):
                    continue
                score = to_float(value.get("epss"), 0.0, 1.0)
                if score is None:
                    continue
                pct = to_float(value.get("percentile"), 0.0, 1.0)
                snap.scores[cve] = (score, pct if pct is not None else 0.0)
            return snap
        raise ValueError("EPSS JSON has neither a data list nor a scores object")

    @classmethod
    def load(cls, path: str) -> EpssSnapshot:
        raw = _read_capped(path)
        if raw[:2] == b"\x1f\x8b":
            import gzip

            raw = gzip.decompress(raw)
            if len(raw) > MAX_FEED_BYTES * 4:
                raise ValueError("EPSS feed decompresses past the size limit")
        text = raw.decode("utf-8", "replace")
        if text.lstrip().startswith("{"):
            return cls._load_json(json.loads(text))
        snap = cls()
        lines = text.splitlines()
        start = 0
        if lines and lines[0].startswith("#"):
            header = lines[0][1:]
            for part in header.split(","):
                key, _, value = part.partition(":")
                key = key.strip().lower()
                if key == "model_version":
                    snap.model_version = clean_name(value)[:40]
                elif key == "score_date":
                    match = _DATE_RE.search(value)
                    snap.score_date = match.group(0) if match else ""
            start = 1
        reader = csv.reader(io.StringIO("\n".join(lines[start:])))
        try:
            columns = next(reader)
        except StopIteration:
            raise ValueError("EPSS snapshot has no header row") from None
        columns = [c.strip().lower() for c in columns]
        if "cve" not in columns or "epss" not in columns:
            raise ValueError("EPSS snapshot lacks cve/epss columns")
        ci, si = columns.index("cve"), columns.index("epss")
        pi = columns.index("percentile") if "percentile" in columns else None
        for row in reader:
            if len(row) <= max(ci, si):
                continue
            cve = clean_cve(row[ci])
            score = to_float(row[si], 0.0, 1.0)
            if cve is None or score is None:
                continue
            pct = to_float(row[pi], 0.0, 1.0) if pi is not None and len(row) > pi else None
            snap.scores[cve] = (score, pct if pct is not None else 0.0)
        return snap


# --------------------------------------------------------------------------
# Tenable Research
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Publication:
    pub_id: str
    title: str
    published: str
    url: str
    cves: Tuple[str, ...]
    kind: str = "blog"


@dataclass
class ResearchSnapshot:
    items: List[Publication] = field(default_factory=list)
    captured: str = ""
    source_id: str = ""

    def for_cve(self, cve: str) -> List[Publication]:
        return [p for p in self.items if cve in p.cves]

    @classmethod
    def load(cls, path: str) -> ResearchSnapshot:
        data = json.loads(_read_capped(path).decode("utf-8"))
        items = data.get("items") if isinstance(data, dict) else data
        snap = cls(captured=clean_name((data.get("captured") if isinstance(data, dict) else "") or "")[:25])
        for item in items or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            if not url.startswith("https://www.tenable.com/"):
                continue  # only Tenable's own site is accepted as a research source
            cves = tuple(sorted({c for c in (clean_cve(x) for x in item.get("cves") or []) if c}))
            snap.items.append(
                Publication(
                    pub_id=clean_name(item.get("id") or "")[:64],
                    title=clean_name(item.get("title") or "")[:160],
                    published=clean_date(item.get("published")) or "",
                    url=url[:300],
                    cves=cves,
                    kind=clean_name(item.get("kind") or "blog")[:20],
                )
            )
        return snap


# --------------------------------------------------------------------------
# Loading everything
# --------------------------------------------------------------------------


@dataclass
class Feeds:
    kev: KevSnapshot
    epss: EpssSnapshot
    research: ResearchSnapshot
    ledger: Ledger
    manifest: Dict[str, object]


def _manifest_entry(manifest: Dict[str, object], key: str) -> Dict[str, str]:
    entry = manifest.get(key) if isinstance(manifest, dict) else None
    return {k: str(v) for k, v in entry.items()} if isinstance(entry, dict) else {}


def load_feeds(feeds_dir: str, ledger: Optional[Ledger] = None) -> Feeds:
    ledger = ledger or Ledger()
    manifest_path = os.path.join(feeds_dir, "MANIFEST.json")
    manifest: Dict[str, object] = {}
    if os.path.isfile(manifest_path):
        manifest = json.loads(_read_capped(manifest_path).decode("utf-8"))

    kev_path = os.path.join(feeds_dir, "kev.json")
    kev = KevSnapshot.load(kev_path) if os.path.isfile(kev_path) else KevSnapshot()
    if kev.entries:
        meta = _manifest_entry(manifest, "kev")
        kev.source_id = ledger.add(
            Source(
                source_id=f"kev:{kev.catalog_version or 'snapshot'}",
                kind="kev",
                title="CISA Known Exploited Vulnerabilities catalogue",
                path=os.path.relpath(kev_path),
                sha256=sha256_file(kev_path),
                captured=meta.get("captured", kev.date_released[:10]),
                version=kev.catalog_version,
                url=meta.get("url", DEFAULT_URLS["kev"]),
                coverage=meta.get("coverage", ""),
                note=meta.get("note", ""),
            )
        )

    epss_path = next(
        (p for p in (os.path.join(feeds_dir, name) for name in ("epss.csv", "epss.csv.gz", "epss.json")) if os.path.isfile(p)),
        os.path.join(feeds_dir, "epss.csv"),
    )
    epss = EpssSnapshot.load(epss_path) if os.path.isfile(epss_path) else EpssSnapshot()
    if epss.scores:
        meta = _manifest_entry(manifest, "epss")
        epss.source_id = ledger.add(
            Source(
                source_id=f"epss:{epss.score_date or 'snapshot'}",
                kind="epss",
                title="FIRST Exploit Prediction Scoring System",
                path=os.path.relpath(epss_path),
                sha256=sha256_file(epss_path),
                captured=meta.get("captured", epss.score_date),
                version=epss.model_version,
                url=meta.get("url", DEFAULT_URLS["epss"]),
                coverage=meta.get("coverage", ""),
                note=meta.get("note", ""),
            )
        )

    research_path = os.path.join(feeds_dir, "tenable_research.json")
    research = ResearchSnapshot.load(research_path) if os.path.isfile(research_path) else ResearchSnapshot()
    if research.items:
        meta = _manifest_entry(manifest, "tenable_research")
        research.source_id = ledger.add(
            Source(
                source_id=f"tenable-research:{research.captured or 'snapshot'}",
                kind="research",
                title="Tenable Research publications",
                path=os.path.relpath(research_path),
                sha256=sha256_file(research_path),
                captured=meta.get("captured", research.captured),
                url=meta.get("url", "https://www.tenable.com/blog"),
                coverage=meta.get("coverage", ""),
                note=meta.get("note", ""),
            )
        )
    return Feeds(kev=kev, epss=epss, research=research, ledger=ledger, manifest=manifest)


# --------------------------------------------------------------------------
# Refresh (explicit opt-in network access)
# --------------------------------------------------------------------------

Fetcher = Callable[[str], bytes]


def _default_fetch(url: str) -> bytes:
    import urllib.request

    if not url.startswith("https://"):
        raise ValueError("feed refresh only fetches https URLs")
    request = urllib.request.Request(url, headers={"User-Agent": "exposure-radio/0.1 (+feeds refresh)"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 (https only, checked above)
        data = response.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError(f"{url} exceeds {MAX_FEED_BYTES} bytes")
    return data


def refresh(feeds_dir: str, urls: Optional[Dict[str, str]] = None, fetch: Optional[Fetcher] = None) -> Dict[str, str]:
    """Download fresh KEV and EPSS snapshots into ``feeds_dir``.

    Each download is validated by the matching loader before it replaces the
    file on disk, so a broken download never clobbers a working snapshot.
    Returns a summary mapping feed name to a short status line.
    """
    urls = dict(DEFAULT_URLS, **(urls or {}))
    fetch = fetch or _default_fetch
    os.makedirs(feeds_dir, exist_ok=True)
    manifest_path = os.path.join(feeds_dir, "MANIFEST.json")
    manifest: Dict[str, object] = {}
    if os.path.isfile(manifest_path):
        manifest = json.loads(_read_capped(manifest_path).decode("utf-8"))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    summary: Dict[str, str] = {}

    kev_raw = fetch(urls["kev"])
    tmp_kev = os.path.join(feeds_dir, "kev.json.tmp")
    with open(tmp_kev, "wb") as handle:
        handle.write(kev_raw)
    kev = KevSnapshot.load(tmp_kev)
    os.replace(tmp_kev, os.path.join(feeds_dir, "kev.json"))
    manifest["kev"] = {"url": urls["kev"], "captured": today, "coverage": "full", "note": "downloaded by feeds refresh"}
    summary["kev"] = f"{len(kev.entries)} entries, catalogue version {kev.catalog_version or 'unknown'}"

    epss_raw = fetch(urls["epss"])
    tmp_epss = os.path.join(feeds_dir, "epss.csv.tmp")
    with open(tmp_epss, "wb") as handle:
        handle.write(epss_raw)
    epss = EpssSnapshot.load(tmp_epss)
    if epss_raw[:2] == b"\x1f\x8b":
        import gzip

        with open(tmp_epss, "wb") as handle:
            handle.write(gzip.decompress(epss_raw))
    os.replace(tmp_epss, os.path.join(feeds_dir, "epss.csv"))
    manifest["epss"] = {"url": urls["epss"], "captured": today, "coverage": "full", "note": "downloaded by feeds refresh"}
    summary["epss"] = f"{len(epss.scores)} scores, score date {epss.score_date or 'unknown'}"

    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return summary
