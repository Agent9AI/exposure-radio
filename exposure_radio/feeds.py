"""Public enrichment feeds: CISA KEV and FIRST EPSS.

Both load from local files. The bundled snapshots make the core and the demo
work offline, and keep tenant CVE lists from leaving the machine.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

from .sanitize import clean_cve, clean_text

DATA = Path(__file__).parent / "data"
DEFAULT_KEV = DATA / "feeds" / "kev-2026.10.30.json"


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: bool
    required_action: str


@dataclass
class KevCatalog:
    version: str
    released: str
    as_of: str
    entries: dict[str, KevEntry]
    sha256: str

    def get(self, cve: str) -> KevEntry | None:
        return self.entries.get(cve)


@lru_cache(maxsize=4)
def _read_catalog(path: str, mtime_ns: int) -> tuple[bytes, dict]:
    raw = Path(path).read_bytes()
    return raw, json.loads(raw)


def load_kev(path: str | Path = DEFAULT_KEV, as_of: date | str | None = None) -> KevCatalog:
    """Load a KEV catalog. With ``as_of``, keep only entries added on or before
    that date, which reconstructs the catalog as it stood on that day."""
    p = Path(path)
    raw, doc = _read_catalog(str(p.resolve()), p.stat().st_mtime_ns)
    cutoff = str(as_of)[:10] if as_of else None
    entries: dict[str, KevEntry] = {}
    for item in doc.get("vulnerabilities", []):
        cve = clean_cve(item.get("cveID"))
        added = str(item.get("dateAdded", ""))[:10]
        if not cve or (cutoff and added > cutoff):
            continue
        entries[cve] = KevEntry(
            cve=cve,
            vendor=clean_text(item.get("vendorProject"), 60),
            product=clean_text(item.get("product"), 60),
            name=clean_text(item.get("vulnerabilityName"), 110),
            date_added=added,
            due_date=str(item.get("dueDate", ""))[:10],
            ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            required_action=clean_text(item.get("requiredAction"), 300),
        )
    return KevCatalog(
        version=clean_text(doc.get("catalogVersion"), 20),
        released=clean_text(doc.get("dateReleased"), 40),
        as_of=cutoff or clean_text(doc.get("dateReleased"), 10)[:10],
        entries=entries,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


@dataclass
class EpssScores:
    score_date: str
    scores: dict[str, tuple[float, float]]   # cve -> (epss, percentile)
    sha256: str

    def get(self, cve: str) -> tuple[float, float] | None:
        return self.scores.get(cve)


def load_epss(path: str | Path) -> EpssScores:
    """Accepts the bundled JSON snapshot, a FIRST API response, or the FIRST
    daily bulk CSV (optionally gzipped)."""
    p = Path(path)
    raw = p.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", "replace")
    scores: dict[str, tuple[float, float]] = {}
    score_date = ""
    if text.lstrip().startswith("{"):
        doc = json.loads(text)
        if "scores" in doc:
            score_date = str(doc.get("score_date", ""))[:10]
            rows = [{"cve": k, **v} for k, v in doc["scores"].items()]
        else:
            rows = doc.get("data", [])
        for row in rows:
            cve = clean_cve(row.get("cve"))
            if cve:
                scores[cve] = (float(row["epss"]), float(row["percentile"]))
                score_date = score_date or str(row.get("date", ""))[:10]
    else:
        lines = text.splitlines()
        if lines and lines[0].startswith("#"):
            for part in lines[0].lstrip("#").split(","):
                if part.startswith("score_date:"):
                    score_date = part.split(":", 1)[1][:10]
            lines = lines[1:]
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            cve = clean_cve(row.get("cve"))
            if cve:
                scores[cve] = (float(row["epss"]), float(row["percentile"]))
    return EpssScores(score_date=score_date, scores=scores, sha256=digest)
