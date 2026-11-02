"""Episode memory in sqlite3.

The memory stores what each episode saw, so the next episode can report
progress ("14 criticals closed, 1 new KEV entry") and so coverage questions
("was this asset scanned last time?") have an answer that survives between
runs. It stores asset identifiers and plugin numbers, never hostnames,
never scanner text.

The default location is in memory (``:memory:``), which is what the demo
and the MCP server use; pass a path to keep history across runs.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, FrozenSet, Iterable, List, Optional

from .model import AssetPluginFinding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS episodes (
    id INTEGER PRIMARY KEY,
    episode_date TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    asset_count INTEGER NOT NULL,
    open_critical INTEGER NOT NULL,
    open_high INTEGER NOT NULL,
    kev_open_cves INTEGER NOT NULL,
    held INTEGER NOT NULL,
    kev_version TEXT NOT NULL,
    summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS episode_assets (
    episode_id INTEGER NOT NULL REFERENCES episodes(id),
    asset_id TEXT NOT NULL,
    PRIMARY KEY (episode_id, asset_id)
);
CREATE TABLE IF NOT EXISTS episode_findings (
    episode_id INTEGER NOT NULL REFERENCES episodes(id),
    asset_id TEXT NOT NULL,
    plugin_id INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    state TEXT NOT NULL,
    primary_cve TEXT,
    kev_listed INTEGER NOT NULL,
    PRIMARY KEY (episode_id, asset_id, plugin_id)
);
CREATE INDEX IF NOT EXISTS idx_episode_findings_cve ON episode_findings(episode_id, primary_cve);
"""


@dataclass(frozen=True)
class EpisodeRecord:
    episode_id: int
    episode_date: str
    label: str
    asset_count: int
    open_critical: int
    open_high: int
    kev_open_cves: int
    held: bool
    kev_version: str
    summary: Dict[str, object]


class Memory:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # --- writing ---------------------------------------------------------
    def record_episode(
        self,
        episode_date: str,
        label: str,
        asset_ids: Iterable[str],
        findings: Iterable[AssetPluginFinding],
        primary_cves: Dict[tuple, Optional[str]],
        kev_listed: FrozenSet[str],
        held: bool,
        kev_version: str,
        summary: Optional[Dict[str, object]] = None,
    ) -> int:
        findings = list(findings)
        asset_ids = sorted(set(asset_ids))
        open_critical = sum(1 for f in findings if f.is_open and f.severity == 4)
        open_high = sum(1 for f in findings if f.is_open and f.severity == 3)
        kev_cves = {
            primary_cves.get(f.key)
            for f in findings
            if f.is_open and primary_cves.get(f.key) in kev_listed
        }
        kev_cves.discard(None)
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO episodes (episode_date, label, created_at, asset_count, open_critical, open_high,"
                " kev_open_cves, held, kev_version, summary_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    episode_date,
                    label,
                    created,
                    len(asset_ids),
                    open_critical,
                    open_high,
                    len(kev_cves),
                    1 if held else 0,
                    kev_version,
                    json.dumps(summary or {}, sort_keys=True),
                ),
            )
            episode_id = int(cursor.lastrowid)
            self.conn.executemany(
                "INSERT INTO episode_assets (episode_id, asset_id) VALUES (?, ?)",
                [(episode_id, a) for a in asset_ids],
            )
            self.conn.executemany(
                "INSERT OR REPLACE INTO episode_findings (episode_id, asset_id, plugin_id, severity, state,"
                " primary_cve, kev_listed) VALUES (?,?,?,?,?,?,?)",
                [
                    (
                        episode_id,
                        f.asset_id,
                        f.plugin_id,
                        f.severity,
                        f.state,
                        primary_cves.get(f.key),
                        1 if primary_cves.get(f.key) in kev_listed else 0,
                    )
                    for f in findings
                ],
            )
        return episode_id

    # --- reading ---------------------------------------------------------
    def _row_to_record(self, row: sqlite3.Row) -> EpisodeRecord:
        return EpisodeRecord(
            episode_id=int(row[0]),
            episode_date=str(row[1]),
            label=str(row[2]),
            asset_count=int(row[3]),
            open_critical=int(row[4]),
            open_high=int(row[5]),
            kev_open_cves=int(row[6]),
            held=bool(row[7]),
            kev_version=str(row[8]),
            summary=json.loads(row[9] or "{}"),
        )

    def episodes(self) -> List[EpisodeRecord]:
        rows = self.conn.execute(
            "SELECT id, episode_date, label, asset_count, open_critical, open_high, kev_open_cves, held,"
            " kev_version, summary_json FROM episodes ORDER BY episode_date, id"
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def previous_episode(self, before_date: str) -> Optional[EpisodeRecord]:
        row = self.conn.execute(
            "SELECT id, episode_date, label, asset_count, open_critical, open_high, kev_open_cves, held,"
            " kev_version, summary_json FROM episodes WHERE episode_date < ? ORDER BY episode_date DESC, id DESC LIMIT 1",
            (before_date,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def assets_of(self, episode_id: int) -> FrozenSet[str]:
        rows = self.conn.execute("SELECT asset_id FROM episode_assets WHERE episode_id = ?", (episode_id,)).fetchall()
        return frozenset(str(r[0]) for r in rows)

    def kev_cves_of(self, episode_id: int) -> FrozenSet[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT primary_cve FROM episode_findings WHERE episode_id = ? AND kev_listed = 1"
            " AND state IN ('OPEN','REOPENED','NEW','ACTIVE') AND primary_cve IS NOT NULL",
            (episode_id,),
        ).fetchall()
        return frozenset(str(r[0]) for r in rows)

    def trend(self, limit: int = 6) -> List[Dict[str, object]]:
        """Compact per-episode numbers for the listen page and the briefing."""
        out = []
        for record in self.episodes()[-limit:]:
            out.append(
                {
                    "episode_date": record.episode_date,
                    "assets": record.asset_count,
                    "open_critical": record.open_critical,
                    "open_high": record.open_high,
                    "kev_open_cves": record.kev_open_cves,
                    "held": record.held,
                }
            )
        return out
