"""When to interrupt: deterministic alert policy with durable memory.

Breaking in is a decision with a cost, so it is made in code, not by a model:

* BREAK_IN  - an exploited (KEV) CVE is open on assets it was not announced
              for before: newly listed by CISA, newly appeared, or newly visible.
* HEALTH    - nothing to announce, but the evidence itself is in doubt
              (incomplete export, missed assets).
* SCHEDULED - normal briefing; changes exist but none warrants interruption.
* SILENT    - this exact evidence was already briefed. The reason is logged.

An alert is keyed by CVE and affected-asset set, so re-running unchanged data
never repeats an alert, while a new asset joining an exploited CVE does.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .delta import CveRollup, Delta
from .feeds import KevCatalog

SEV = ("info", "low", "medium", "high", "critical")


@dataclass
class Alert:
    cve: str
    key: str
    reasons: list[str]
    duplicate: bool = False
    assets: frozenset[str] = frozenset()


@dataclass
class Decision:
    kind: str
    lead: str
    episode: str
    alerts: list[Alert] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    health: list[str] = field(default_factory=list)

    @property
    def fresh_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if not a.duplicate]

    def push_payload(self) -> dict | None:
        """Generic text and an opaque reference. No CVEs, counts or names."""
        if self.kind == "BREAK_IN":
            return {"title": "Exposure Radio", "body": "Priority bulletin ready.", "ref": self.episode}
        if self.kind == "HEALTH":
            return {"title": "Exposure Radio", "body": "Data health notice.", "ref": self.episode}
        return None


def rank_key(r: CveRollup) -> tuple:
    return (bool(r.open_assets - r.unverified_assets), r.in_kev and bool(r.newly_listed or r.new_exposure_assets or r.reopened_assets), r.newly_listed, r.in_kev,
            bool(r.new_exposure_assets), bool(r.new_visibility_assets), SEV.index(r.severity), len(r.open_assets),
            r.cve)


def ranked(delta: Delta) -> list[CveRollup]:
    return sorted((r for r in delta.cves.values() if r.open_assets), key=rank_key, reverse=True)


class Memory:
    """Episode and alert history in SQLite (standard library)."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.db = sqlite3.connect(str(path))
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (key TEXT PRIMARY KEY, cve TEXT NOT NULL,
                episode TEXT NOT NULL, created TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alert_assets (cve TEXT NOT NULL, asset TEXT NOT NULL, PRIMARY KEY(cve, asset));
            CREATE TABLE IF NOT EXISTS episodes (id TEXT PRIMARY KEY, created TEXT NOT NULL,
                prev TEXT, curr TEXT, kev TEXT, decision TEXT, lead TEXT);
        """)

    def close(self) -> None:
        self.db.close()

    def __del__(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass

    def seen_alert(self, key: str) -> bool:
        return self.db.execute("SELECT 1 FROM alerts WHERE key = ?", (key,)).fetchone() is not None

    def seen_assets(self, cve: str) -> set[str]:
        return {row[0] for row in self.db.execute("SELECT asset FROM alert_assets WHERE cve = ?", (cve,))}

    def seen_episode(self, episode: str) -> bool:
        return self.db.execute("SELECT 1 FROM episodes WHERE id = ?", (episode,)).fetchone() is not None

    def commit(self, decision: Decision, delta: Delta, kev: KevCatalog) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO episodes VALUES (?,?,?,?,?,?,?)",
                            (decision.episode, now, delta.prev.digest, delta.curr.digest, kev.version,
                             decision.kind, decision.lead))
            for alert in decision.fresh_alerts:
                self.db.execute("INSERT OR IGNORE INTO alerts VALUES (?,?,?,?)",
                                (alert.key, alert.cve, decision.episode, now))
                self.db.executemany("INSERT OR IGNORE INTO alert_assets VALUES (?,?)",
                                    [(alert.cve, asset) for asset in alert.assets])


def alert_key(r: CveRollup) -> str:
    return hashlib.sha256(f"{r.cve}|{','.join(sorted(r.open_assets))}".encode()).hexdigest()[:16]


def decide(delta: Delta, kev: KevCatalog, memory: Memory) -> Decision:
    episode = hashlib.sha256(f"{delta.prev.digest}|{delta.curr.digest}|{kev.sha256}".encode()).hexdigest()[:12]
    order = ranked(delta)
    if memory.seen_episode(episode):
        return Decision("SILENT", "", episode,
                        log=[f"episode {episode} was already briefed; evidence unchanged, nothing repeated"])

    alerts: list[Alert] = []
    for r in order:
        if not r.in_kev:
            continue
        reasons = []
        if r.newly_listed:
            reasons.append("newly listed by CISA")
        if r.new_exposure_assets:
            reasons.append("newly appeared on scanned assets")
        if r.new_visibility_assets:
            reasons.append("found on newly scanned or newly credentialed assets")
        if r.reopened_assets:
            reasons.append("reopened on scanned assets")
        if not reasons and r.open_assets - r.unverified_assets - memory.seen_assets(r.cve):
            reasons.append("exploited exposure not previously announced")
        if reasons:
            key = alert_key(r)
            assets = frozenset(r.open_assets - r.unverified_assets)
            alerts.append(Alert(r.cve, key, reasons, duplicate=not bool(assets - memory.seen_assets(r.cve)) or memory.seen_alert(key), assets=assets))

    log = [f"{a.cve}: {'; '.join(a.reasons)}" + (" (already announced for these assets)" if a.duplicate else "")
           for a in alerts]
    fresh = [a for a in alerts if not a.duplicate]
    if fresh:
        return Decision("BREAK_IN", fresh[0].cve, episode, alerts, log, list(delta.health))
    lead = order[0].cve if order else ""
    if delta.health:
        return Decision("HEALTH", lead, episode, alerts, log + ["no new exploited exposure; data health issues"],
                        list(delta.health))
    return Decision("SCHEDULED", lead, episode, alerts, log + ["no new exploited exposure; scheduled briefing"], [])
