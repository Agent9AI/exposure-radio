"""Zero-PII alert preview.

A push notification is the least private surface there is: it shows on a
lock screen. The alert therefore carries counts and an opaque reference
only. It never names a host, an asset, a vendor or a CVE. ``audit_alert``
enforces that before the alert is written anywhere.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from .facts import FactStore
from .textaudit import ForbiddenTerms, Issue, audit_free_text


def _n(value: object, singular: str, plural: Optional[str] = None) -> str:
    number = int(value or 0)  # type: ignore[arg-type]
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def build_alert(store: FactStore, receipt_hash: str) -> Dict[str, str]:
    held = store.value("episode", "held") is True
    priority = int(store.value("priority", "count", 0) or 0)
    kev_cves = int(store.value("episode", "kev_open_cve_count", 0) or 0)
    closed = int(store.value("delta", "critical_closed", 0) or 0)
    new_kev = int(store.value("delta", "kev_new_entry_count", 0) or 0)
    has_previous = store.value("delta", "has_previous") is True
    date = str(store.value("episode", "export_date", ""))
    if held:
        body = (
            f"Export for {date} is incomplete. Briefing held; closures withheld. "
            f"{_n(priority, 'priority item')} still listed."
        )
    else:
        parts = [f"{_n(priority, 'priority item')} today, {_n(kev_cves, 'KEV-listed CVE')} open."]
        if has_previous:
            parts.append(f"{_n(closed, 'critical finding')} closed since the previous export.")
            if new_kev:
                parts.append(f"{_n(new_kev, 'KEV catalogue addition')} touches the estate.")
        body = " ".join(parts)
    reference = hashlib.sha256(receipt_hash.encode("utf-8")).hexdigest()[:12]
    return {
        "title": "Exposure Radio",
        "body": body,
        "reference": reference,
        "action": "Open the briefing",
    }


def audit_alert(alert: Dict[str, str], forbidden: Optional[ForbiddenTerms]) -> List[Issue]:
    text = " ".join(str(v) for v in alert.values())
    return audit_free_text(text, forbidden, allow_cves=False)
