# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
**Report a vulnerability** button on this repository (Security tab), or by
email to terry@agent9.dev. Do not open a public issue for a suspected
vulnerability. We acknowledge reports within two business days.

## Security model

Exposure Radio reads vulnerability scanner exports. Those exports describe
weaknesses in real systems, so the design treats them as sensitive and their
text fields as untrusted.

| Boundary | Rule | Where |
|---|---|---|
| Scanner text | Plugin output, descriptions, synopses, solutions, "see also" links and banners are never read into memory; parsers count and drop them. Plugin names are kept after allowlist cleaning and length capping and are never spoken. | `exposure_radio/parsers/`, `sanitize.py` |
| XML | `.nessus` files are parsed with expat in streaming mode: `DOCTYPE` and entity declarations are rejected, parameter entities disabled, nesting depth, byte size and element counts capped. | `parsers/nessus.py` |
| Incomplete exports | An export that declares itself unfinished, has missing or failed chunks, or is truncated holds the briefing: nothing is reported as fixed. | `parsers/`, `pipeline.py` |
| Claims | Every spoken or written factual statement is a `(subject, predicate, value, cite)` claim checked against the fact ledger; narration is rendered from fixed templates only; the rendered text is audited again; audio needs a receipt whose hash matches the script. | `claims.py`, `templates.py`, `textaudit.py`, `gate.py`, `audio/produce.py` |
| Identifiers | Hostnames, FQDNs, IP addresses, asset ids and plugin names never appear in narration, in the CISO edition, in the redacted fact dump or in the alert. Those artefacts are audited before writing and withheld on any hit. | `textaudit.py`, `packet.py`, `alert.py` |
| Model access | Optional and off by default. The analyst model sees redacted facts through read-only tools whose output is audited, can only propose claims, and runs under call, token, wall-clock and retry caps; the template edition airs on any cap, error or refusal. | `agent.py` |
| MCP | Three read-only tools over stdio; export paths must be inside the working or data directory; inputs are validated and size-capped. No write path exists. | `mcp_server.py` |
| Memory | The sqlite3 episode and alert memory stores asset identifiers, plugin numbers and hashes. No hostnames, no scanner text. | `memory.py` |
| Network | The core, the demo and `make check` make no network calls. `feeds refresh` (HTTPS GET to CISA and FIRST) and the model call are explicit opt-ins. | `feeds.py`, `agent.py` |
| Credentials | None are stored in the repository or its history (gitleaks scan recorded in `docs/BUILDLOG.md`). The API key is read from the environment at run time. | — |

Public demos and the hosted sample use synthetic data only.
