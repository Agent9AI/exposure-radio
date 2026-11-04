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

| Boundary | Rule |
|---|---|
| Scanner text | Plugin output, banners and other free text are never read. Scanner names and owner tags are excluded from model-safe outputs; kept private fields are length-capped. |
| Claims | Every factual narration sentence is rendered from structured claims and checked against the evidence ledger. Claims that fail are blocked before any audio is generated. |
| Model access | Optional. The analyst model sees only allowlisted, structured facts, can call read-only tools, and runs under call and time caps. The API adapter reserves counted input and output tokens; the operator-trusted command adapter uses bounded bytes and requires separate provider controls. |
| Hostnames | Executive editions, audio scripts and notification payloads are checked fail-closed for tenant hostnames, FQDNs, IP addresses and asset IDs. |
| Notifications | Push payloads carry generic text and an opaque reference only. |
| Network | The core, the demo and the station host make no outbound calls while playing. Public desks fetch NWS, Census geocoder and CISA feeds over HTTPS only when a station hour is built; `station pull` calls the Tenable export API; Gemini is called only with the operator's own key. |
| Station host | Listens on loopback unless `--allow-lan` is given. Writes require the admin token printed at start; the Host header is checked against an allowlist to stop DNS rebinding; request bodies are capped; settings are validated against a fixed schema. |
| Keys | Tenable and Gemini keys are stored in one private settings file (mode 600, directory 700) on the station host. The API reports only whether a key is configured; no endpoint returns a key. |
| Cloud voices | Exposure segments use a cloud voice only when the operator marks the Gemini project as paid, because free-tier content may be used to improve Google products. Spoken lines carry product names and counts, never asset names, addresses or owners. |
| Credentials | None are stored in the repository. API keys come from the environment or the private settings file at run time. |

Public demos and the hosted sample use synthetic data only.

The stdio MCP server is local and exposes no network listener. Its export root limits file access; it rejects symlink exports, oversized messages and malformed tool arguments. It is not a multi-tenant authentication service.
