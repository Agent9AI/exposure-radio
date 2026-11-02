# ADR-0004: Tenant identifiers are never spoken, and the CISO edition fails closed

Date: 2026-11-02
Status: accepted

## Context

Audio travels. A briefing played in a car or shared as a file is a worse
place for a hostname than a ticket is, and a push notification is worse
still. Scanner text (plugin output, banners, solution prose) is written by
software and sometimes by the systems being scanned, so it is a carrier for
injected instructions as well as for identifiers.

## Decision

1. Parsers never store free text from the scanner. Plugin names are kept
   after allowlist cleaning and length capping; everything else is counted
   and dropped. Nothing in the fact store is scanner prose.
2. Narration never contains hostnames, FQDNs, IP addresses, asset
   identifiers or plugin names, in any edition. The text audit checks each
   sentence against the exact identifiers in the exports and against
   DNS-, IP- and UUID-shaped tokens. Asset detail belongs to the action
   card, never to the audio.
3. Two card editions exist. The full edition lists affected assets; the
   CISO edition carries counts and asset groups only. The CISO edition, the
   redacted fact dump and the alert are audited for identifiers before they
   are written; on any hit the artefact is withheld and replaced with the
   audit result, never patched up.
4. The push alert carries counts and an opaque reference only: no CVE
   identifiers, no vendor names, no asset identifiers.
5. The optional analyst model sees the CISO view only, through tools that
   run the same audit on their own output.

## Consequences

Executives and on-call engineers can listen anywhere; the ticket, not the
audio, is where the hostnames live. A hostname that does reach the wrong
place is a test failure, not a judgement call, and `make audit` reports it.
