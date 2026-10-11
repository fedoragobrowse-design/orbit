# Marketplace plugins

Marketplace packages install from the upstream Orbit-MarketPlace repo index
over HTTPS (`crates/api/src/marketplace.rs`, `GET /api/v1/marketplace/search`
for the list, `POST /api/v1/marketplace/preview` for one manifest). The web
Marketplace page (`apps/web/src/marketplace.tsx`) renders each package as a
tile: name, description, version, and an Install button. The description on
each tile is not written in the UI — it comes from that package's own
`manifest.json` (`description` field), fetched live from the index.

## Plugin file layout

Copy `plugins/example-hello/` to start a new plugin:

```text
plugins/example-hello/
  manifest.json  package metadata (name, version, description, files, capabilities)
  README.md      human docs for the package
  SKILL.md       the skill text
```

Payload files (`README.md`, `SKILL.md`) are part of the signed content:

- Every file except `manifest.json` must be listed in the manifest `files`
  array with its sha256 hex digest.
- `content_digest` is recomputed from that list: sort the `path:hex` lines by
  path bytes, join with `\n`, sha256, prefix with `sha256:`.

## Minimal manifest

See `plugins/example-hello/manifest.json` (signed example key
`example-2026-dev`) for the full shape. The fields the API requires:

```json
{
  "manifest_version": 1,
  "name": "example-hello",
  "version": "0.1.0",
  "kind": "skill",
  "description": "Shown on the Marketplace tile. Keep it to one plain sentence.",
  "content_digest": "sha256:<recomputed>",
  "files": [{ "path": "SKILL.md", "sha256": "<hex>" }],
  "publisher": { "name": "Orbit Example", "key": "<base64 ed25519 key>", "key_id": "example-2026-dev" },
  "requested_capabilities": {
    "network": { "hosts": [], "egress": false },
    "filesystem": { "scopes": ["workspace"], "read_only": true },
    "secrets": [],
    "tools": []
  },
  "trust_level": "experimental",
  "versions_pinned": { "orbit-manifest": "1" },
  "signature": { "algorithm": "ed25519", "key_id": "example-2026-dev", "value": "<base64>" }
}
```

## Your own marketplaces

Owners can pin extra indexes that use the same manifest format as the built-in
one. The Marketplace page has a Marketplaces panel: give the index a name
(`team-index`) and the https address of its root
(`https://market.example.com`). Adding checks the format first — the address
must be https with no credentials, and it must serve a `manifest.schema.json`
object at its root — then saves the pin. Each package in that index lives at
`<root>/entries/<name>/manifest.json` with the exact fields from the minimal
manifest above (description, digest, files, capabilities, trust level,
signature). Removing an index never touches installed packages. Index rows
are owner-scoped (`marketplace_registries`, migration 0033) behind the same
mutation auth as installs, and every add/remove is audit-logged.

## Trust and install rules

- The signing key ships inside the manifest, so a passing signature check is
  self-asserted, never registry trust. Local installs use the dev override
  (`allow_unsigned`), recorded as self-asserted trust.
- Installs need the owner's explicit capability approval (the previewed
  `requested_capabilities` echoed back as `approved_capabilities` plus
  `accept_trust_level`) and run sandbox-only.
- Keep capabilities narrow: no egress, no secrets, no host tools, read-only
  workspace access. Anything broader is flagged on preview.
