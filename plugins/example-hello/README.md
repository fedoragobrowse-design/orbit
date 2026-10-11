# example-hello

Minimal marketplace plugin fixture. Copy this directory as the starting shape
for a new plugin: `manifest.json` describes the package, every other file is
payload covered by the digest.

## Layout

```text
plugins/example-hello/
  manifest.json  package metadata (name, version, description, files, capabilities)
  README.md      this file (human docs, part of the digest)
  SKILL.md       the skill text (part of the digest)
```

Every file except `manifest.json` must appear in the manifest `files` list
with its sha256 hex digest, and `content_digest` must equal the digest
recomputed from that list: sort the `path:hex` lines by path bytes, join with
`\n`, sha256, prefix with `sha256:`.

## Local dev install

This fixture is unsigned, so it installs with the dev override only
(`allow_unsigned`), recorded as self-asserted trust and runnable
sandbox-only. Signed publishing follows the upstream repo's `SIGNING.md`.
See `docs/marketplace.md` for the full manifest reference.
