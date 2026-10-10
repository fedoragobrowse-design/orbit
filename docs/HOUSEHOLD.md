# Household mode: declined

Orbit is single-owner by design: one `installation` row, one owner, every
row scoped by `owner_id`, freeze/backup/kill-switch scoped the same way.
Household (multi-user) mode would need tenancy rework across every table
plus auth, freeze, and backup scoping — a separate plan, not a feature
flag. Recorded as wont-do unless the owner overrides.
