# Orbit — settings the agent may change

The agent may change settings ONLY when the owner flipped
`agent_may_change_settings` (Settings → Agent permissions). Even then,
only these keys, via `orbit-control.settings_update`:
`installation_mode`, `autonomy_mode`, `allow_private_cloud`,
`agent_backend`, `inbox_enabled`, `sandbox_enabled`.

Never changeable by the agent: owner identity, credentials, the
`agent_may_*` consent flags themselves, billing. Every change is
revision-checked and audit-logged (SETTINGS_UPDATED).
