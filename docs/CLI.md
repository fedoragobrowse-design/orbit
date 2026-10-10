# Orbit CLI

The CLI talks to a running Orbit server with an API token. Mint the
token in the app (Settings → API tokens), then log in once:

```sh
orbit login --server http://127.0.0.1:18080 --token orb_...
orbit brief
orbit jobs
orbit search --query "quarterly report"
orbit approve --id <uuid> --decision allow
orbit tail
```

Tokens are bearer credentials with the same access as your session:

- `login` saves the token to `~/.config/orbit/token` with mode `0600`
  and verifies it against `GET /api/v1/tokens` before claiming
  success. A bad token fails here, not later.
- Every other command reads that file. No token, no request — the CLI
  exits 1 and tells you to log in.
- Revoke a token in Settings → API tokens (or
  `POST /api/v1/tokens/{id}/revoke`). Revoked tokens return 401;
  `login` with a revoked token fails verification.
- The server stores only the SHA256 hash. The plaintext is shown once
  at mint time — copy it then.

`--server` defaults to `http://127.0.0.1:18080` and can also come from
`ORBIT_SERVER`. `tail --follow` polls every 5 seconds; plain `tail`
prints the 10 most recent activity rows once.
