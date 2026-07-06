# CPA Codex Login Butler

A local helper for repeated Codex OAuth re-login through CLIProxyAPI (CPA). It
keeps your saved roster stable, reads live CPA auth status, quarantines bad auth
files outside CPA's auth directory, and opens OAuth login URLs with the right
email hint.

It does **not** automate email, SMS, phone, or account verification. Those stay
manual.

## Run

```bash
/Users/lfan/Project/agent/cpa-codex-login-butler/bin/cpa-codex-butler status
/Users/lfan/Project/agent/cpa-codex-login-butler/bin/cpa-codex-butler fix
```

Optional alias:

```bash
alias cpa-codex-butler="/Users/lfan/Project/agent/cpa-codex-login-butler/bin/cpa-codex-butler"
```

## Daily Commands

Show accounts that need login:

```bash
cpa-codex-butler status
```

Show every current Codex auth file:

```bash
cpa-codex-butler status --all
```

Preview cleanup and login queue:

```bash
cpa-codex-butler fix --dry-run
```

Quarantine invalid auth files and walk through manual re-login:

```bash
cpa-codex-butler fix
```

Skip per-account prompts:

```bash
cpa-codex-butler fix --yes
```

Login one email, cleaning bad files for that email first:

```bash
cpa-codex-butler login xinyiw9596@gmail.com --clean
```

Refresh the saved roster only when accounts/seats intentionally change:

```bash
cpa-codex-butler roster sync
```

Set expected seats:

```bash
cpa-codex-butler roster set gameoflifan@gmail.com --seats 2
```

## Safety

- Reads only top-level `codex-*.json` files from `~/.cli-proxy-api`.
- Stores roster metadata under `~/.cli-proxy-api-state/codex-login-butler`.
- Quarantines bad auth files under `~/.cli-proxy-api-state/codex-login-butler/quarantine/`, outside CPA's scanned auth directory.
- Never copies token files back into CPA automatically.
- Uses CPA Management `/v0/management/auth-files` for live runtime auth status.
- Treats `auth_unavailable`, `authentication_error`, invalidated-token text, disabled records, or missing token fields as re-login signals.

## Compatibility

The old command names still work:

```bash
cpa-codex-butler status --needs-login
cpa-codex-butler queue --needs-login
cpa-codex-butler update-roster
cpa-codex-butler set user@example.com --expected-seats 1
```
