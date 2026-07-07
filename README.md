# CPA Codex Login Butler

A local helper for repeated Codex OAuth re-login through CLIProxyAPI (CPA). It
reads current CPA Codex auth files, merges live CPA auth status, quarantines bad
auth files outside CPA's auth directory, and opens OAuth login URLs with the
right email hint.

It does **not** automate email, SMS, phone, or account verification. Those stay
manual.

## Run

```bash
python -m pip install -e .
cpa-codex-butler status
cpa-codex-butler queue
```

For a checkout-only run without installing:

```bash
./bin/cpa-codex-butler status
```

## Daily Commands

Show current auth files that need login:

```bash
cpa-codex-butler status
```

Show every current Codex auth file:

```bash
cpa-codex-butler status --all
```

Preview cleanup and login queue:

```bash
cpa-codex-butler queue --dry-run
```

Quarantine invalid auth files and walk through manual re-login:

```bash
cpa-codex-butler queue
```

Skip per-account prompts:

```bash
cpa-codex-butler queue --yes
```

Queue a specific email. If no bad auth file exists for that email, this creates
a one-attempt manual login row:

```bash
cpa-codex-butler queue --email user@example.com
```

## Safety

- Reads only top-level `codex-*.json` files from `~/.cli-proxy-api`.
- Quarantines bad auth files under `~/.cli-proxy-api-state/codex-login-butler/quarantine/`, outside CPA's scanned auth directory.
- Never copies token files back into CPA automatically.
- Uses CPA Management `/v0/management/auth-files` for live runtime auth status.
- Treats `auth_unavailable`, `authentication_error`, invalidated-token text, disabled records, or missing access tokens as re-login signals.
