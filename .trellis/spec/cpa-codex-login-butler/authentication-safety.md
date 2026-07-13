# Authentication Safety

## Discovery and identity

- Discovery may report metadata such as file class, count, status category, and a non-secret reference. It must not expose token values, credential bodies, cookies, OAuth payloads, browser state, or sensitive source details.
- Same-email records can represent distinct seats. Never deduplicate authentication records by email alone.
- The saved roster is authoritative for the intended account set.
- Missing, disabled, token-invalid, runtime `401`, and `auth_unavailable` states are re-login signals, not permission to repair automatically.
- Account verification and OAuth re-login remain manual operator actions.

## Quarantine boundary

- Invalid top-level Codex authentication JSON is quarantined outside the CPA authentication directory before manual re-login.
- Never place a backup beneath `~/.cli-proxy-api`; recursive scanning can treat it as another live credential.
- Never copy one rotating refresh token into multiple live homes.
- Quarantine is one-way during normal repair. Do not automatically restore quarantined or backed-up JSON.
- A restore requires explicit operator selection, review of freshness and destination safety, and proof that it cannot overwrite newer rotating refresh-token state.

## Preview and mutation

- Dry-run is preview-only. It may describe proposed quarantine or re-login actions but must not mutate authentication or runtime state.
- A preview is not authorization to execute login, quarantine, restore, browser, or OAuth work.
- Tests and migration checks must use isolated parser/help behavior and must not discover live authentication state, including through a product dry-run.

## Logging and artifacts

Record only redacted metadata needed to explain a decision. Never place secrets, raw command output containing sensitive material, personal account details, or machine-local runtime contents in Trellis tasks, specs, journals, commits, or reports.
