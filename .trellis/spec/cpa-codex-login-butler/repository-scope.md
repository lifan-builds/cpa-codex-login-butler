# Repository Scope

## Project-owned sources

- `src/cpa_codex_butler/` contains the Python 3.10+ CLI implementation.
- `bin/cpa-codex-butler` is the checkout launcher used for safe help-only validation without installing the package.
- `pyproject.toml` defines the setuptools package and console entry point. The project currently declares no runtime dependencies.
- `README.md` documents operator-facing behavior.
- `.trellis/spec/cpa-codex-login-butler/` is the durable source for agent-facing project rules.

## Preserve unless separately authorized

- Do not change application behavior, install the package, upgrade dependencies, or invent application tests as part of an agent-workflow migration.
- `src/cpa_codex_login_butler.egg-info/` is checked-in generated package metadata. Classify it as generated and preserve it unless a package-metadata task explicitly owns it.
- Preserve unrelated platform configuration and existing files. Trellis initialization and maintenance use non-destructive collision handling.

## Generated and managed integration

Trellis CLI owns `.trellis/` core files, `.claude/`, `.codex/`, the Codex-required shared `.agents/` surface, and managed entries in `.trellis/.template-hashes.json`. Do not deploy these paths through Agent Nexus, force an overwrite, or hand-edit the ownership ledger.

Project-specific rules belong in this spec layer, not in bundled Trellis skills.

## External and sensitive state

Authentication files, CPA runtime state, browser profiles and sessions, OAuth material, cookies, generated login images, caches, virtual environments, build output, and other machine-local state are not repository sources. Do not read their contents, copy them into tracked artifacts, stage them, or use them as migration fixtures.
