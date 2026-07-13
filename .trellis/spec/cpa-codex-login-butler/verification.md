# Verification

## Safe repository-native checks

Use the checkout launcher with bytecode generation disabled. The migration-safe application probes are limited to parser/help behavior:

```bash
PYTHONDONTWRITEBYTECODE=1 ./bin/cpa-codex-butler --help
PYTHONDONTWRITEBYTECODE=1 ./bin/cpa-codex-butler status --help
PYTHONDONTWRITEBYTECODE=1 ./bin/cpa-codex-butler queue --help
```

These checks validate argument construction only. They do not prove live CPA connectivity, credential validity, quarantine behavior, OAuth, browser integration, or successful re-login.

## Forbidden migration probes

Do not install the package or execute an application subcommand that discovers or mutates authentication state. In particular, do not run `status`, `queue`, `fix`, login, OAuth/browser flows, or a product dry-run. Do not read external auth/token files to construct fixtures.

## Trellis checks

For workflow-only changes:

1. Run `python3 ./.trellis/scripts/get_context.py`, phase mode, and package mode.
2. Confirm the project spec layer is discoverable and all indexed links resolve.
3. Parse generated JSON, JSONL, YAML, and TOML with local standard-library parsers where available.
4. Resolve every configured hook/command target inside the repository and use only isolated, non-auth fixtures.
5. Exercise disposable task lifecycle without modifying a real task and without allowing auto-commit.
6. Confirm `.trellis/.template-hashes.json` matches every managed file.
7. Run `git diff --check` and review every changed path for sensitive/runtime state and migration-only scope.

Unsupported or intentionally forbidden live probes are explicit skips, never passes.
