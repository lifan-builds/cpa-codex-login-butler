# CPA Codex Login Butler Specifications

These specifications govern the tracked Python CLI and its safety boundary around machine-local CPA/Codex authentication state.

## Pre-Development Checklist

1. Read [Repository Scope](repository-scope.md) before changing paths or dependencies.
2. Read [Authentication Safety](authentication-safety.md) before changing discovery, classification, quarantine, login, restore, or dry-run behavior.
3. Read [Verification](verification.md) before running any repository-native command.
4. Keep Trellis repository-local. Generate and maintain only Claude Code, Codex, and Codex-required shared `.agents/` integrations.
5. Start future Trellis maintenance with `trellis update --dry-run`; stop on unexpected deletion, unmanaged rewrite, or an ambiguous collision.

## Topics

- [Repository Scope](repository-scope.md) — project-owned sources, generated metadata, dependencies, and local-state boundaries.
- [Authentication Safety](authentication-safety.md) — roster identity, metadata-only discovery, quarantine, restore, token freshness, and preview rules.
- [Verification](verification.md) — permitted offline checks and forbidden auth-aware probes.

## Quality Check

Before completing work:

- confirm no credential, OAuth payload, token, cookie, browser/session state, generated QR image, or machine-local runtime file entered the diff;
- confirm same-email records were not collapsed and the saved roster remains authoritative;
- confirm quarantine remains outside the CPA auth directory and no automatic restore path was introduced;
- confirm dry-run remains preview-only;
- run only the bytecode-disabled help/parser checks allowed by [Verification](verification.md), unless the user separately authorizes a live operation;
- run Trellis context/package discovery and `git diff --check`.
