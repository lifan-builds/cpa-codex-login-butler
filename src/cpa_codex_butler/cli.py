from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

URL_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-._~:/?#[]@!$&'()*+,;=%"
)
AUTH_MARKERS = (
    "auth_unavailable",
    "authentication_error",
    "authentication token",
    "invalidated",
    "invalid oauth",
    "invalidated oauth",
    "refresh_token_reused",
    "token_revoked",
    "signing in again",
    "sign in again",
    "unauthorized",
)


@dataclass
class Config:
    auth_dir: Path
    state_dir: Path
    base_url: str
    secret_file: Path
    cpa_config: Path
    timeout: int = 5


def default_state_dir() -> Path:
    configured = os.environ.get("CPA_CODEX_BUTLER_STATE_DIR") or os.environ.get(
        "CLIPROXYAPI_LOGIN_BUTLER_STATE_DIR"
    )
    return Path(configured or Path.home() / ".cli-proxy-api-state" / "codex-login-butler").expanduser()


def make_config(args: argparse.Namespace) -> Config:
    cpa_dir = Path(os.environ.get("CLIPROXYAPI_DIR", Path.home() / ".cli-proxy-api")).expanduser()
    return Config(
        auth_dir=Path(args.auth_dir or cpa_dir).expanduser(),
        state_dir=Path(args.state_dir or default_state_dir()).expanduser(),
        base_url=args.base_url or os.environ.get("CLIPROXYAPI_BASE_URL", "http://127.0.0.1:8317"),
        secret_file=Path(
            args.secret_file
            or os.environ.get("CLIPROXYAPI_MANAGEMENT_SECRET_FILE", cpa_dir / "management-secret.txt")
        ).expanduser(),
        cpa_config=Path(args.cpa_config or cpa_dir / "config.yaml").expanduser(),
        timeout=args.timeout,
    )


def account_hash(account_id: str) -> str:
    return hashlib.sha256(account_id.encode()).hexdigest()[:8] if account_id else "<missing>"


def top_level_codex_files(auth_dir: Path) -> list[Path]:
    return sorted(path for path in auth_dir.glob("codex-*.json") if path.is_file())


def load_auth_records(config: Config) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in top_level_codex_files(config.auth_dir):
        try:
            data = json.loads(path.read_text())
        except Exception as error:
            records.append({"file": path.name, "path": str(path), "error": str(error)})
            continue
        if data.get("type") != "codex":
            continue
        records.append(
            {
                "file": path.name,
                "path": str(path),
                "email": data.get("email") or "",
                "account_id_hash": account_hash(data.get("account_id") or ""),
                "disabled": bool(data.get("disabled")),
                "expired": data.get("expired") or "",
                "last_refresh": data.get("last_refresh") or "",
                "has_access_token": bool(data.get("access_token")),
                "has_refresh_token": bool(data.get("refresh_token")),
                "cpa_status": "",
                "cpa_message": "",
                "cpa_error": "",
                "cpa_disabled": False,
                "cpa_unavailable": False,
            }
        )
    return records


def read_management_secret(config: Config) -> str:
    env_secret = os.environ.get("CLIPROXYAPI_MANAGEMENT_SECRET", "").strip()
    if env_secret:
        return env_secret
    if not config.secret_file.exists():
        return ""
    return config.secret_file.read_text(encoding="utf-8").strip()


def request_json(base_url: str, path: str, bearer: str, timeout: int) -> dict[str, Any] | list[Any]:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def auth_file_items(payload: dict[str, Any] | list[Any]) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("auth_files", "authFiles", "files", "items", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def item_basename(item: dict[str, Any]) -> str:
    for key in ("file", "filename", "name", "path", "auth_file", "authFile"):
        value = item.get(key)
        if value:
            return Path(str(value)).name
    return ""


def item_status_message(item: dict[str, Any]) -> str:
    messages = []
    for key in ("status_message", "statusMessage", "message", "error", "last_error", "lastError"):
        value = item.get(key)
        if value:
            messages.append(str(value))
    return " | ".join(dict.fromkeys(messages))


def error_kind_from_message(message: str) -> str:
    if not message:
        return ""
    try:
        parsed = json.loads(message)
    except (TypeError, ValueError):
        return ""
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if not isinstance(error, dict):
        return ""
    return str(error.get("code") or error.get("type") or "")


def item_bool(item: dict[str, Any], *keys: str) -> bool:
    for key in keys:
        if key in item:
            value = item.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "on"}
            return bool(value)
    return False


def load_cpa_status(config: Config) -> tuple[dict[str, dict[str, Any]], str]:
    secret = read_management_secret(config)
    if not secret:
        return {}, "management secret unavailable"
    try:
        payload = request_json(config.base_url, "/v0/management/auth-files", secret, config.timeout)
    except urllib.error.HTTPError as error:
        return {}, f"management auth-files HTTP {error.code}"
    except urllib.error.URLError as error:
        return {}, f"management auth-files unreachable: {error.reason}"
    except TimeoutError:
        return {}, "management auth-files timed out"
    except Exception as error:
        return {}, f"management auth-files unavailable: {error}"

    statuses: dict[str, dict[str, Any]] = {}
    for item in auth_file_items(payload):
        if not isinstance(item, dict):
            continue
        basename = item_basename(item)
        if not basename.startswith("codex-") or not basename.endswith(".json"):
            continue
        message = item_status_message(item)
        statuses[basename] = {
            "cpa_status": str(item.get("status") or item.get("state") or ""),
            "cpa_message": message,
            "cpa_error": error_kind_from_message(message),
            "cpa_disabled": item_bool(item, "disabled"),
            "cpa_unavailable": item_bool(item, "unavailable", "is_unavailable", "unhealthy"),
        }
    return statuses, ""


def live_records(config: Config, offline: bool) -> tuple[list[dict[str, Any]], str]:
    records = load_auth_records(config)
    warning = ""
    if not offline:
        statuses, warning = load_cpa_status(config)
        for record in records:
            record.update(statuses.get(record.get("file") or "", {}))
    return records, warning


def records_by_email(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(record.get("email") or "<missing>", []).append(record)
    return grouped


def needs_relogin(record: dict[str, Any]) -> bool:
    status = str(record.get("cpa_status") or "").lower()
    message = str(record.get("cpa_message") or "").lower()
    error = str(record.get("cpa_error") or "").lower()
    combined = f"{status} {error} {message}"
    unavailable_status = record.get("cpa_unavailable") or "unavailable" in status or "disabled" in status
    return any(marker in combined for marker in AUTH_MARKERS) or (bool(unavailable_status) and "401" in combined)


def record_is_usable(record: dict[str, Any]) -> bool:
    return (
        not record.get("disabled")
        and not record.get("cpa_disabled")
        and not needs_relogin(record)
        and record.get("has_access_token")
    )


def record_needs_cleanup(record: dict[str, Any]) -> bool:
    return (
        bool(record.get("disabled"))
        or bool(record.get("cpa_disabled"))
        or needs_relogin(record)
        or not record.get("has_access_token")
    )


def record_reason_keys(record: dict[str, Any]) -> list[str]:
    reasons = []
    if record.get("disabled"):
        reasons.append("disabled")
    if record.get("cpa_disabled"):
        reasons.append("cpa_disabled")
    if needs_relogin(record):
        reasons.append("auth_401")
    if not record.get("has_access_token"):
        reasons.append("missing_access_token")
    return reasons


def summarize_reasons(records: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for record in records:
        for reason in record_reason_keys(record):
            counts[reason] = counts.get(reason, 0) + 1
    return ", ".join(f"{reason} {count}" for reason, count in counts.items()) or "requested"


def queue_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for email, email_records in sorted(records_by_email(records).items()):
        bad_records = [record for record in email_records if record_needs_cleanup(record)]
        if not bad_records:
            continue
        rows.append(
            {
                "email": email,
                "bad_files": len(bad_records),
                "usable": sum(1 for record in email_records if record_is_usable(record)),
                "attempts": max(len(bad_records), 1),
                "reason": summarize_reasons(bad_records),
            }
        )
    return rows


def manual_queue_row(email: str) -> dict[str, Any]:
    return {"email": email, "bad_files": 0, "usable": 0, "attempts": 1, "reason": "requested"}


def print_table(rows: list[list[Any]], headers: list[str]) -> None:
    if not rows:
        return
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    fmt = "  ".join("{:<" + str(width) + "}" for width in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * width for width in widths]))
    for row in rows:
        print(fmt.format(*[str(cell) for cell in row]))


def show_needs(rows: list[dict[str, Any]], warning: str = "") -> None:
    if rows:
        print_table(
            [[row["email"], row["bad_files"], row["usable"], row["attempts"], row["reason"]] for row in rows],
            ["email", "bad_files", "usable", "logins", "reason"],
        )
        return
    if warning:
        print("No local missing/disabled/token-invalid auth files detected.")
        print(f"Live CPA status was unavailable: {warning}")
    else:
        print("All current auth files look OK. No login needed.")


def quarantine_root(config: Config) -> Path:
    stamp = dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    target = config.state_dir / "quarantine" / stamp
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, 0o700)
    return target


def safe_auth_path(config: Config, record: dict[str, Any]) -> Path | None:
    path_text = record.get("path") or ""
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    try:
        resolved = path.resolve(strict=True)
        auth_dir = config.auth_dir.resolve(strict=True)
    except FileNotFoundError:
        return None
    if resolved.parent != auth_dir:
        return None
    if not resolved.name.startswith("codex-") or not resolved.name.endswith(".json"):
        return None
    return resolved


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(1, 1000):
        candidate = path.with_name(f"{path.name}.{index}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find unique quarantine destination for {path.name}")


def clean_email(config: Config, email: str, records: list[dict[str, Any]], dry_run: bool) -> list[dict[str, str]]:
    cleanup = [record for record in records_by_email(records).get(email, []) if record_needs_cleanup(record)]
    if not cleanup:
        return []
    target_dir = None if dry_run else quarantine_root(config)
    moved = []
    for record in cleanup:
        source = safe_auth_path(config, record)
        if not source:
            print(f"Skipped cleanup for {record.get('file') or '<unknown>'}: not a top-level Codex auth file.")
            continue
        destination = target_dir / source.name if target_dir else config.state_dir / "quarantine" / "<dry-run>" / source.name
        if target_dir:
            destination = unique_destination(destination)
        reason = str(record.get("cpa_error") or record.get("cpa_status") or "local-invalid")
        if dry_run:
            print(f"Would quarantine {source.name} for {email} ({reason}).")
        else:
            shutil.move(str(source), str(destination))
            os.chmod(destination, 0o600)
            print(f"Quarantined {source.name} for {email} -> {destination}")
        moved.append({"file": source.name, "destination": str(destination), "reason": reason})
    return moved


def extract_urls(text: str) -> list[str]:
    urls = []
    for marker in ("https://", "http://"):
        start = 0
        while True:
            index = text.find(marker, start)
            if index == -1:
                break
            end = index
            while end < len(text) and text[end] in URL_CHARS:
                end += 1
            urls.append(text[index:end].rstrip(".,);]}'\""))
            start = end
    return urls


def hinted_login_url(url: str, email: str) -> str:
    if not email:
        return url
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return url
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [(key, value) for key, value in params if key not in {"login_hint", "prompt"}]
    filtered.extend([("login_hint", email), ("prompt", "login")])
    query = urllib.parse.urlencode(filtered)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def open_url(url: str) -> bool:
    opener = shutil.which("open")
    if not opener:
        return False
    subprocess.Popen([opener, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def snapshot_files(config: Config) -> dict[str, float]:
    return {path.name: path.stat().st_mtime for path in top_level_codex_files(config.auth_dir)}


def changed_files(config: Config, before: dict[str, float]) -> list[Path]:
    changed = []
    for path in top_level_codex_files(config.auth_dir):
        previous = before.get(path.name)
        current = path.stat().st_mtime
        if previous is None or current > previous + 0.001:
            changed.append(path)
    return changed


def login_command(config: Config, args: argparse.Namespace) -> list[str]:
    binary = shutil.which(args.binary)
    if not binary:
        raise SystemExit(f"Could not find {args.binary!r} on PATH")

    command = [binary]
    if args.device:
        command.append("-codex-device-login")
    else:
        command.extend(["-codex-login", "--no-browser"])
        if args.port:
            command.extend(["--oauth-callback-port", str(args.port)])
    command.extend(["-config", str(config.cpa_config)])
    return command


def run_cpa_login(config: Config, args: argparse.Namespace, email: str = "") -> int:
    command = login_command(config, args)

    print("Running:", " ".join(command))
    print("Complete email/SMS/phone verification manually in the browser when prompted.")
    if args.device or args.print_url:
        return subprocess.run(command).returncode

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    opened = False
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="")
        if opened:
            continue
        for url in extract_urls(line):
            browser_url = hinted_login_url(url, email)
            if open_url(browser_url):
                print(f"Opened browser with login hint for {email}." if email else "Opened browser for CPA login.")
                opened = True
                break
    return process.wait()


def show_changed(config: Config, changed: list[Path]) -> None:
    if not changed:
        print("No new or modified top-level Codex auth file detected.")
        return
    print("New/modified Codex auth files:")
    for path in changed:
        try:
            data = json.loads(path.read_text())
            email = data.get("email") or "<missing>"
            seat = account_hash(data.get("account_id") or "")
            last_refresh = data.get("last_refresh") or "<missing>"
        except Exception:
            email = "<parse-error>"
            seat = "<parse-error>"
            last_refresh = "<parse-error>"
        print(f"- {path.name}: email={email} seat={seat} last_refresh={last_refresh}")


def login_once(config: Config, args: argparse.Namespace, email: str) -> None:
    before = snapshot_files(config)
    attempts = 2 if args.double else 1
    for attempt in range(1, attempts + 1):
        print(f"\nLogin attempt {attempt}/{attempts}")
        status = run_cpa_login(config, args, email=email)
        if status != 0:
            raise SystemExit(status)
        if attempt < attempts:
            print(f"Waiting {args.wait}s before second login...")
            time.sleep(args.wait)
    show_changed(config, changed_files(config, before))


def batch_login_items(rows: list[dict[str, Any]]) -> list[tuple[str, int, int]]:
    items = []
    for row in rows:
        attempts = int(row["attempts"])
        for attempt in range(1, attempts + 1):
            items.append((row["email"], attempt, attempts))
    return items


def stream_batch_login_output(
    process: subprocess.Popen[str],
    args: argparse.Namespace,
    email: str,
    label: str,
    print_lock: threading.Lock,
) -> None:
    opened = False
    assert process.stdout is not None
    for line in process.stdout:
        with print_lock:
            print(f"{label} {line}", end="")
        if opened or args.device or args.print_url:
            continue
        for url in extract_urls(line):
            browser_url = hinted_login_url(url, email)
            if open_url(browser_url):
                with print_lock:
                    print(f"{label} Opened browser with login hint for {email}.")
                opened = True
                break


def run_batch_logins(config: Config, args: argparse.Namespace, items: list[tuple[str, int, int]]) -> int:
    if args.port and len(items) > 1:
        raise SystemExit("Batch mode cannot reuse one --port for multiple login attempts; omit --port or run without --batch.")

    before = snapshot_files(config)
    print_lock = threading.Lock()
    processes: list[tuple[str, subprocess.Popen[str], threading.Thread]] = []
    total = len(items)
    for index, (email, attempt, attempts) in enumerate(items, 1):
        label = f"[{index}/{total}] {email}"
        if attempts > 1:
            label = f"{label} login {attempt}/{attempts}"
        command = login_command(config, args)
        print(f"Starting {label}: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        thread = threading.Thread(
            target=stream_batch_login_output,
            args=(process, args, email, label, print_lock),
            daemon=True,
        )
        thread.start()
        processes.append((label, process, thread))

    statuses = []
    for label, process, _thread in processes:
        statuses.append((label, process.wait()))
    for _label, _process, thread in processes:
        thread.join()

    show_changed(config, changed_files(config, before))
    failed = [(label, status) for label, status in statuses if status != 0]
    if failed:
        for label, status in failed:
            print(f"{label} exited with status {status}.")
        return failed[0][1]
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config = make_config(args)
    records, warning = live_records(config, args.offline)
    rows = queue_rows(records)

    if args.all:
        all_rows = []
        for email, email_records in sorted(records_by_email(records).items()):
            email_records.sort(key=lambda item: (item.get("account_id_hash"), item.get("file")))
            for index, record in enumerate(email_records):
                all_rows.append(
                    [
                        email if index == 0 else "",
                        record.get("account_id_hash", ""),
                        "yes" if record.get("disabled") else "no",
                        record.get("cpa_status") or "<unknown>",
                        record.get("cpa_error") or "",
                        "yes" if record.get("has_access_token") else "no",
                        "yes" if record.get("has_refresh_token") else "no",
                        record.get("last_refresh") or "<missing>",
                        record.get("file") or "",
                    ]
                )
        print_table(
            all_rows,
            ["email", "seat", "disabled", "cpa_status", "cpa_error", "access", "refresh", "last_refresh", "file"],
        )
        if warning:
            print(f"\nLive CPA status unavailable: {warning}")
        print("\nNeeds login:")
    show_needs(rows, warning)
    return 0


def selected_queue_rows(records: list[dict[str, Any]], emails: list[str] | None) -> list[dict[str, Any]]:
    rows = queue_rows(records)
    if not emails:
        return rows
    selected = set(emails)
    filtered = [row for row in rows if row["email"] in selected]
    queued = {row["email"] for row in filtered}
    for email in emails:
        if email not in queued:
            filtered.append(manual_queue_row(email))
            queued.add(email)
    return filtered


def cmd_queue(args: argparse.Namespace) -> int:
    config = make_config(args)
    records, warning = live_records(config, args.offline)
    if warning:
        print(f"Live CPA status unavailable ({warning}); falling back to local auth files.")
    rows = selected_queue_rows(records, args.email)
    if not rows:
        print("No matching auth files need login.")
        return 0

    print("Needs login:")
    show_needs(rows)
    attempts_by_email = {row["email"]: int(row["attempts"]) for row in rows}
    reasons_by_email = {row["email"]: row["reason"] for row in rows}

    if args.batch:
        items = batch_login_items(rows)
        action = "Start" if args.keep_old else "Quarantine bad files and start"
        if not args.yes and not args.dry_run:
            answer = input(f"{action} {len(items)} login attempt(s) for {len(rows)} account(s) at once? [y/N] ").strip().lower()
            if answer != "y":
                return 0
        for row in rows:
            if not args.keep_old:
                clean_email(config, row["email"], records, dry_run=args.dry_run)
        if args.dry_run:
            print(f"Would start {len(items)} login attempt(s) at once.")
            return 0
        return run_batch_logins(config, args, items)

    for index, email in enumerate([row["email"] for row in rows], 1):
        print(f"\n[{index}/{len(rows)}] {email}")
        print(f"reason: {reasons_by_email[email]}")
        attempts = attempts_by_email[email]
        if not args.yes and not args.dry_run:
            answer = input(f"Quarantine bad files and run {attempts} login attempt(s)? [y/N/q] ").strip().lower()
            if answer == "q":
                break
            if answer != "y":
                continue
        if not args.keep_old:
            clean_email(config, email, records, dry_run=args.dry_run)
        if args.dry_run:
            continue
        for attempt in range(1, attempts + 1):
            if attempts > 1:
                print(f"Seat login {attempt}/{attempts} for {email}")
            login_once(config, args, email)
    return 0


def add_global(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth-dir", help=argparse.SUPPRESS)
    parser.add_argument("--state-dir", help=argparse.SUPPRESS)
    parser.add_argument("--base-url", help=argparse.SUPPRESS)
    parser.add_argument("--secret-file", help=argparse.SUPPRESS)
    parser.add_argument("--cpa-config", help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=int, default=5, help=argparse.SUPPRESS)
    parser.add_argument("--offline", action="store_true", help="Skip CPA Management and use local auth JSON only.")
    parser.add_argument("--no-live-cpa", dest="offline", action="store_true", help=argparse.SUPPRESS)


def add_login_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--binary", default="cliproxyapi", help="CPA binary name/path.")
    parser.add_argument("--device", action="store_true", help="Use CPA device-code login instead of browser callback.")
    parser.add_argument("--print-url", action="store_true", help="Do not auto-open OAuth URL.")
    parser.add_argument("--no-open-browser", dest="print_url", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help="OAuth callback port override.")
    parser.add_argument("--oauth-callback-port", dest="port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--double", action="store_true", help="Run two login attempts for the same account.")
    parser.add_argument("--double-login", dest="double", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--wait", type=int, default=90, help="Seconds between --double attempts.")
    parser.add_argument("--between-attempts-seconds", dest="wait", type=int, help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cpa-codex-butler",
        description="Local helper for CPA Codex OAuth re-login queues.",
    )
    add_global(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Show current auth files needing login. Use --all for full table.")
    status.add_argument("--all", action="store_true", help="Show every top-level Codex auth file.")
    status.add_argument("--offline", action="store_true", default=argparse.SUPPRESS, help="Skip CPA Management and use local auth JSON only.")
    status.add_argument("--no-live-cpa", dest="offline", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    status.add_argument("--needs-login", action="store_true", help=argparse.SUPPRESS)
    status.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)
    status.set_defaults(func=cmd_status)

    queue = sub.add_parser("queue", help="Quarantine bad auth files and walk the login queue.")
    queue.add_argument("--offline", action="store_true", default=argparse.SUPPRESS, help="Skip CPA Management and use local auth JSON only.")
    queue.add_argument("--no-live-cpa", dest="offline", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    add_login_options(queue)
    queue.add_argument("--email", action="append", help="Only process this email; can be repeated.")
    queue.add_argument("--dry-run", action="store_true", help="Preview cleanup/login queue; do not move files or run login.")
    queue.add_argument("--dry-run-clean-auth", dest="dry_run", action="store_true", help=argparse.SUPPRESS)
    queue.add_argument("--batch", action="store_true", help="Start all selected login attempts at once.")
    queue.add_argument("--keep-old", action="store_true", help="Do not quarantine old invalid auth files first.")
    queue.add_argument("--no-clean-auth", dest="keep_old", action="store_true", help=argparse.SUPPRESS)
    queue.add_argument("--yes", "-y", action="store_true", help="Do not prompt per account.")
    queue.add_argument("--needs-login", action="store_true", help=argparse.SUPPRESS)
    queue.set_defaults(func=cmd_queue)

    return parser


def normalize_args(args: argparse.Namespace) -> None:
    for name, value in {
        "dry_run": False,
        "batch": False,
        "keep_old": False,
        "yes": False,
        "print_url": False,
        "device": False,
        "binary": "cliproxyapi",
        "double": False,
        "wait": 90,
        "port": None,
    }.items():
        if not hasattr(args, name) or getattr(args, name) is None:
            setattr(args, name, value)


def main(argv: list[str] | None = None) -> int:
    import sys

    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    normalize_args(args)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
