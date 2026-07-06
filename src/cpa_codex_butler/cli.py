from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
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

    @property
    def state_path(self) -> Path:
        return self.state_dir / "accounts.json"


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


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


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


def load_state(config: Config) -> dict[str, Any]:
    if not config.state_path.exists():
        return {"version": 1, "accounts": {}, "updated_at": ""}
    return json.loads(config.state_path.read_text())


def save_state(config: Config, state: dict[str, Any]) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    tmp = config.state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    os.replace(tmp, config.state_path)
    os.chmod(config.state_path, 0o600)


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
        and record.get("has_refresh_token")
    )


def record_needs_cleanup(record: dict[str, Any]) -> bool:
    return (
        bool(record.get("disabled"))
        or bool(record.get("cpa_disabled"))
        or needs_relogin(record)
        or not record.get("has_access_token")
        or not record.get("has_refresh_token")
    )


def need_rows(state: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped = records_by_email(records)
    rows = []
    for email, account in sorted(state.get("accounts", {}).items()):
        email_records = grouped.get(email, [])
        usable = [record for record in email_records if record_is_usable(record)]
        expected = int(account.get("expected_seats") or 1)
        disabled = [record for record in email_records if record.get("disabled")]
        cpa_disabled = [record for record in email_records if record.get("cpa_disabled")]
        cpa_401 = [record for record in email_records if needs_relogin(record)]
        invalid = [record for record in email_records if not record.get("has_access_token") or not record.get("has_refresh_token")]
        missing = max(0, expected - len(usable))
        if not (missing or disabled or cpa_disabled or cpa_401 or invalid):
            continue
        reasons = []
        if missing:
            reasons.append(f"missing {missing}/{expected}")
        if disabled:
            reasons.append(f"disabled {len(disabled)}")
        if cpa_disabled:
            reasons.append(f"cpa_disabled {len(cpa_disabled)}")
        if cpa_401:
            reasons.append(f"auth_401 {len(cpa_401)}")
        if invalid:
            reasons.append(f"missing_token {len(invalid)}")
        rows.append(
            {
                "email": email,
                "expected": expected,
                "usable": len(usable),
                "attempts": max(missing, 1 if disabled or cpa_disabled or cpa_401 or invalid else 0),
                "reason": ", ".join(reasons),
            }
        )
    return rows


def update_roster(config: Config) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    state = load_state(config)
    accounts = state.setdefault("accounts", {})
    records = load_auth_records(config)
    seen_seats: dict[str, set[str]] = {}
    for record in records:
        email = record.get("email")
        if not email:
            continue
        seen_seats.setdefault(email, set()).add(record["account_id_hash"])
        account = accounts.setdefault(
            email,
            {
                "email": email,
                "label": email.split("@", 1)[0],
                "expected_seats": 1,
                "phone_hint": "",
                "email_hint": "",
                "browser_profile": "",
                "notes": "",
                "created_at": now_iso(),
            },
        )
        seat = account.setdefault("seats", {}).setdefault(
            record["account_id_hash"],
            {"seat": record["account_id_hash"], "label": f"seat-{record['account_id_hash']}", "created_at": now_iso()},
        )
        seat.update(
            {
                "file": record["file"],
                "disabled": record["disabled"],
                "expired": record["expired"],
                "last_refresh": record["last_refresh"],
                "has_access_token": record["has_access_token"],
                "has_refresh_token": record["has_refresh_token"],
                "seen_at": now_iso(),
            }
        )
    for email, seats in seen_seats.items():
        accounts[email]["expected_seats"] = max(int(accounts[email].get("expected_seats") or 1), len(seats))
    state["updated_at"] = now_iso()
    save_state(config, state)
    return state, records


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
            [[row["email"], row["expected"], row["usable"], row["attempts"], row["reason"]] for row in rows],
            ["email", "expected", "usable", "logins", "reason"],
        )
        return
    if warning:
        print("No static missing/disabled/token-invalid accounts detected.")
        print(f"Live CPA status was unavailable: {warning}")
    else:
        print("All saved accounts look OK. No login needed.")


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


def run_cpa_login(config: Config, args: argparse.Namespace, email: str = "") -> int:
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
    update_roster(config)
    show_changed(config, changed_files(config, before))


def cmd_status(args: argparse.Namespace) -> int:
    config = make_config(args)
    if getattr(args, "update_roster", False):
        update_roster(config)
    state = load_state(config)
    records, warning = live_records(config, args.offline)
    rows = need_rows(state, records)

    if args.all:
        all_rows = []
        for email, email_records in sorted(records_by_email(records).items()):
            email_records.sort(key=lambda item: (item.get("account_id_hash"), item.get("file")))
            expected = state.get("accounts", {}).get(email, {}).get("expected_seats", "")
            for index, record in enumerate(email_records):
                all_rows.append(
                    [
                        email if index == 0 else "",
                        expected if index == 0 else "",
                        record.get("account_id_hash", ""),
                        "yes" if record.get("disabled") else "no",
                        record.get("cpa_status") or "<unknown>",
                        record.get("cpa_error") or "",
                        "yes" if record.get("has_refresh_token") else "no",
                        record.get("last_refresh") or "<missing>",
                        record.get("file") or "",
                    ]
                )
        print_table(all_rows, ["email", "expected", "seat", "disabled", "cpa_status", "cpa_error", "refresh", "last_refresh", "file"])
        if warning:
            print(f"\nLive CPA status unavailable: {warning}")
        print("\nNeeds login:")
    show_needs(rows, warning)
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    config = make_config(args)
    state = load_state(config)
    records, warning = live_records(config, args.offline)
    if warning:
        print(f"Live CPA status unavailable ({warning}); falling back to local auth files.")
    rows = need_rows(state, records)
    selected = set(args.email or [row["email"] for row in rows])
    rows = [row for row in rows if row["email"] in selected]
    if not rows:
        print("No matching accounts need login.")
        return 0

    print("Needs login:")
    show_needs(rows)
    attempts_by_email = {row["email"]: int(row["attempts"]) for row in rows}
    reasons_by_email = {row["email"]: row["reason"] for row in rows}

    for index, email in enumerate([row["email"] for row in rows], 1):
        account = state.get("accounts", {}).get(email, {})
        print(f"\n[{index}/{len(rows)}] {email}")
        print(f"reason: {reasons_by_email[email]}")
        for label in ("phone_hint", "email_hint", "notes"):
            if account.get(label):
                print(f"{label.replace('_', ' ')}: {account[label]}")
        attempts = attempts_by_email[email]
        if not args.yes:
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


def cmd_login(args: argparse.Namespace) -> int:
    config = make_config(args)
    if args.clean:
        records, warning = live_records(config, args.offline)
        if warning:
            print(f"Live CPA status unavailable ({warning}); using local auth-file cleanup only.")
        clean_email(config, args.email, records, dry_run=args.dry_run)
        if args.dry_run:
            return 0
    login_once(config, args, args.email)
    return 0


def cmd_roster_sync(args: argparse.Namespace) -> int:
    config = make_config(args)
    state, records = update_roster(config)
    print(f"Synced {len(records)} Codex auth records into {config.state_path}")
    print(f"Accounts: {len(state.get('accounts', {}))}")
    return 0


def cmd_roster_set(args: argparse.Namespace) -> int:
    config = make_config(args)
    state = load_state(config)
    account = state.setdefault("accounts", {}).setdefault(
        args.email,
        {
            "email": args.email,
            "label": args.email.split("@", 1)[0],
            "phone_hint": "",
            "email_hint": "",
            "browser_profile": "",
            "notes": "",
            "created_at": now_iso(),
            "seats": {},
        },
    )
    if args.seats is not None:
        if args.seats < 1:
            raise SystemExit("--seats must be >= 1")
        account["expected_seats"] = args.seats
    for key in ("label", "phone_hint", "email_hint", "notes"):
        value = getattr(args, key)
        if value is not None:
            account[key] = value
    state["updated_at"] = now_iso()
    save_state(config, state)
    print(f"Updated {args.email} in {config.state_path}")
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

    status = sub.add_parser("status", help="Show accounts needing login. Use --all for full auth-file table.")
    status.add_argument("--all", action="store_true", help="Show every top-level Codex auth file.")
    status.add_argument("--update-roster", action="store_true", help="Sync roster before status.")
    status.add_argument("--needs-login", action="store_true", help=argparse.SUPPRESS)
    status.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)
    status.set_defaults(func=cmd_status)

    fix = sub.add_parser("fix", help="Quarantine bad auth files and walk the login queue.")
    add_login_options(fix)
    fix.add_argument("--email", action="append", help="Only process this email; can be repeated.")
    fix.add_argument("--dry-run", action="store_true", help="Preview cleanup/login queue; do not move files or run login.")
    fix.add_argument("--dry-run-clean-auth", dest="dry_run", action="store_true", help=argparse.SUPPRESS)
    fix.add_argument("--keep-old", action="store_true", help="Do not quarantine old invalid auth files first.")
    fix.add_argument("--no-clean-auth", dest="keep_old", action="store_true", help=argparse.SUPPRESS)
    fix.add_argument("--yes", "-y", action="store_true", help="Do not prompt per account.")
    fix.add_argument("--needs-login", action="store_true", help=argparse.SUPPRESS)
    fix.set_defaults(func=cmd_fix)

    login = sub.add_parser("login", help="Login one email manually.")
    login.add_argument("email", nargs="?", help="Email to hint on the OAuth URL.")
    login.add_argument("--login-hint", dest="legacy_login_hint", help=argparse.SUPPRESS)
    add_login_options(login)
    login.add_argument("--clean", action="store_true", help="Quarantine bad files for this email before login.")
    login.add_argument("--dry-run", action="store_true", help="With --clean, preview cleanup and do not login.")
    login.set_defaults(func=cmd_login)

    roster = sub.add_parser("roster", help="Manage saved account roster.")
    roster_sub = roster.add_subparsers(dest="roster_command", required=True)
    roster_sync = roster_sub.add_parser("sync", help="Refresh saved roster from current auth files.")
    roster_sync.set_defaults(func=cmd_roster_sync)
    roster_set = roster_sub.add_parser("set", help="Set notes or expected seats for an email.")
    roster_set.add_argument("email")
    roster_set.add_argument("--seats", type=int, help="Expected seat count.")
    roster_set.add_argument("--expected-seats", dest="seats", type=int, help=argparse.SUPPRESS)
    roster_set.add_argument("--label")
    roster_set.add_argument("--phone-hint")
    roster_set.add_argument("--email-hint")
    roster_set.add_argument("--notes")
    roster_set.set_defaults(func=cmd_roster_set)

    return parser


def normalize_args(args: argparse.Namespace) -> None:
    if getattr(args, "legacy_login_hint", None) and not args.email:
        args.email = args.legacy_login_hint
    if getattr(args, "command", "") == "login" and not args.email:
        raise SystemExit("login requires EMAIL, e.g. cpa-codex-butler login user@example.com")
    for name, value in {
        "dry_run": False,
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


def normalize_legacy_argv(argv: list[str] | None) -> list[str] | None:
    if argv is None:
        return None
    if not argv:
        return argv
    first = argv[0]
    if first == "queue":
        return ["fix", *argv[1:]]
    if first in {"update-roster", "sync"}:
        return ["roster", "sync", *argv[1:]]
    if first == "set":
        return ["roster", "set", *argv[1:]]
    return argv


def main(argv: list[str] | None = None) -> int:
    import sys

    parser = build_parser()
    args = parser.parse_args(normalize_legacy_argv(list(sys.argv[1:] if argv is None else argv)))
    normalize_args(args)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
