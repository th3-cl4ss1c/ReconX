from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from reconx.utils.process import raise_on_interrupt_returncode

_PROVIDER_CONFIG_CACHE: dict | None = None
_BW_SESSION_CACHE: str | None = None
_BW_TIMEOUT_WARNED: bool = False
_BW_ERROR_WARNED: bool = False
_BW_AUTH_WARNED: bool = False


def _load_provider_config() -> dict:
    global _PROVIDER_CONFIG_CACHE
    if _PROVIDER_CONFIG_CACHE is not None:
        return _PROVIDER_CONFIG_CACHE

    try:
        import yaml

        config_file = Path.home() / ".config" / "reconx" / "provider-config.yaml"
        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as f:
                _PROVIDER_CONFIG_CACHE = yaml.safe_load(f) or {}
                if isinstance(_PROVIDER_CONFIG_CACHE, dict):
                    return _PROVIDER_CONFIG_CACHE
    except Exception:
        pass
    _PROVIDER_CONFIG_CACHE = {}
    return _PROVIDER_CONFIG_CACHE


def _value_to_string(value: object) -> str | None:
    if not value:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    text = str(value).strip()
    return text or None


def _ensure_bw_env() -> None:
    """
    Готовим appdata-dir для bw cli (помогает в средах с ограниченной записью в $HOME).
    """
    if os.getenv("BITWARDENCLI_APPDATA_DIR"):
        return
    default = Path.home() / ".config" / "Bitwarden CLI"
    try:
        default.mkdir(parents=True, exist_ok=True)
        if os.access(default, os.W_OK):
            return
    except Exception:
        pass
    fallback = Path("/tmp") / f"bitwarden-cli-{os.getuid()}"
    fallback.mkdir(parents=True, exist_ok=True)
    os.environ["BITWARDENCLI_APPDATA_DIR"] = str(fallback)


def _bw_warn_once(kind: str, message: str) -> None:
    global _BW_TIMEOUT_WARNED, _BW_ERROR_WARNED, _BW_AUTH_WARNED
    if kind == "timeout":
        if _BW_TIMEOUT_WARNED:
            return
        _BW_TIMEOUT_WARNED = True
        print(message)
        return
    if kind == "auth":
        if _BW_AUTH_WARNED:
            return
        _BW_AUTH_WARNED = True
        print(message)
        return
    if kind == "error":
        if _BW_ERROR_WARNED:
            return
        _BW_ERROR_WARNED = True
        print(message)


def _looks_like_bw_auth_error(text: str) -> bool:
    low = text.lower()
    markers = (
        "not logged in",
        "vault is locked",
        "is locked",
        "you are not logged in",
        "unlock your vault",
        "unauthorized",
    )
    return any(marker in low for marker in markers)


def _bw_run(
    args: list[str],
    session: str | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess | None:
    cmd = ["bw", *args]
    if session:
        cmd.extend(["--session", session])
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        raise_on_interrupt_returncode(proc.returncode)
        if proc.returncode != 0 and _looks_like_bw_auth_error((proc.stderr or "") + "\n" + (proc.stdout or "")):
            _bw_warn_once(
                "auth",
                "ℹ️  Bitwarden заблокирован/не авторизован. Выполните: bw login && export BW_SESSION=\"$(bw unlock --raw)\"",
            )
        return proc
    except subprocess.TimeoutExpired:
        _bw_warn_once(
            "timeout",
            "⚠️  Bitwarden CLI timeout, продолжаю без bw (проверьте bw status/unlock).",
        )
        return None
    except Exception:
        _bw_warn_once("error", "⚠️  Bitwarden CLI недоступен, продолжаю без bw.")
        return None


def _bw_find_item_id(item_name: str, session: str | None = None) -> str | None:
    proc = _bw_run(["list", "items", "--search", item_name, "--raw"], session=session, timeout=45)
    if proc is None:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        items = json.loads(proc.stdout)
        if not isinstance(items, list):
            return None
    except Exception:
        return None

    target = item_name.strip().lower()
    exact = [it for it in items if str(it.get("name", "")).strip().lower() == target]
    candidate = exact[0] if exact else (items[0] if items else None)
    if not isinstance(candidate, dict):
        return None
    raw_id = candidate.get("id")
    return str(raw_id).strip() if raw_id else None


def _bw_extract_field(item: dict, field: str) -> str | None:
    f = (field or "password").strip()
    if not f:
        f = "password"
    login = item.get("login") if isinstance(item.get("login"), dict) else {}

    if f == "password":
        return _value_to_string(login.get("password"))
    if f == "username":
        return _value_to_string(login.get("username"))
    if f == "notes":
        return _value_to_string(item.get("notes"))
    if f == "uri":
        uris = login.get("uris") or []
        if isinstance(uris, list) and uris:
            first = uris[0]
            if isinstance(first, dict):
                return _value_to_string(first.get("uri"))
        return None
    if f.startswith("custom:"):
        need = f.split(":", 1)[1].strip().lower()
        fields = item.get("fields") or login.get("fields") or []
        if isinstance(fields, list):
            for entry in fields:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "")).strip().lower()
                if name == need:
                    return _value_to_string(entry.get("value"))
        return None
    return None


def _load_api_key_from_bw(item_name: str | None, field: str = "password") -> str | None:
    if not item_name:
        return None
    if not shutil.which("bw"):
        return None

    _ensure_bw_env()
    # 1) Пытаемся использовать существующую сессию (или unlocked state) без интерактива.
    for session in (os.getenv("BW_SESSION"), _BW_SESSION_CACHE, None):
        item_id = _bw_find_item_id(item_name, session=session)
        if not item_id:
            continue
        proc = _bw_run(["get", "item", item_id, "--raw"], session=session, timeout=45)
        if proc is None:
            continue
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        try:
            item_obj = json.loads(proc.stdout)
            if isinstance(item_obj, dict):
                value = _bw_extract_field(item_obj, field=field)
                if value:
                    return value
        except Exception:
            continue

    # 2) Интерактивный login/unlock в процессе скана не запускаем:
    # это мешает корректному Ctrl+C и делает поток выполнения хрупким.
    return None


def _load_api_key(
    env_var: str,
    config_key: str,
    bw_item_env_var: str,
    bw_field_env_var: str,
    bw_default_item: str,
) -> str | None:
    # 1) ENV (основной путь)
    api_key = _value_to_string(os.getenv(env_var))
    if api_key:
        return api_key

    config = _load_provider_config()

    # 2) Bitwarden CLI (основной путь)
    bw_item = _value_to_string(os.getenv(bw_item_env_var)) or _value_to_string(config.get(f"{config_key}_bw_item")) or bw_default_item
    bw_field = _value_to_string(os.getenv(bw_field_env_var)) or _value_to_string(config.get(f"{config_key}_bw_field")) or "password"
    api_key = _load_api_key_from_bw(bw_item, field=bw_field)
    if api_key:
        os.environ[env_var] = api_key
        return api_key

    # 3) provider-config.yaml (опциональный fallback)
    api_key = _value_to_string(config.get(config_key))
    if api_key:
        os.environ[env_var] = api_key
        return api_key
    return None


def run_hunter(domain: str, out_path: Path) -> None:
    api_key = _load_api_key(
        env_var="HUNTER_API_KEY",
        config_key="hunter_io",
        bw_item_env_var="RECONX_BW_HUNTER_ITEM",
        bw_field_env_var="RECONX_BW_HUNTER_FIELD",
        bw_default_item="reconx/hunter_io",
    )
    if not api_key:
        out_path.write_text("{}", encoding="utf-8")
        print("⚠️  HUNTER_API_KEY не найден (ENV/Bitwarden/provider-config), пропускаю")
        return

    try:
        import requests

        use_requests = True
    except ImportError:
        use_requests = False
        import urllib.error
        import urllib.request

    try:
        import urllib.parse

        def build_url(offset: int | None = None, limit: int | None = None) -> str:
            params = {
                "domain": domain,
                "api_key": api_key,
            }
            if offset is not None:
                params["offset"] = str(offset)
            if limit is not None:
                params["limit"] = str(limit)
            return f"https://api.hunter.io/v2/domain-search?{urllib.parse.urlencode(params)}"

        def fetch_page(offset: int | None = None, limit: int | None = None) -> dict | None:
            url = build_url(offset, limit)
            retry_statuses = {429, 500, 502, 503, 504}
            attempts = 3
            for attempt in range(1, attempts + 1):
                if use_requests:
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        return response.json()
                    if response.status_code in retry_statuses and attempt < attempts:
                        time.sleep(2)
                        continue
                    suppress_log = False
                    error_preview = ""
                    try:
                        error_json = response.json()
                        error_preview = error_json
                        if response.status_code == 400:
                            errors = error_json.get("errors") if isinstance(error_json, dict) else None
                            if isinstance(errors, list) and any(
                                isinstance(err, dict) and err.get("id") == "pagination_error" for err in errors
                            ):
                                suppress_log = True
                    except Exception:
                        error_preview = (response.text or "")[:300]
                        if response.status_code == 400 and "pagination_error" in str(error_preview):
                            suppress_log = True
                    if not suppress_log:
                        print(f"⚠️  hunter.io HTTP ошибка {response.status_code}: {error_preview}")
                    return None
                try:
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=30) as response:
                        return json.loads(response.read().decode("utf-8"))
                except urllib.error.HTTPError as e:
                    if e.code in retry_statuses and attempt < attempts:
                        time.sleep(2)
                        continue
                    body = ""
                    try:
                        body = (e.read() or b"").decode("utf-8", errors="replace")
                    except Exception:
                        body = ""
                    error_preview = body[:300] if body else ""
                    suppress_log = e.code == 400 and "pagination_error" in error_preview
                    if not suppress_log:
                        print(f"⚠️  hunter.io HTTP ошибка {e.code}: {error_preview}")
                    return None
                except Exception as e:
                    if attempt < attempts:
                        time.sleep(2)
                        continue
                    print(f"⚠️  hunter.io ошибка запроса: {e}")
                    return None
            return None

        def dedupe_emails(emails: list[dict]) -> list[dict]:
            seen: set[str] = set()
            unique: list[dict] = []
            for email in emails:
                value = str(email.get("value") or "").strip().lower()
                if not value or value in seen:
                    continue
                seen.add(value)
                unique.append(email)
            return unique

        limit = 100
        offset = 0
        all_emails: list[dict] = []
        base_data: dict | None = None
        meta: dict | None = None
        total_results: int | None = None
        page_limit: int | None = None
        page_count = 0
        max_pages = 20

        data = fetch_page()
        if data is None:
            out_path.write_text("{}", encoding="utf-8")
            print("⚠️  hunter.io ошибка: нет данных")
            return

        base_data = data
        page_emails = []
        if isinstance(data, dict):
            page_emails = data.get("data", {}).get("emails") or []
            if not isinstance(page_emails, list):
                page_emails = []
            if isinstance(data.get("meta"), dict):
                meta = data.get("meta")
                total_results = meta.get("results") if isinstance(meta.get("results"), int) else None
                page_limit = meta.get("limit") if isinstance(meta.get("limit"), int) else None

        all_emails.extend(page_emails)

        if total_results is not None and page_limit is not None and total_results > page_limit:
            limit = page_limit if page_limit > 0 else limit
            offset = limit
            while True:
                data = fetch_page(offset, limit)
                if data is None:
                    break

                page_emails = []
                if isinstance(data, dict):
                    page_emails = data.get("data", {}).get("emails") or []
                    if not isinstance(page_emails, list):
                        page_emails = []

                all_emails.extend(page_emails)

                if not page_emails:
                    break

                if total_results is not None and len(all_emails) >= total_results:
                    break

                offset += limit
                page_count += 1
                if page_count >= max_pages:
                    break

        all_emails = dedupe_emails(all_emails)
        if base_data is None:
            out_path.write_text("{}", encoding="utf-8")
            print("⚠️  hunter.io ошибка")
            return

        base_data.setdefault("data", {})
        base_data["data"]["emails"] = all_emails
        if meta is None and isinstance(base_data.get("meta"), dict):
            meta = base_data.get("meta")
        if meta is None:
            meta = {}
        meta.setdefault("results", len(all_emails))
        meta["offset"] = 0
        meta["limit"] = len(all_emails)
        base_data["meta"] = meta

        out_path.write_text(json.dumps(base_data, indent=2, ensure_ascii=False), encoding="utf-8")

        email_count = len(all_emails)
        print(f"hunter.io: {email_count} email{'ов' if email_count != 1 else ''}")

    except KeyboardInterrupt:
        raise
    except Exception:
        out_path.write_text("{}", encoding="utf-8")
        print("⚠️  hunter.io ошибка")


def run_snusbase(domain: str, out_path: Path) -> None:
    api_key = _load_api_key(
        env_var="SNUSBASE_API_KEY",
        config_key="snusbase",
        bw_item_env_var="RECONX_BW_SNUSBASE_ITEM",
        bw_field_env_var="RECONX_BW_SNUSBASE_FIELD",
        bw_default_item="reconx/snusbase",
    )
    if not api_key:
        out_path.write_text("{}", encoding="utf-8")
        print("⚠️  SNUSBASE_API_KEY не найден (ENV/Bitwarden/provider-config), пропускаю")
        return

    try:
        import requests

        use_requests = True
    except ImportError:
        use_requests = False
        import urllib.error
        import urllib.request

    try:
        url = "https://api.snusbase.com/data/search"
        headers = {
            "Content-Type": "application/json",
            "Auth": api_key,
        }
        payload = {
            "terms": [domain],
            "types": ["_domain"],
        }

        if use_requests:
            max_retries = 3
            retry_delay = 2
            result = None
            for attempt in range(max_retries):
                try:
                    response = requests.post(url, json=payload, headers=headers, timeout=45)
                    if response.status_code != 200:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        out_path.write_text("{}", encoding="utf-8")
                        print("⚠️  snusbase HTTP ошибка")
                        return
                    result = response.json()
                    break
                except requests.exceptions.Timeout:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase ошибка сети")
                    return
                except requests.exceptions.ConnectionError:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase ошибка сети")
                    return
                except requests.exceptions.RequestException:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase ошибка")
                    return
            if result is None:
                out_path.write_text("{}", encoding="utf-8")
                print("⚠️  snusbase ошибка")
                return
        else:
            import urllib.request

            max_retries = 3
            retry_delay = 2
            result = None
            data = json.dumps(payload).encode("utf-8")

            for attempt in range(max_retries):
                try:
                    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                    with urllib.request.urlopen(req, timeout=45) as response:
                        response_data = response.read()
                        response_text = response_data.decode("utf-8")
                        result = json.loads(response_text)
                        break
                except urllib.error.HTTPError:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase HTTP ошибка")
                    return
                except urllib.error.URLError:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase ошибка сети")
                    return

            if result is None:
                out_path.write_text("{}", encoding="utf-8")
                print("⚠️  snusbase ошибка")
                return

        out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        total_size = result.get("size", 0)
        print(f"snusbase: {total_size}")

    except KeyboardInterrupt:
        raise
    except Exception:
        out_path.write_text("{}", encoding="utf-8")
        print("⚠️  snusbase ошибка")
