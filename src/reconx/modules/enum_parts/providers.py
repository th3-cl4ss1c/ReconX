from __future__ import annotations

import json
import os
import time
from pathlib import Path


def _load_api_key(env_var: str, config_key: str) -> str | None:
    api_key = os.getenv(env_var)
    if api_key:
        return str(api_key)

    try:
        import yaml

        config_file = Path.home() / ".config" / "reconx" / "provider-config.yaml"
        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
                value = config.get(config_key)
                if value:
                    api_key = value[0] if isinstance(value, list) else value
                    os.environ[env_var] = str(api_key)
                    return str(api_key)
    except Exception:
        return None
    return None


def run_hunter(domain: str, out_path: Path) -> None:
    api_key = _load_api_key("HUNTER_API_KEY", "hunter_io")
    if not api_key:
        out_path.write_text("{}", encoding="utf-8")
        print("⚠️  HUNTER_API_KEY не установлен, пропускаю")
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
    api_key = _load_api_key("SNUSBASE_API_KEY", "snusbase")
    if not api_key:
        out_path.write_text("{}", encoding="utf-8")
        print("⚠️  SNUSBASE_API_KEY не установлен, пропускаю")
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
