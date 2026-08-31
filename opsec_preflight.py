"""Read-only OPSEC checks and optional fail-closed worker preflight."""
from __future__ import annotations

import ast
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from config_loader import get_bool, get_int, get_str
from paths import BASE_DIR, REPORTS_DIR
from screenshot_service import preview_safety_contract
from tor_circuits import circuit_policy_status, playwright_proxy, requests_proxy_url
from artifact_hygiene import scan_workspace_hygiene
from log_redaction import redact_for_log


AUDIT_STATE_PATH = REPORTS_DIR / "opsec_audit.json"
PROJECT_SOURCE_DIRS = ("dashboard_pages", "dashboard_services", "scripts")


def _reachable(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_direct_fetch_paths(root: Path = BASE_DIR) -> dict:
    """Statically reject unapproved outbound transports in runtime source."""
    findings: list[str] = []
    project_files = list(root.glob("*.py"))
    for directory in PROJECT_SOURCE_DIRS:
        source_root = root / directory
        if source_root.is_dir():
            project_files.extend(source_root.rglob("*.py"))
    for path in sorted(set(project_files)):
        relative = path.relative_to(root)
        if ".bak" in path.name:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
        except (OSError, SyntaxError) as exc:
            findings.append(f"{relative}:parse:{type(exc).__name__}")
            continue
        module_aliases: dict[str, str] = {}
        callable_aliases: dict[str, str] = {}
        session_variables: set[str] = set()
        llm_loopback_endpoint = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    bound_name = item.asname or item.name.split(".", 1)[0]
                    module_aliases[bound_name] = item.name if item.asname else item.name.split(".", 1)[0]
                    if item.name.split(".", 1)[0] in {"httpx", "aiohttp"}:
                        findings.append(f"{relative}:{node.lineno}:unapproved_http_library")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.split(".", 1)[0] in {"httpx", "aiohttp"}:
                    findings.append(f"{relative}:{node.lineno}:unapproved_http_library")
                for item in node.names:
                    qualified = f"{module}.{item.name}" if module else item.name
                    callable_aliases[item.asname or item.name] = qualified
            elif (isinstance(node, (ast.Assign, ast.AnnAssign))
                  and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id == "LLM_ENDPOINT" for target in targets):
                    try:
                        llm_loopback_endpoint = (urlsplit(node.value.value).hostname or "").casefold() in {
                            "localhost", "127.0.0.1", "::1"}
                    except ValueError:
                        llm_loopback_endpoint = False

        def qualified_name(
            node: ast.AST,
            callable_aliases: dict[str, str] = callable_aliases,
            module_aliases: dict[str, str] = module_aliases,
        ) -> str:
            if isinstance(node, ast.Name):
                return callable_aliases.get(node.id, module_aliases.get(node.id, node.id))
            if isinstance(node, ast.Attribute):
                owner = qualified_name(node.value)
                return f"{owner}.{node.attr}" if owner else node.attr
            return ""

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if isinstance(value, ast.Call) and qualified_name(value.func) in {
                        "requests.Session", "http.client.HTTPConnection", "http.client.HTTPSConnection",
                        "urllib.request.build_opener"}:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    session_variables.update(
                        target.id for target in targets if isinstance(target, ast.Name))
            if not isinstance(node, ast.Call):
                continue
            called = qualified_name(node.func)
            allowed_requests = relative.as_posix() == "safe_transport.py"
            allowed_preview = relative.as_posix() == "screenshot_service.py"
            if (called in {"requests.get", "requests.post", "requests.put", "requests.delete",
                           "requests.patch", "requests.request"}
                    and not allowed_requests):
                findings.append(f"{relative}:{node.lineno}:{called}")
            if (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in session_variables
                    and node.func.attr in {"get", "post", "put", "delete", "patch", "request", "open"}
                    and not allowed_requests):
                findings.append(f"{relative}:{node.lineno}:session.{node.func.attr}")
            if called in {"urllib.request.urlopen", "urllib.urlopen"}:
                if relative.as_posix() != "llm_classifier.py" or not llm_loopback_endpoint:
                    findings.append(f"{relative}:{node.lineno}:urlopen")
            if called in {"http.client.HTTPConnection", "http.client.HTTPSConnection"}:
                findings.append(f"{relative}:{node.lineno}:{called}")
            if (called.endswith(".goto") or called == "page.goto") and not allowed_preview:
                findings.append(f"{relative}:{node.lineno}:page.goto")
    return {"pass": not findings, "findings": findings}


def _isolation_status() -> tuple[str, str]:
    if not get_bool("TOR_SOCKS_ISOLATION", True):
        return "missing", "TOR_SOCKS_ISOLATION is disabled"
    host = get_str("TOR_CONTROL_HOST", "127.0.0.1") or "127.0.0.1"
    port = get_int("TOR_CONTROL_PORT", 9051)
    if not _reachable(host, port, timeout=0.2):
        return "unknown", "ControlPort is not reachable"
    previous_timeout = socket.getdefaulttimeout()
    try:
        from stem.control import Controller
        password = get_str("TOR_CONTROL_PASSWORD")
        socket.setdefaulttimeout(0.75)
        with Controller.from_port(address=host, port=port) as controller:
            controller.authenticate(password=password or None)
            values = controller.get_conf("SocksPort", multiple=True) or []
        joined = " ".join(values if isinstance(values, list) else [str(values)])
        if "IsolateSOCKSAuth" in joined:
            return "configured", "SocksPort includes IsolateSOCKSAuth"
        return "missing", "SocksPort does not advertise IsolateSOCKSAuth"
    except Exception:
        return "unknown", "ControlPort could not confirm SocksPort isolation"
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _release_hygiene_status() -> bool:
    try:
        from scripts.make_clean_release import release_files
        forbidden_names = {".env", "runtime_settings.json", "messages.db"}
        for path in release_files():
            relative = path.relative_to(BASE_DIR)
            lowered = {part.casefold() for part in relative.parts}
            name = path.name.casefold()
            if (lowered & {"backups", "logs", "reports", "previews", "screenshots", "__pycache__", ".pytest_cache"}
                    or name in forbidden_names
                    or name.endswith((".db", ".db-wal", ".db-shm", ".session", ".session-journal", ".log"))):
                return False
        return True
    except Exception:
        return False


def _log_redaction_status() -> bool:
    token = "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
    api_hash = "0123456789abcdef0123456789abcdef"
    proxy_password = "audit-proxy-password"
    onion = f"{'a' * 56}.onion"
    redacted = redact_for_log(
        f"bot_token={token} api_hash={api_hash} "
        f"socks5h://user:{proxy_password}@127.0.0.1:9050 {onion}")
    return all(secret not in redacted for secret in (token, api_hash, proxy_password, onion))


def _cached_audit() -> dict:
    try:
        value = json.loads(AUDIT_STATE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def opsec_status_snapshot() -> dict:
    """Return cached/config-derived status without opening any Tor socket."""
    cached = _cached_audit()
    proxy_scheme = urlsplit(requests_proxy_url()).scheme.casefold()
    preview = preview_safety_contract()
    preview_proxy_ok = playwright_proxy().get("server", "").casefold().startswith("socks5://")
    return {
        "timestamp": cached.get("timestamp"),
        "status": cached.get("status", "NOT_AUDITED"),
        "strict_mode": get_bool("OPSEC_STRICT_MODE", False),
        "tor_socks_reachable": cached.get("tor_socks_reachable"),
        "socks5h_enforced": proxy_scheme == "socks5h",
        "socks_isolation": cached.get(
            "socks_isolation", "unknown" if get_bool("TOR_SOCKS_ISOLATION", True) else "missing"),
        "preview_proxy_ok": preview_proxy_ok,
        "preview_policy": preview,
        "direct_fetch_scan": cached.get("direct_fetch_scan", {"pass": None, "findings": []}),
        "release_hygiene": cached.get("release_hygiene"),
        "workspace_hygiene": cached.get("workspace_hygiene"),
        "live_checks_performed": False,
    }


def run_opsec_audit(*, persist: bool = False) -> dict:
    host = get_str("TOR_SOCKS_HOST", "127.0.0.1") or "127.0.0.1"
    port = get_int("TOR_SOCKS_PORT", 9050)
    proxy = requests_proxy_url()
    proxy_scheme = urlsplit(proxy).scheme.casefold()
    socks5h = proxy_scheme == "socks5h"
    socks_reachable = _reachable(host, port)
    isolation, isolation_detail = _isolation_status()
    preview = preview_safety_contract()
    preview_proxy = playwright_proxy().get("server", "")
    preview_proxy_ok = preview_proxy.casefold().startswith("socks5://")
    direct = scan_direct_fetch_paths()
    log_redaction_ok = _log_redaction_status()
    strict = get_bool("OPSEC_STRICT_MODE", False)
    require_isolation = get_bool("OPSEC_REQUIRE_TOR_ISOLATION", False)
    screenshots_enabled = get_bool("ENABLE_PAGE_SCREENSHOTS", False)
    critical = {
        "tor_socks_reachable": socks_reachable,
        "socks5h_enforced": socks5h,
        "direct_fetch_scan": bool(direct["pass"]),
        "preview_policy": all(preview.values()),
        "preview_proxy": (not screenshots_enabled or preview_proxy_ok),
        "required_isolation": (not require_isolation or isolation == "configured"),
        "log_redaction": log_redaction_ok,
    }
    release_hygiene = _release_hygiene_status()
    workspace_hygiene = scan_workspace_hygiene()
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "PASS" if all(critical.values()) else "FAIL",
        "strict_mode": strict,
        "tor_socks_reachable": socks_reachable,
        "socks5h_enforced": socks5h,
        "socks_isolation": isolation,
        "socks_isolation_detail": isolation_detail,
        "newnym_enabled": bool(circuit_policy_status().get("newnym_enabled")),
        "preview_proxy_ok": preview_proxy_ok,
        "preview_policy": preview,
        "direct_fetch_scan": direct,
        "release_hygiene": release_hygiene,
        "workspace_hygiene": workspace_hygiene,
        "log_redaction": log_redaction_ok,
        "critical_checks": critical,
    }
    if strict and workspace_hygiene.get("highest_severity") == "critical":
        result["critical_checks"]["workspace_hygiene"] = False
        result["status"] = "FAIL"
    if persist:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        AUDIT_STATE_PATH.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def enforce_strict_mode() -> dict:
    result = run_opsec_audit(persist=True)
    if get_bool("OPSEC_STRICT_MODE", False) and result["status"] != "PASS":
        failures = ", ".join(key for key, passed in result["critical_checks"].items() if not passed)
        raise RuntimeError(f"OPSEC strict mode blocked worker startup: {failures}")
    return result


def format_opsec_audit(result: dict) -> str:
    def line(label: str, passed: bool, detail: str = "") -> str:
        return f"{'PASS' if passed else 'FAIL'}  {label}" + (f" - {detail}" if detail else "")
    isolation = result["socks_isolation"]
    isolation_prefix = "PASS" if isolation == "configured" else "WARN" if isolation == "unknown" else "FAIL"
    preview = result["preview_policy"]
    lines = [
        line("Tor SOCKS reachable", result["tor_socks_reachable"]),
        line("socks5h enforced", result["socks5h_enforced"]),
        f"{isolation_prefix}  SOCKS auth isolation - {isolation}",
        f"{'PASS' if result['newnym_enabled'] else 'WARN'}  NEWNYM - " +
        ("enabled" if result["newnym_enabled"] else "optional renewal disabled"),
        line("Preview proxy", result["preview_proxy_ok"]),
        line("Preview JS/download/subresource policy", all(preview.values())),
        line("Direct-fetch source scan", result["direct_fetch_scan"]["pass"]),
        line("Source release is clean", result["release_hygiene"]),
        line("Workspace source-handoff hygiene", bool((result.get("workspace_hygiene") or {}).get("pass")),
             f"{(result.get('workspace_hygiene') or {}).get('total_findings', 0)} finding(s), highest="
             f"{(result.get('workspace_hygiene') or {}).get('highest_severity', 'unknown')}"),
        line("Log redaction", result["log_redaction"]),
    ]
    return "\n".join(lines)
