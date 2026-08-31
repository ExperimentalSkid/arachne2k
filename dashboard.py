"""Lightweight Streamlit entry point for the passive OSINT workspace.

Page rendering lives in :mod:`dashboard_pages`; importing this module performs
no GUI, crawler, repair, or network work.
"""
from __future__ import annotations

import html

import streamlit as st

import dashboard_auth
from dashboard_pages.workspace import (
    _need_review_count,  # noqa: F401 - compatibility helpers used by extensions/tests
    _restricted_hidden_count,  # noqa: F401
    _scalar,  # noqa: F401
    main as _render_workspace,
)

DASHBOARD_SESSION_QUERY_KEY = "rt_session"
_SESSION_EXIT_STATE_KEY = "_dashboard_show_session_exit"


def _format_remaining(seconds: int) -> str:
    seconds = max(0, int(seconds or 0))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m {secs:02d}s"


def _query_session_token() -> str | None:
    try:
        value = st.query_params.get(DASHBOARD_SESSION_QUERY_KEY)
    except Exception:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    value = str(value or "").strip()
    return value or None


def _set_query_session_token(token: str | None) -> None:
    try:
        if token:
            st.query_params[DASHBOARD_SESSION_QUERY_KEY] = token
        elif DASHBOARD_SESSION_QUERY_KEY in st.query_params:
            del st.query_params[DASHBOARD_SESSION_QUERY_KEY]
    except Exception:
        return


def _current_session_token() -> tuple[str | None, bool]:
    """Return the current token and whether it came from the URL on this run."""
    state_token = str(st.session_state.get("dashboard_session_token") or "").strip()
    if state_token:
        return state_token, False
    query_token = _query_session_token()
    return query_token, bool(query_token)


def _clear_dashboard_session_ui_state() -> None:
    """Clear browser-only access state without changing authentication rules."""
    st.session_state.pop("dashboard_session_token", None)
    st.session_state.pop("dashboard_session_expires_at", None)
    st.session_state.pop("dashboard_principal", None)
    st.session_state.pop(_SESSION_EXIT_STATE_KEY, None)
    _set_query_session_token(None)


def _store_dashboard_principal(status: dict) -> None:
    """Keep only the non-secret authorization context needed by the workspace."""
    role = dashboard_auth.normalize_role(status.get("role"))
    capabilities = [
        str(item)
        for item in status.get("capabilities", [])
        if isinstance(item, str)
    ]
    st.session_state["dashboard_principal"] = {
        "role": role,
        "capabilities": capabilities,
        "lock_enabled": bool(status.get("lock_enabled")),
    }


def _render_authenticated_session_control() -> None:
    """Render the session exit after the workspace has completed its sidebar."""
    if not bool(st.session_state.get(_SESSION_EXIT_STATE_KEY)):
        return
    token = str(st.session_state.get("dashboard_session_token") or "").strip()
    if not token:
        return
    with st.sidebar:
        principal = st.session_state.get("dashboard_principal") or {}
        role_label = {
            dashboard_auth.ROLE_ADMIN: "Administrator",
            dashboard_auth.ROLE_ANALYST: "Analyst",
            dashboard_auth.ROLE_DEMO_READONLY: "Read-only demo",
        }.get(principal.get("role"), "Restricted")
        st.caption(f"Access: {role_label}")
        if st.button(
            "End secure session",
            key="end-secure-session",
            use_container_width=True,
        ):
            dashboard_auth.revoke_dashboard_session(token)
            _clear_dashboard_session_ui_state()
            st.rerun()


def _render_unlock() -> None:
    access_status = dashboard_auth.dashboard_access_status()
    code_available = bool(access_status.get("active_code"))
    storage_error = str(access_status.get("storage_error") or "").strip()
    state_label = "Code available" if code_available else "No active code"
    state_class = "rt-lock-state-on" if code_available else "rt-lock-state-off"
    form_state_class = "rt-code-ready" if code_available else "rt-code-waiting"
    helper_text = (
        "Access storage is temporarily unavailable. Check the server database/disk, then refresh."
        if storage_error
        else
        "Enter the temporary code to continue."
        if code_available
        else "Access is currently unavailable. Activate a temporary code, then refresh this page."
    )
    st.markdown(
        f"""
        <style>
        .rt-lock-shell{{display:flex;align-items:center;justify-content:center;padding:12vh 1rem .75rem}}
        .rt-lock-wrap{{width:min(430px,100%);border:1px solid #d8dee5;border-radius:10px;
        background:#ffffff;box-shadow:0 10px 28px rgba(31,41,55,.08);overflow:hidden}}
        .rt-lock-head{{padding:1rem 1.15rem;border-bottom:1px solid #e5e9ef;
        display:flex;align-items:center;justify-content:space-between;gap:1rem;background:#fafbfc}}
        .rt-lock-brand{{font-size:.78rem;letter-spacing:.03em;font-weight:650;color:#303846}}
        .rt-lock-state{{font-size:.68rem;color:#697586;border:1px solid #d9e0e8;border-radius:999px;
        padding:.28rem .55rem;background:#fff;white-space:nowrap}}
        .rt-lock-state-on{{color:#256047;border-color:#c9dfd4;background:#f5fbf7}}
        .rt-lock-state-off{{color:#697586;border-color:#d9e0e8;background:#f6f7f9}}
        .rt-lock-body{{padding:1.25rem 1.15rem 1.35rem}}
        .rt-lock-body h1{{font-size:1.08rem;line-height:1.25;margin:0 0 .4rem;color:#1f2937;font-weight:650}}
        .rt-lock-muted{{color:#697586;margin:0;font-size:.84rem;line-height:1.5}}
        .rt-lock-note{{margin-top:.85rem;border:1px solid #e3e8ef;background:#f8fafc;border-radius:8px;
        padding:.68rem .75rem;color:#667085;font-size:.76rem;line-height:1.45}}
        .rt-lock-unavailable{{opacity:.72}}
        [data-testid="stForm"]{{width:min(430px,calc(100% - 2rem));margin:.85rem auto 0;
          border:1px solid #d8dee5;border-radius:10px;background:#ffffff;
          box-shadow:0 10px 28px rgba(31,41,55,.06);padding:1rem 1rem .95rem}}
        [data-testid="stForm"] label p{{font-size:.76rem;color:#667085;font-weight:650}}
        [data-testid="stForm"] input:not(:disabled){{
          background:#ffffff!important;color:#111827!important;opacity:1!important;filter:none!important;
          -webkit-text-fill-color:#111827!important;cursor:text!important;border-color:#2563eb!important;
          box-shadow:0 0 0 3px rgba(37,99,235,.14)!important;
        }}
        [data-testid="stForm"] input:disabled{{
          background:#eef3f7!important;color:#98a2b3!important;opacity:.72!important;filter:grayscale(.35)!important;
          -webkit-text-fill-color:#98a2b3!important;cursor:not-allowed!important;
        }}
        .rt-code-ready-note{{width:min(430px,calc(100% - 2rem));margin:.7rem auto 0;
          color:#14532d;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;
          padding:.62rem .75rem;font-size:.8rem;line-height:1.35}}
        .rt-code-waiting-note{{width:min(430px,calc(100% - 2rem));margin:.7rem auto 0;
          color:#475467;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
          padding:.62rem .75rem;font-size:.8rem;line-height:1.35}}
        [data-testid="stToolbar"], .stDeployButton{{display:none!important}}
        </style>
        <div class="rt-lock-shell">
        <div class="rt-lock-wrap">
        <div class="rt-lock-head">
          <div class="rt-lock-brand">Workspace access</div>
          <div class="rt-lock-state {state_class}">{html.escape(state_label)}</div>
        </div>
        <div class="rt-lock-body">
        <h1>Sign in</h1>
        <div class="rt-lock-muted">{html.escape(helper_text)}</div>
        <div class="rt-lock-note">Codes are single-use and expire automatically.</div>
        </div>
        </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if storage_error:
        st.error("Access-code storage is unavailable. Check runtime folder permissions, then refresh.")
    st.markdown(
        f"""<div class="{form_state_class}-note">
        {html.escape('Code is active. The field is unlocked and ready.' if code_available else 'Waiting for an active code. Generate one, then press Check again or refresh.')}
        </div>""",
        unsafe_allow_html=True,
    )
    with st.form("dashboard_unlock_form"):
        code = st.text_input(
            "Verification code",
            type="password",
            placeholder="XXXX-XXXX" if code_available else "No active code",
            disabled=not code_available,
        )
        submitted = st.form_submit_button(
            "Continue",
            use_container_width=True,
            disabled=not code_available,
        )
    if not code_available and st.button("Check again", use_container_width=True):
        st.rerun()
    if submitted:
        user_agent = ip_hint = ""
        try:
            user_agent = str(st.context.headers.get("User-Agent", ""))
            ip_hint = str(st.context.ip_address or "")
        except (AttributeError, RuntimeError, TypeError):
            # AppTest and older Streamlit builds may not expose request context.
            pass
        result = dashboard_auth.consume_dashboard_code(
            code, user_agent=user_agent, ip_hint=ip_hint,
        )
        if result.get("ok"):
            st.session_state["dashboard_session_token"] = result["session_token"]
            st.session_state["dashboard_session_expires_at"] = result["expires_at"]
            _store_dashboard_principal(result)
            _set_query_session_token(result["session_token"])
            st.rerun()
        st.error(result.get("error") or "Invalid, expired, or already-used access code.")


def _dashboard_access_allowed() -> bool:
    token, restored_from_query = _current_session_token()
    status = dashboard_auth.validate_dashboard_session(token)
    if status.get("ok"):
        _store_dashboard_principal(status)
        if not status.get("lock_enabled"):
            # An open development workspace does not need a stale bearer in its
            # URL or session state.
            _clear_dashboard_session_ui_state()
            _store_dashboard_principal(status)
            return True
        if restored_from_query:
            rotated = dashboard_auth.rotate_dashboard_session(token)
            if not rotated.get("ok"):
                _clear_dashboard_session_ui_state()
                _render_unlock()
                return False
            token = rotated["session_token"]
            status = dashboard_auth.validate_dashboard_session(token)
            if not status.get("ok"):
                _clear_dashboard_session_ui_state()
                _render_unlock()
                return False
            _store_dashboard_principal(status)
            st.session_state["dashboard_session_token"] = token
            st.session_state["dashboard_session_expires_at"] = rotated["expires_at"]
            _set_query_session_token(token)
        if status.get("lock_enabled"):
            st.session_state[_SESSION_EXIT_STATE_KEY] = True
            remaining = _format_remaining(int(status.get("remaining_seconds") or 0))
            st.markdown(
                f"""<div class="rt-session-timer" role="status"
                aria-label="Session expires in {html.escape(remaining)}">
                <span>Session expires in</span><strong>{html.escape(remaining)}</strong></div>""",
                unsafe_allow_html=True,
            )
        return True
    _clear_dashboard_session_ui_state()
    _render_unlock()
    return False


def main() -> None:
    """Render the dashboard through the page-oriented workspace package."""
    st.set_page_config(page_title="Arachne Console", page_icon="A", layout="wide",
                       initial_sidebar_state="expanded")
    if not _dashboard_access_allowed():
        st.stop()
    _render_workspace()
    _render_authenticated_session_control()


if __name__ == "__main__":
    main()
