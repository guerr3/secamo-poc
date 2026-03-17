from __future__ import annotations

from shared.models import HiTLRequest


def _render_metadata_rows(metadata: dict) -> str:
    return "".join(
        f"<tr><td style='padding:6px 8px;border:1px solid #e5e7eb;'><b>{key}</b></td>"
        f"<td style='padding:6px 8px;border:1px solid #e5e7eb;'>{value}</td></tr>"
        for key, value in metadata.items()
    )


def _render_action_buttons(action_urls: dict[str, str]) -> str:
    return "".join(
        f"<a href='{url}' style='display:inline-block;margin:8px 8px 0 0;padding:10px 16px;"
        f"background:#0b5ed7;color:#ffffff;text-decoration:none;border-radius:6px;'>"
        f"{action.replace('_', ' ').title()}</a>"
        for action, url in action_urls.items()
    )


def _render_metadata_section(metadata_rows: str) -> str:
    if not metadata_rows:
        return ""
    return (
        "<h3 style='margin:16px 0 8px 0;font-family:Segoe UI,Arial,sans-serif;'>Context</h3>"
        "<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:14px;'>"
        f"{metadata_rows}</table>"
    )


def _render_approval_email(request: HiTLRequest, action_urls: dict[str, str]) -> str:
    metadata_rows = _render_metadata_rows(request.metadata)
    action_buttons = _render_action_buttons(action_urls)
    metadata_section = _render_metadata_section(metadata_rows)

    return (
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;color:#111827;'>"
        f"<h2 style='margin:0 0 12px 0;'>{request.title}</h2>"
        f"<p style='line-height:1.5;'>{request.description}</p>"
        f"{metadata_section}"
        "<h3 style='margin:18px 0 8px 0;'>Choose an action</h3>"
        f"<div>{action_buttons}</div>"
        "<p style='margin-top:14px;font-size:12px;color:#6b7280;'>"
        f"This link expires in {request.timeout_hours} hour(s) and can only be used once."
        "</p>"
        "</body></html>"
    )
