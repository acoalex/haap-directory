# -*- coding: utf-8 -*-
"""Plain-text metrics rendering (SPEC §9.2).

A minimal Prometheus-style exposition — no client library, no dependency. The
operator can scrape it or a sidecar can translate it.
"""

from __future__ import annotations


def render_metrics(service, uptime_s: float, ops_total: int, rejections: dict) -> str:
    head = service.store.audit_head()
    lines = [
        "# HELP haapd_agents_listed Currently listed agents.",
        "# TYPE haapd_agents_listed gauge",
        f"haapd_agents_listed {service.store.count_live()}",
        "# HELP haapd_agents_suspended Suspended agents.",
        "# TYPE haapd_agents_suspended gauge",
        f"haapd_agents_suspended {service.store.count_suspended()}",
        "# HELP haapd_agents_total Agent rows including history.",
        "# TYPE haapd_agents_total gauge",
        f"haapd_agents_total {service.store.count_total_agents()}",
        "# HELP haapd_audit_seq Current audit-chain head sequence.",
        "# TYPE haapd_audit_seq counter",
        f"haapd_audit_seq {head['seq']}",
        "# HELP haapd_ops_total Total HTTP requests handled.",
        "# TYPE haapd_ops_total counter",
        f"haapd_ops_total {ops_total}",
        "# HELP haapd_uptime_seconds Process uptime.",
        "# TYPE haapd_uptime_seconds gauge",
        f"haapd_uptime_seconds {round(uptime_s, 1)}",
        "# HELP haapd_rejections_total Rejections by stable error code.",
        "# TYPE haapd_rejections_total counter",
    ]
    for code, count in sorted(rejections.items()):
        lines.append(f'haapd_rejections_total{{code="{code}"}} {count}')
    return "\n".join(lines) + "\n"
