"""Home page — hero + live metrics + breathing status + action cards."""
import streamlit as st
from utils.es import get_live_metrics
from utils.system import check_all_systems


def _status_card(label: str, icon: str, up: bool) -> str:
    dot_class = "up" if up else "down"
    state_text = "Operational" if up else "Unreachable"
    return (
        f'<div class="status-card">'
        f'<span class="dot {dot_class}"></span>'
        f'<div>'
        f'<p class="label"><i class="bi {icon}"></i>&nbsp;{label}</p>'
        f'<p class="value">{state_text}</p>'
        f'</div>'
        f'</div>'
    )


def _action_card(icon: str, title: str, blurb: str) -> str:
    return (
        f'<div class="action-card">'
        f'<i class="bi {icon} card-icon"></i>'
        f'<h4>{title}</h4>'
        f'<p>{blurb}</p>'
        f'<span class="btn-hint">Use the sidebar →</span>'
        f'</div>'
    )


def render():
    # -------- Hero --------
    st.markdown(
        '<div class="hero">'
        '<h1>ARGUS</h1>'
        '<p class="tagline">Automated Low-Interaction Honeypot with Threat Intelligence Visualization</p>'
        '<p class="version">v0.1 · Control Center</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    # -------- Live metrics --------
    st.markdown(
        '<div class="section-heading">'
        '<i class="bi bi-activity"></i>'
        '&nbsp;Live Snapshot · Last 24 Hours'
        '<span class="live-indicator"><span class="live-dot"></span>Live</span>'
        '</div>',
        unsafe_allow_html=True,
    )
    try:
        with st.spinner("Querying live telemetry..."):
            m = get_live_metrics(hours=24)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Attack Sessions", f"{m['total_attacks']:,}")
        c2.metric("Unique Source IPs", f"{m['unique_ips']:,}")
        c3.metric("Countries Represented", f"{m['countries']}+")
        c4.metric("Malware Captured", m["malware"])
    except Exception as e:
        st.error(f"Could not fetch metrics — is the SSH tunnel up? ({e})")

    st.markdown("---")

    # -------- Breathing system health --------
    st.markdown(
        '<div class="section-heading"><i class="bi bi-heart-pulse"></i>&nbsp;System Health</div>',
        unsafe_allow_html=True,
    )
    status = check_all_systems()
    systems = [
        ("SSH Tunnel",    "bi-diagram-2",       status["tunnel"]),
        ("Elasticsearch", "bi-database-check",  status["es"]),
        ("Ollama LLM",    "bi-cpu",             status["ollama"]),
        ("T-Pot",         "bi-shield-check",    status["tpot"]),
    ]
    cards_html = '<div class="status-row">'
    for label, icon, up in systems:
        cards_html += _status_card(label, icon, up)
    cards_html += '</div>'
    st.markdown(cards_html, unsafe_allow_html=True)

    if not all(status.values()):
        st.warning(
            "One or more subsystems are unreachable. Report generation may fail. "
            "Run `./scripts/session-start.sh` from the repo root to restore."
        )

    st.markdown("---")

    # -------- Explore action cards --------
    st.markdown(
        '<div class="section-heading"><i class="bi bi-compass"></i>&nbsp;Explore</div>',
        unsafe_allow_html=True,
    )
    q1, q2, q3, q4 = st.columns(4)
    with q1:
        st.markdown(
            _action_card(
                "bi-file-earmark-text",
                "Report Studio",
                "Generate a fresh threat intelligence report from live honeypot data — Brief or Analyst detail.",
            ),
            unsafe_allow_html=True,
        )
    with q2:
        st.markdown(
            _action_card(
                "bi-archive-fill",
                "Reports Archive",
                "Browse and download previously generated reports in Markdown, PDF, or DOCX.",
            ),
            unsafe_allow_html=True,
        )
    with q3:
        st.markdown(
            _action_card(
                "bi-broadcast-pin",
                "T-Pot Bridge",
                "Direct links to live Kibana dashboards, geographic attack map, and system Cockpit.",
            ),
            unsafe_allow_html=True,
        )
    with q4:
        st.markdown(
            _action_card(
                "bi-activity",
                "System Health",
                "Infrastructure status: SSH tunnel, Elasticsearch cluster, Ollama LLM, and EC2 instance.",
            ),
            unsafe_allow_html=True,
        )

    # -------- Footer --------
    st.markdown("---")
    st.caption(
        "ARGUS v0.1 · Automated Threat Intelligence · "
        "Powered by T-Pot HIVE, Elasticsearch, Ollama LLM, "
        "and framework integration with MITRE ATT&CK, Cyber Kill Chain, and NIST CSF."
    )