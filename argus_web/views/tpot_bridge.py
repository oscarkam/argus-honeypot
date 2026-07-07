"""T-Pot Bridge — link cards to live T-Pot dashboards + connection info."""
import streamlit as st
from config import load_argus_config


def render():
    st.markdown(
        '<div class="page-header">'
        '<div class="page-header-titlerow">'
        '<span class="page-header-icon"><i class="bi bi-broadcast-pin"></i></span>'
        '<h1 class="page-header-title">T-Pot Bridge</h1>'
        '</div>'
        '<p class="page-header-desc">'
        'Direct links to live T-Pot infrastructure — Kibana, Attack Map, '
        'Elasticvue, and CyberChef. All links open in a new tab. '
        'T-Pot uses self-signed HTTPS certificates — accept the browser warning '
        'on first visit per site.'
        '</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    config = load_argus_config()
    tpot_cfg = config.get("tpot", {})
    host = tpot_cfg.get("host", "3.1.46.106")
    ports = tpot_cfg.get("ports", {})
    kibana_port = ports.get("kibana", 64297)
    ssh_port = ports.get("ssh", 64295)

    st.info(
        "**Login credentials**: use the T-Pot web user and password you set during install "
        "(stored in `infra/ansible/vars/tpot_secrets.yml`, gitignored)."
    )

    # -------- Live dashboards grid --------
    st.markdown("### Live Dashboards")

    c1, c2 = st.columns(2)
    with c1:
        _bridge_card(
            icon="bi-grid-3x3-gap-fill",
            title="T-Pot Portal",
            description=(
                "Central landing page with quick access to all T-Pot tools — "
                "Kibana, Attack Map, CyberChef, Elasticvue, and SpiderFoot."
            ),
            url=f"https://{host}:{kibana_port}/",
            action="Open Portal",
        )
    with c2:
        _bridge_card(
            icon="bi-graph-up-arrow",
            title="Kibana Analytics",
            description=(
                "Full Kibana interface — attack timelines, session forensics, "
                "credential analysis, and pre-built T-Pot dashboards."
            ),
            url=f"https://{host}:{kibana_port}/kibana/",
            action="Open Kibana",
        )

    c3, c4 = st.columns(2)
    with c3:
        _bridge_card(
            icon="bi-globe-central-south-asia",
            title="Attack Map",
            description=(
                "Real-time geographic visualization of inbound attacks. "
                "Live-updating world map with source country and target port."
            ),
            url=f"https://{host}:{kibana_port}/map/",
            action="Open Attack Map",
        )
    with c4:
        _bridge_card(
            icon="bi-database-fill-gear",
            title="Elasticvue Explorer",
            description=(
                "Direct Elasticsearch admin UI — browse raw attack indices, run "
                "ad-hoc queries, and inspect the telemetry ARGUS reads from."
            ),
            url=f"https://{host}:{kibana_port}/elasticvue/",
            action="Open Elasticvue",
        )

    c5, c6 = st.columns(2)
    with c5:
        _bridge_card(
            icon="bi-search",
            title="CyberChef",
            description=(
                "Web app for encoding, decoding, encryption, and data analysis. "
                "Useful for decoding captured payloads and shell commands."
            ),
            url=f"https://{host}:{kibana_port}/cyberchef/",
            action="Open CyberChef",
        )
    with c6:
        _bridge_card(
            icon="bi-github",
            title="Project Source",
            description=(
                "GitHub repository — Terraform, Ansible, ARGUS analyser, "
                "and this Control Center. Complete IaC + analytics stack."
            ),
            url="https://github.com/oscarkam/cp2-honeypot-iac",
            action="Open GitHub",
        )

    st.markdown("---")

    # -------- Connection info --------
    st.markdown("### Connection Details")

    info_html = (
        '<div class="status-row">'
        f'<div class="status-card"><i class="bi bi-hdd" style="color: var(--secondary); font-size: 1.2rem;"></i>'
        f'<div><p class="label">Public IP (EIP)</p><p class="value">{host}</p></div></div>'
        f'<div class="status-card"><i class="bi bi-terminal" style="color: var(--secondary); font-size: 1.2rem;"></i>'
        f'<div><p class="label">SSH Port</p><p class="value">{ssh_port}</p></div></div>'
        f'<div class="status-card"><i class="bi bi-bar-chart" style="color: var(--secondary); font-size: 1.2rem;"></i>'
        f'<div><p class="label">Kibana Port</p><p class="value">{kibana_port}</p></div></div>'
        f'<div class="status-card"><i class="bi bi-database" style="color: var(--secondary); font-size: 1.2rem;"></i>'
        f'<div><p class="label">Elasticvue</p><p class="value">{kibana_port}/elasticvue/</p></div></div>'
        '</div>'
    )
    st.markdown(info_html, unsafe_allow_html=True)

    st.markdown("---")

    # -------- SSH command helper --------
    st.markdown("### Admin Shell")
    st.caption("Copy-paste SSH command for management access:")
    st.code(
        f"ssh -i ~/.ssh/cp2_honeypot_ed25519 -p {ssh_port} ubuntu@{host}",
        language="bash",
    )


def _bridge_card(icon: str, title: str, description: str, url: str, action: str):
    st.markdown(
        f'<a href="{url}" target="_blank" class="bridge-card-link">'
        f'<div class="bridge-card">'
        f'<i class="bi {icon} card-icon"></i>'
        f'<h4>{title}</h4>'
        f'<p>{description}</p>'
        f'<span class="btn-hint">{action} →</span>'
        f'</div>'
        f'</a>',
        unsafe_allow_html=True,
    )