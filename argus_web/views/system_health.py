"""System Health — detailed real-time infrastructure status across the ARGUS stack."""
import sys
import subprocess
from pathlib import Path
from datetime import datetime

import requests
import streamlit as st

_ANALYZER = Path(__file__).parent.parent.parent / "analyzer"
sys.path.insert(0, str(_ANALYZER))

from utils.system import check_all_systems
from config import load_argus_config


def render():
    st.markdown(
        '<div class="section-heading">'
        '<i class="bi bi-activity"></i>'
        '&nbsp;System Health'
        '</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Detailed real-time infrastructure status — SSH tunnel, Elasticsearch cluster, "
        "Ollama LLM runtime, T-Pot honeypot, and AWS infrastructure."
    )

    # -------- Refresh controls --------
    c_refresh, c_time = st.columns([1, 3])
    with c_refresh:
        if st.button("↻ Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
    with c_time:
        st.caption(f"Last checked · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # -------- Overall Status --------
    st.markdown("### Overall Status")
    status = check_all_systems()
    _render_status_grid(status)

    st.markdown("---")

    # -------- Elasticsearch --------
    st.markdown("### Elasticsearch Cluster")
    _render_es_details(status["es"])

    st.markdown("---")

    # -------- Ollama LLM --------
    st.markdown("### Ollama LLM Runtime")
    config = load_argus_config()
    _render_ollama_details(config["ollama"])

    st.markdown("---")

    # -------- SSH Tunnel --------
    st.markdown("### SSH Tunnel")
    _render_tunnel_details(status["tunnel"])

    st.markdown("---")

    # -------- AWS Infrastructure --------
    st.markdown("### AWS Infrastructure")
    _render_aws_infra(config.get("tpot", {}))


def _render_status_grid(status: dict) -> None:
    systems = [
        ("SSH Tunnel",    "bi-diagram-2",       status["tunnel"], "Port 9200 forwarded to T-Pot ES"),
        ("Elasticsearch", "bi-database-check",  status["es"],     "T-Pot cluster reachable via tunnel"),
        ("Ollama LLM",    "bi-cpu",             status["ollama"], "Local model responding"),
        ("T-Pot",         "bi-shield-check",    status["tpot"],   "Honeypot service operational"),
    ]
    cards_html = '<div class="status-row">'
    for label, icon, up, desc in systems:
        dot_class = "up" if up else "down"
        state_text = "Operational" if up else "Unreachable"
        cards_html += (
            f'<div class="status-card" style="min-width: 250px;">'
            f'<span class="dot {dot_class}"></span>'
            f'<div style="flex: 1;">'
            f'<p class="label"><i class="bi {icon}"></i>&nbsp;{label}</p>'
            f'<p class="value">{state_text}</p>'
            f'<p style="color: var(--text-dim); font-size: 0.72rem; margin: 0.25rem 0 0 0; font-family: \'Space Grotesk\', sans-serif;">{desc}</p>'
            f'</div>'
            f'</div>'
        )
    cards_html += '</div>'
    st.markdown(cards_html, unsafe_allow_html=True)


def _render_es_details(es_up: bool) -> None:
    if not es_up:
        st.error("Elasticsearch unreachable. Cannot fetch cluster details.")
        return
    try:
        cluster_info = requests.get("http://localhost:9200/", timeout=5).json()
        health = requests.get("http://localhost:9200/_cluster/health", timeout=5).json()
        indices_raw = requests.get(
            "http://localhost:9200/_cat/indices/logstash-*?format=json&h=index,docs.count,store.size",
            timeout=5,
        ).json()
    except Exception as e:
        st.error(f"Failed to fetch ES details: {e}")
        return

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Cluster Status", health.get("status", "?").upper())
    m2.metric("Nodes", health.get("number_of_nodes", 0))
    m3.metric("Active Shards", health.get("active_shards", 0))
    m4.metric("Logstash Indices", len(indices_raw))

    if indices_raw:
        st.markdown("**Attack Data Indices**")
        sorted_indices = sorted(indices_raw, key=lambda x: x.get("index", ""), reverse=True)
        for idx in sorted_indices[:7]:
            docs = int(idx.get("docs.count", 0) or 0)
            size = idx.get("store.size", "-")
            st.markdown(
                f'<div style="background: var(--panel); padding: 0.6rem 1rem; border-radius: 6px; '
                f'border: 1px solid var(--grid); margin-bottom: 0.4rem; display: flex; '
                f'justify-content: space-between; align-items: center;">'
                f'<span style="font-family: JetBrains Mono, monospace; color: var(--text);">{idx.get("index", "?")}</span>'
                f'<span style="color: var(--text-dim); font-size: 0.85rem;">{docs:,} docs · {size}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        total_docs = sum(int(i.get("docs.count", 0) or 0) for i in indices_raw)
        st.caption(
            f"Total documents across all logstash-* indices: **{total_docs:,}** · "
            f"Cluster: `{cluster_info.get('cluster_name', '?')}` · "
            f"ES version: {cluster_info.get('version', {}).get('number', '?')}"
        )


def _render_ollama_details(ollama_cfg: dict) -> None:
    try:
        base_url = ollama_cfg["base_url"]
        r = requests.get(f"{base_url}/api/tags", timeout=5).json()
        models = r.get("models", [])
    except Exception as e:
        st.error(f"Failed to reach Ollama at {ollama_cfg.get('base_url', '?')}: {e}")
        return

    m1, m2, m3 = st.columns(3)
    m1.metric("Endpoint", base_url)
    m2.metric("Models Available", len(models))
    m3.metric("Active Model", ollama_cfg.get("model", "?"))

    if models:
        st.markdown("**Installed Models**")
        for m in models:
            name = m.get("name", "unknown")
            size_bytes = m.get("size", 0)
            size_gb = size_bytes / (1024 ** 3)
            params = m.get("details", {}).get("parameter_size", "?")
            fam = m.get("details", {}).get("family", "?")
            st.markdown(
                f'<div style="background: var(--panel); padding: 0.6rem 1rem; border-radius: 6px; '
                f'border: 1px solid var(--grid); margin-bottom: 0.4rem; display: flex; '
                f'justify-content: space-between; align-items: center;">'
                f'<span style="font-family: JetBrains Mono, monospace; color: var(--text);">{name}</span>'
                f'<span style="color: var(--text-dim); font-size: 0.85rem;">{fam} · {params} · {size_gb:.2f} GB</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
    st.caption(
        "Ollama runs locally on the operator's Windows host (WSL2 forwards `localhost:11434`). "
        "All LLM inference is local — no cloud services invoked, raw telemetry never leaves the workstation."
    )


def _render_tunnel_details(tunnel_up: bool) -> None:
    if not tunnel_up:
        st.error("SSH tunnel not running. Start with `./scripts/session-start.sh` from repo root.")
        return
    try:
        result = subprocess.run(
            ["lsof", "-ti", ":9200"], capture_output=True, text=True, timeout=2
        )
        pid = result.stdout.strip().split("\n")[0] if result.stdout.strip() else "unknown"
    except Exception:
        pid = "unknown"

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Local Port", "9200")
    m2.metric("Remote Port", "64298")
    m3.metric("Process PID", pid)
    m4.metric("Manager", "autossh")

    st.caption(
        "SSH-encrypted tunnel forwarding operator laptop `localhost:9200` → T-Pot host `localhost:64298` "
        "(internal Elasticsearch container port). Keepalive every 30s. Auto-reconnects on drops. "
        "No credentials — internal ES relies on Docker network isolation."
    )


def _render_aws_infra(tpot_cfg: dict) -> None:
    host = tpot_cfg.get("host", "?")
    ports = tpot_cfg.get("ports", {})

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Elastic IP", host)
    m2.metric("Instance Type", "t3.xlarge")
    m3.metric("Region", "ap-southeast-1")
    m4.metric("Storage", "128 GB gp3")

    st.markdown("**Exposed Management Ports**")
    port_rows_html = '<div class="status-row">'
    port_items = [
        ("SSH Management", "bi-terminal", ports.get("ssh", 64295), "Admin shell (SSH key + admin IP)"),
        ("Kibana / Portal", "bi-graph-up", ports.get("kibana", 64297), "T-Pot web UI + all analytics tools"),
        ("Cockpit / LS-Web", "bi-diagram-3", ports.get("cockpit", 64294), "Logstash sensor ingest endpoint"),
        ("Elasticsearch", "bi-database", 64298, "Internal ES (localhost only, via SSH tunnel)"),
    ]
    for label, icon, port, desc in port_items:
        port_rows_html += (
            f'<div class="status-card" style="min-width: 240px;">'
            f'<i class="bi {icon}" style="color: var(--secondary); font-size: 1.2rem;"></i>'
            f'<div style="flex: 1;">'
            f'<p class="label">{label}</p>'
            f'<p class="value">Port {port}</p>'
            f'<p style="color: var(--text-dim); font-size: 0.72rem; margin: 0.2rem 0 0 0;">{desc}</p>'
            f'</div>'
            f'</div>'
        )
    port_rows_html += '</div>'
    st.markdown(port_rows_html, unsafe_allow_html=True)

    st.caption(
        "Managed via Infrastructure-as-Code (Terraform + Ansible). "
        "Instance stopped-and-started or resized without losing data (EBS volume persists, Elastic IP stays). "
    )