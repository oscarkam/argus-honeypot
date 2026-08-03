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

# Reliability metrics (from metrics.py) and external validation summary
# (from validate_ips.py). Imported here so failure to import either module
# does not break the whole page; both loaders fall back to run_count=0 or None.
try:
    from metrics import load_summary as load_metrics_summary
except Exception:
    load_metrics_summary = lambda **kwargs: {"run_count": 0}

try:
    from validate_ips import load_summary as load_validation_summary
except Exception:
    load_validation_summary = lambda: None


def _load_proposal_metrics_snapshot():
    """Load analyzer/proposal_metrics.json (written by analyzer.py on each run).

    Returns dict on success, None if the file does not exist. All values in
    the returned dict are exact integers or rounded percentages, matching
    the numbers-first design principle.
    """
    import json as _json
    snapshot_path = _ANALYZER / "proposal_metrics.json"
    if not snapshot_path.exists():
        return None
    try:
        return _json.loads(snapshot_path.read_text())
    except Exception:
        return None


def _load_manual_verification_results():
    """Load analyzer/verification_results.json (populated on Jul 21 manual verification day).

    Returns dict on success, None if the file does not exist.
    """
    import json as _json
    verification_path = _ANALYZER / "verification_results.json"
    if not verification_path.exists():
        return None
    try:
        return _json.loads(verification_path.read_text())
    except Exception:
        return None


def render():
    st.markdown(
        '<div class="page-header">'
        '<div class="page-header-titlerow">'
        '<span class="page-header-icon"><i class="bi bi-activity"></i></span>'
        '<h1 class="page-header-title">System Health</h1>'
        '</div>'
        '<p class="page-header-desc">'
        'Detailed real-time infrastructure status — SSH tunnel, Elasticsearch cluster, '
        'Ollama LLM runtime, T-Pot honeypot, and AWS infrastructure.'
        '</p>'
        '</div>',
        unsafe_allow_html=True,
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

    st.markdown("---")

    # -------- Proposal Evaluation Metrics --------
    st.markdown("### Proposal Evaluation Metrics")
    st.caption(
        "The three evaluation metrics committed in the Capstone 1 proposal, "
        "computed from the most recent analyser run. "
        "Source: analyzer/proposal_metrics.json."
    )
    _render_proposal_metrics()

    st.markdown("---")

    # -------- Framework Mapping Coverage --------
    st.markdown("### Framework Mapping Coverage")
    st.caption(
        "Breadth of MITRE ATT&CK, Cyber Kill Chain, and NIST CSF classification "
        "produced by the analyser. Source: analyzer/proposal_metrics.json."
    )
    _render_framework_coverage()

    st.markdown("---")

    # -------- Manual Verification Results --------
    st.markdown("### Manual Verification Results")
    st.caption(
        "Manual labelling of a random sample to verify framework mapping "
        "and LLM narrative accuracy. Scheduled Jul 21. "
        "Source: analyzer/verification_results.json."
    )
    _render_manual_verification()

    st.markdown("---")

    # -------- Report Generation Reliability --------
    st.markdown("### Report Generation Reliability")
    st.caption(
        "Recorded automatically by the analyser on every run. "
        "Source: analyzer/metrics.csv."
    )
    _render_reliability_metrics()

    st.markdown("---")

    # -------- External Threat Intelligence Validation --------
    st.markdown("### External Threat Intelligence Validation")
    st.caption(
        "Cross-reference of top attacker IPs against AbuseIPDB, VirusTotal, "
        "and GreyNoise Community feeds. Source: analyzer/validation_ips.csv."
    )
    _render_validation_metrics()


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


def _render_reliability_metrics() -> None:
    """Render four large-number cards from analyzer/metrics.csv."""
    summary = load_metrics_summary()

    if not summary or summary.get("run_count", 0) == 0:
        st.info(
            "No runs recorded yet. Generate a report from Report Studio "
            "to populate `analyzer/metrics.csv`."
        )
        return

    run_count = summary["run_count"]
    success_count = summary["success_count"]
    success_rate = summary["success_rate_percent"]
    mean_s = summary["total_seconds_mean"]
    min_s = summary["total_seconds_min"]
    max_s = summary["total_seconds_max"]
    p95_s = summary["total_seconds_p95"]
    pdf_ok = summary["pdf_success_count"]
    docx_ok = summary["docx_success_count"]

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Runs Recorded", f"{run_count}")
    m2.metric("Success Rate", f"{success_rate}%",
              help=f"{success_count} of {run_count} runs completed successfully")
    m3.metric("Mean Total Time", f"{mean_s}s",
              help=f"min {min_s}s, max {max_s}s, P95 {p95_s}s")
    m4.metric("PDF / DOCX Success", f"{pdf_ok} / {docx_ok}",
              help=f"PDF succeeded {pdf_ok} of {run_count} times, DOCX {docx_ok} of {run_count}")

    st.caption(f"Latest run at: {summary.get('latest_timestamp', 'unknown')}")


def _render_validation_metrics() -> None:
    """Render six large-number cards from analyzer/validation_ips.csv.

    Uses three-band AbuseIPDB reporting (high / medium / low) plus VirusTotal
    and GreyNoise counts. Every value is an exact integer, no ranges.
    """
    summary = load_validation_summary()

    if not summary:
        st.info(
            "External validation not yet performed. Run "
            "`python3 validate_ips.py --live` from the analyzer directory "
            "to populate `analyzer/validation_ips.csv`."
        )
        return

    total = summary["total_ips"]
    ab_high = summary.get("abuseipdb_high", 0)
    ab_high_thr = summary.get("abuseipdb_high_threshold", 80)
    ab_medium = summary.get("abuseipdb_medium", 0)
    ab_medium_thr = summary.get("abuseipdb_medium_threshold", 50)
    ab_low = summary.get("abuseipdb_low", 0)
    vt_flagged = summary["virustotal_flagged"]
    vt_threshold = summary["virustotal_threshold"]
    gn_flagged = summary["greynoise_flagged"]

    # Row 1: IPs validated + AbuseIPDB three-band
    r1_1, r1_2, r1_3, r1_4 = st.columns(4)
    r1_1.metric("IPs Validated", f"{total}",
                help="Top attacker source IPs from the most recent validation run")
    r1_2.metric(f"AbuseIPDB High (>= {ab_high_thr})", f"{ab_high} / {total}",
                help=f"AbuseIPDB confidence score at or above {ab_high_thr}")
    r1_3.metric(f"AbuseIPDB Medium ({ab_medium_thr}-{ab_high_thr - 1})", f"{ab_medium} / {total}",
                help=f"AbuseIPDB confidence between {ab_medium_thr} and {ab_high_thr - 1}")
    r1_4.metric(f"AbuseIPDB Low (< {ab_medium_thr})", f"{ab_low} / {total}",
                help=f"AbuseIPDB confidence below {ab_medium_thr}")

    # Row 2: VirusTotal + GreyNoise
    r2_1, r2_2 = st.columns(2)
    r2_1.metric("VirusTotal Flagged", f"{vt_flagged} / {total}",
                help=f"At least {vt_threshold} vendor detection classifying as malicious")
    r2_2.metric("GreyNoise Flagged", f"{gn_flagged} / {total}",
                help="Classified as malicious or malicious scanner")

    st.caption(f"Last validation run at: {summary.get('timestamp', 'unknown')}")


def _render_proposal_metrics() -> None:
    """Render four large-number cards from analyzer/proposal_metrics.json.

    Covers the three proposal-committed evaluation metrics plus a total.
    """
    snap = _load_proposal_metrics_snapshot()

    if not snap:
        st.info(
            "No proposal metrics snapshot yet. Run any report from Report Studio "
            "to populate `analyzer/proposal_metrics.json`."
        )
        return

    total_attacks = snap.get("total_attacks", 0)
    engagement = snap.get("engagement_rate_percent", 0.0)
    sessions_with_commands = snap.get("sessions_with_commands", 0)
    top_cred_pair = snap.get("top_credential_pair", "-")
    top_cred_count = snap.get("top_credential_count", 0)
    top_cred_ratio = snap.get("top_credential_ratio_percent", 0.0)
    completeness = snap.get("completeness_ratio_percent", 0.0)
    complete_sessions = snap.get("complete_sessions", 0)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Attack Sessions", f"{total_attacks:,}",
              help=f"Sessions in the {snap.get('window_hours', '?')}h reporting window")
    m2.metric("Sensor Engagement Rate", f"{engagement}%",
              help=f"{sessions_with_commands} of {total_attacks} sessions executed one or more commands")
    m3.metric("Session Completeness Ratio", f"{completeness}%",
              help=f"{complete_sessions} of {total_attacks} sessions contain post-connection activity")
    m4.metric("Top Credential Frequency", f"{top_cred_ratio}%",
              help=f"'{top_cred_pair}' attempted {top_cred_count} times")

    st.caption(
        f"Snapshot taken at: {snap.get('timestamp', 'unknown')} "
        f"| Reporting period: {snap.get('reporting_period', '?')} "
        f"({snap.get('window_hours', '?')}h)"
    )


def _render_framework_coverage() -> None:
    """Render four large-number cards showing framework classification breadth."""
    snap = _load_proposal_metrics_snapshot()

    if not snap:
        st.info(
            "No framework snapshot yet. Run any report from Report Studio to populate the snapshot."
        )
        return

    mitre_techniques = snap.get("mitre_techniques_observed", 0)
    mitre_tactics = snap.get("mitre_tactics_observed", 0)
    mitre_tactics_total = snap.get("mitre_tactics_total", 14)
    kill_chain_reached = snap.get("kill_chain_stages_reached", 0)
    kill_chain_total = snap.get("kill_chain_stages_total", 7)
    top_tactic = snap.get("top_tactic_name", "-")
    top_tactic_count = snap.get("top_tactic_count", 0)
    csf_covered = snap.get("nist_csf_functions_covered", 0)
    csf_total = snap.get("nist_csf_functions_total", 5)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("MITRE Techniques Observed", f"{mitre_techniques}",
              help="Distinct ATT&CK technique IDs mapped from captured commands")
    m2.metric("MITRE Tactics Reached", f"{mitre_tactics} / {mitre_tactics_total}",
              help=f"Distinct tactics reached out of {mitre_tactics_total} in ATT&CK Enterprise")
    m3.metric("Kill Chain Stages Reached", f"{kill_chain_reached} / {kill_chain_total}",
              help=f"Distinct Kill Chain stages observed out of {kill_chain_total}")
    m4.metric("NIST CSF Functions Covered", f"{csf_covered} / {csf_total}",
              help=f"Core Functions with at least one recommendation")

    if top_tactic:
        st.caption(f"Most-observed tactic: **{top_tactic}** ({top_tactic_count} observations)")


def _render_manual_verification() -> None:
    """Render four large-number cards from analyzer/verification_results.json."""
    verif = _load_manual_verification_results()

    if not verif:
        st.info(
            "Manual verification scheduled for **Jul 21**. Sample sizes locked: "
            "**50** MITRE mappings, **30** Kill Chain classifications, "
            "**10** LLM narrative runs. Results will appear here once "
            "`analyzer/verification_results.json` is populated."
        )
        return

    mitre_correct = verif.get("mitre_correct", 0)
    mitre_total = verif.get("mitre_sample_size", 50)
    kc_correct = verif.get("kill_chain_correct", 0)
    kc_total = verif.get("kill_chain_sample_size", 30)
    llm_numeric = verif.get("llm_numeric_accuracy_percent", 0.0)
    llm_runs = verif.get("llm_runs_checked", 10)
    hallucinations = verif.get("llm_hallucinations", 0)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("MITRE Accuracy", f"{mitre_correct} / {mitre_total}",
              help=f"Correct technique assignments in a random sample of {mitre_total}")
    m2.metric("Kill Chain Accuracy", f"{kc_correct} / {kc_total}",
              help=f"Correct stage assignments in a random sample of {kc_total}")
    m3.metric("LLM Numeric Accuracy", f"{llm_numeric}%",
              help=f"Percent of quoted numbers verified against underlying stats across {llm_runs} runs")
    m4.metric("LLM Hallucinations", f"{hallucinations}",
              help=f"Unsupported claims found across {llm_runs} runs")

    st.caption(f"Verification performed at: {verif.get('timestamp', 'unknown')}")