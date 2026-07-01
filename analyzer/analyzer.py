"""
T-Pot LLM Analyser
------------------
Generates plain-English threat intelligence reports from T-Pot honeypot
data using a local LLM (Ollama + Llama 3.2).

Currently implemented:
  --test-ollama : smoke test the Ollama client end-to-end

Pending (unlocked once T-Pot is live and ES schema confirmed):
  --period daily|weekly|monthly : generate the actual reports
"""
import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

import requests
import yaml
from jinja2 import Environment, FileSystemLoader


# ---------------------------------------------------------------- config

def load_config(path: str) -> dict:
    """Load YAML config file into a dict."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------- Ollama

def call_ollama(prompt: str, model: str, base_url: str, timeout: int = 120) -> str:
    """Send a prompt to Ollama's /api/generate endpoint and return the response text.

    Ollama's REST API is at <base_url>/api/generate. We use non-streaming mode
    (stream=False) for simplicity — waits for full response before returning.
    """
    url = f"{base_url}/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": False}
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()["response"]


# ---------------------------------------------------------------- ES (stub)

def query_elasticsearch(config: dict, time_window_hours: int) -> dict:
    """Query T-Pot Elasticsearch for attack data.

    STUB: returns placeholder data. Real implementation blocked until T-Pot
    is live and we can inspect the actual ES index schema.
    """
    # TODO: implement real queries once T-Pot data is flowing
    return {
        "total_attacks": 0,
        "top_source_countries": [],
        "top_attacked_ports": [],
        "top_credentials_attempted": [],
        "notable_sessions": [],
        "window_hours": time_window_hours,
    }


# ---------------------------------------------------------------- report

def render_prompt(data: dict, template_dir: str, template_name: str) -> str:
    """Render a Jinja2 prompt template with query data."""
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_name)
    return template.render(data=data)


def write_report(content: str, output_dir: str, period: str) -> str:
    """Write the generated report to disk with a timestamped filename."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    filename = f"report_{period}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    filepath = output_path / filename
    with open(filepath, "w") as f:
        f.write(content)
    return str(filepath)


# ---------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(description="T-Pot LLM Threat Analyser")
    parser.add_argument("--config", default="config.yml", help="Path to config file")
    parser.add_argument("--period", choices=["daily", "weekly", "monthly"], default="daily")
    parser.add_argument("--test-ollama", action="store_true",
                        help="Smoke test Ollama connectivity end-to-end")
    args = parser.parse_args()

    # Minimal-config fallback for --test-ollama when config.yml is unpopulated
    if args.test_ollama and not os.path.exists(args.config):
        config = {
            "ollama": {"base_url": "http://localhost:11434",
                       "model": "llama3.2:3b", "timeout": 120}
        }
    else:
        config = load_config(args.config)

    if args.test_ollama:
        prompt = ("In one sentence, explain what a low-interaction honeypot is "
                  "in cybersecurity.")
        print(f"→ Testing Ollama at {config['ollama']['base_url']} "
              f"with model '{config['ollama']['model']}'...")
        response = call_ollama(
            prompt=prompt,
            model=config["ollama"]["model"],
            base_url=config["ollama"]["base_url"],
            timeout=config["ollama"].get("timeout", 120),
        )
        print(f"\nOllama response:\n{response}\n")
        return 0

    # Full report generation flow
    hours_map = {"daily": 24, "weekly": 168, "monthly": 720}
    hours = hours_map[args.period]
    print(f"→ Generating {args.period} report from last {hours}h of data...")

    data = query_elasticsearch(config, hours)
    print(f"  ES query returned: {data['total_attacks']} attacks in window")

    prompt = render_prompt(data, "prompts", f"{args.period}_summary.j2")
    print(f"  Sending {len(prompt)} chars to Ollama for narrative generation...")

    narrative = call_ollama(
        prompt=prompt,
        model=config["ollama"]["model"],
        base_url=config["ollama"]["base_url"],
        timeout=config["ollama"].get("timeout", 120),
    )

    report_body = f"# T-Pot {args.period.title()} Threat Report\n\n"
    report_body += f"*Generated: {datetime.now().isoformat()}*\n\n"
    report_body += f"## Narrative Summary\n\n{narrative}\n\n"
    report_body += f"## Raw Data\n\n```yaml\n{yaml.dump(data)}```\n"

    output_path = write_report(
        report_body,
        config["report"]["output_dir"],
        args.period,
    )
    print(f"✓ Report written to: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())