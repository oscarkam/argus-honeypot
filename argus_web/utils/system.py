"""System health checks — tunnel, ES, Ollama."""
import subprocess
from pathlib import Path
import requests
import yaml
import streamlit as st


def check_tunnel() -> bool:
    try:
        r = subprocess.run(["lsof", "-ti", ":9200"],
                           capture_output=True, text=True, timeout=2)
        return bool(r.stdout.strip())
    except Exception:
        return False


def check_es() -> bool:
    try:
        r = requests.get("http://localhost:9200/_cluster/health", timeout=3)
        return r.status_code == 200 and r.json().get("status") in ("green", "yellow")
    except Exception:
        return False


def check_ollama() -> bool:
    try:
        cfg_path = Path(__file__).parent.parent.parent / "analyzer" / "config.yml"
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        url = cfg["ollama"]["base_url"] + "/api/tags"
        r = requests.get(url, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


@st.cache_data(ttl=15, show_spinner=False)
def check_all_systems() -> dict:
    tunnel = check_tunnel()
    es = check_es() if tunnel else False
    ollama = check_ollama()
    return {"tunnel": tunnel, "es": es, "ollama": ollama, "tpot": es}