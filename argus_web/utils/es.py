"""Elasticsearch client wrapper — reuses analyzer's TpotEsClient."""
import sys
from pathlib import Path

_ANALYZER = Path(__file__).parent.parent.parent / "analyzer"
sys.path.insert(0, str(_ANALYZER))

from es_client import TpotEsClient   # noqa: E402
import yaml   # noqa: E402
import streamlit as st   # noqa: E402


@st.cache_resource
def get_client() -> TpotEsClient:
    """Cached ES client (persists across reruns)."""
    with open(_ANALYZER / "config.yml") as f:
        config = yaml.safe_load(f)
    es_cfg = config["elasticsearch"]
    return TpotEsClient(
        hosts=es_cfg["hosts"],
        username=es_cfg.get("username", ""),
        password=es_cfg.get("password", ""),
        verify_certs=False,
        timeout=30,
    )


@st.cache_data(ttl=60, show_spinner=False)
def get_live_metrics(hours: int = 24) -> dict:
    """Lightweight home-page metrics (cached 60s)."""
    client = get_client()
    tf = {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
    total = client._total_attacks(tf)
    unique_ips = client._unique_source_ips(tf)
    countries = client._top_countries(tf, total)
    malware = client._malware_count(tf)
    return {
        "total_attacks": total,
        "unique_ips": unique_ips,
        "countries": len(countries),
        "malware": malware,
    }

@st.cache_data(ttl=60, show_spinner=False)
def get_full_data(hours: int = 24) -> dict:
    """Full pipeline query data — used by Report Studio (cached 60s)."""
    client = get_client()
    return client.query_window(hours=hours)