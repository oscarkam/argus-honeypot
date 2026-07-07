"""Load ARGUS shared config from analyzer/config.yml."""
from pathlib import Path
import yaml
import streamlit as st


@st.cache_data
def load_argus_config():
    """Load configuration from analyzer/config.yml."""
    config_path = Path(__file__).parent.parent / "analyzer" / "config.yml"
    with open(config_path) as f:
        return yaml.safe_load(f)