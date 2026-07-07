"""ARGUS Control Center — main Streamlit application entry."""
import sys
from pathlib import Path

_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

import streamlit as st
from streamlit_option_menu import option_menu

from styles import inject_aurora_css
from config import load_argus_config
from views import home, report_studio, reports_archive, tpot_bridge, system_health

# Page config MUST be first Streamlit call
st.set_page_config(
    page_title="ARGUS Control Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_aurora_css()
config = load_argus_config()

# ---- Sidebar navigation ----
with st.sidebar:
    st.markdown("# 🛡️ ARGUS")
    st.caption(f"v{config['system']['version']} · Control Center")
    st.markdown("---")

    selected = option_menu(
        menu_title=None,
        options=[
            "Home",
            "Report Studio",
            "Reports Archive",
            "T-Pot Bridge",
            "System Health",
        ],
        icons=[
            "house-fill",
            "file-earmark-text",
            "archive-fill",
            "broadcast-pin",
            "activity",
        ],
        default_index=0,
        styles={
            "container": {"padding": "0!important", "background-color": "transparent"},
            "icon": {"color": "#A78BFA", "font-size": "17px"},
            "nav-link": {
                "font-size": "14px",
                "color": "#EEEBFA",
                "text-align": "left",
                "margin": "3px 0",
                "border-radius": "6px",
                "padding": "10px 12px",
            },
            "nav-link-selected": {
                "background-color": "#4C7DFF",
                "color": "white",
                "font-weight": "600",
            },
        },
    )

    # Session context footer — intentional identity block
    st.markdown(
        '<div class="sidebar-footer">'
        '<p class="footer-heading">Session Context</p>'
        '<div class="footer-item">'
        '<i class="bi bi-building"></i>'
        '<div>'
        '<p class="footer-label">Organization</p>'
        f'<p class="footer-value">{config["report"]["organization"]}</p>'
        '</div>'
        '</div>'
        '<div class="footer-item">'
        '<i class="bi bi-clock"></i>'
        '<div>'
        '<p class="footer-label">Timezone</p>'
        f'<p class="footer-value">{config["report"]["timezone"]}</p>'
        '</div>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

# ---- Page routing ----
if selected == "Home":
    home.render()
elif selected == "Report Studio":
    report_studio.render()
elif selected == "Reports Archive":
    reports_archive.render()
elif selected == "T-Pot Bridge":
    tpot_bridge.render()
elif selected == "System Health":
    system_health.render()