"""Aurora Ops CSS theme injection — ARGUS Control Center."""
import streamlit as st


AURORA_OPS_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">

<style>
:root {
    --bg: #0D1329;
    --panel: #1A2040;
    --primary: #4C7DFF;
    --secondary: #A78BFA;
    --accent: #C4A8F5;
    --text: #EEEBFA;
    --text-dim: #8B90B8;
    --grid: #252B4A;
    --positive: #3EBB84;
    --negative: #E14E64;
    --warning: #F0A64E;
}

.stApp {
    background: var(--bg);
    color: var(--text);
    font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
}

/* Subtle dot grid background — 'monitored surface' feel */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background-image: radial-gradient(circle at 1px 1px, rgba(167, 139, 250, 0.06) 1px, transparent 0);
    background-size: 34px 34px;
    pointer-events: none;
    z-index: 0;
}
.main .block-container { position: relative; z-index: 1; }

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0D1329 0%, #161C34 100%);
    border-right: 1px solid var(--grid);
}

[data-testid="stSidebar"] h1 {
    font-family: 'Orbitron', sans-serif;
    letter-spacing: 0.15em;
    font-weight: 700;
    background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

h1, h2, h3, h4, h5 {
    color: var(--text);
    font-family: 'Space Grotesk', sans-serif;
}

/* ---- Hero ---- */
.hero {
    text-align: center;
    padding: 3rem 1rem 2.5rem 1rem;
    background: linear-gradient(135deg, rgba(76,125,255,0.10) 0%, rgba(167,139,250,0.10) 100%);
    border-radius: 14px;
    border: 1px solid var(--grid);
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(circle at 50% 50%, rgba(76,125,255,0.10) 0%, transparent 60%);
    pointer-events: none;
    animation: hero-glow 6s ease-in-out infinite;
}
@keyframes hero-glow {
    0%, 100% { opacity: 0.6; }
    50% { opacity: 1; }
}
.hero::after {
    content: "";
    position: absolute;
    top: 0; left: -30%;
    width: 30%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(167, 139, 250, 0.10), transparent);
    animation: scan-sweep 10s ease-in-out infinite;
    pointer-events: none;
}
@keyframes scan-sweep {
    0% { left: -30%; }
    100% { left: 130%; }
}
.hero h1 {
    font-family: 'Orbitron', sans-serif;
    font-size: 5rem;
    font-weight: 900;
    background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 60%, var(--accent) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    animation: title-breathe 5s ease-in-out infinite;
    position: relative;
    z-index: 2;
}
@keyframes title-breathe {
    0%, 100% { filter: drop-shadow(0 2px 8px rgba(76,125,255,0.3)); }
    50% { filter: drop-shadow(0 2px 22px rgba(167,139,250,0.55)); }
}
.hero .tagline {
    color: var(--text-dim);
    font-size: 1.05rem;
    margin: 0.8rem 0 0.4rem 0;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 400;
    position: relative; z-index: 2;
}
.hero .version {
    color: var(--secondary);
    font-size: 0.8rem;
    letter-spacing: 0.25em;
    text-transform: uppercase;
    margin: 0;
    font-family: 'Orbitron', sans-serif;
    font-weight: 500;
    position: relative; z-index: 2;
}

/* ---- Section headings ---- */
.section-heading {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 1.5rem 0 1rem 0;
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text);
}
.section-heading i {
    color: var(--secondary);
    font-size: 1.4rem;
    animation: subtle-glow 3.5s ease-in-out infinite;
}
@keyframes subtle-glow {
    0%, 100% { filter: drop-shadow(0 0 0 rgba(167, 139, 250, 0)); }
    50% { filter: drop-shadow(0 0 8px rgba(167, 139, 250, 0.6)); }
}

/* ---- LIVE indicator badge ---- */
.live-indicator {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem 0.65rem;
    background: rgba(225, 78, 100, 0.10);
    border: 1px solid rgba(225, 78, 100, 0.30);
    border-radius: 4px;
    font-family: 'Orbitron', sans-serif;
    font-size: 0.68rem;
    font-weight: 500;
    letter-spacing: 0.18em;
    color: var(--negative);
    text-transform: uppercase;
    margin-left: 0.75rem;
}
.live-indicator .live-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--negative);
    animation: pulse-live 1.5s infinite;
}
@keyframes pulse-live {
    0%, 100% { opacity: 1; box-shadow: 0 0 6px rgba(225, 78, 100, 0.7); }
    50% { opacity: 0.35; box-shadow: 0 0 0 rgba(225, 78, 100, 0); }
}

/* ---- Metric cards ---- */
[data-testid="stMetric"] {
    background: var(--panel);
    padding: 1rem 1.25rem;
    border-radius: 8px;
    border: 1px solid var(--grid);
    transition: border-color 0.2s, transform 0.2s;
    position: relative;
    overflow: hidden;
}
[data-testid="stMetric"]:hover {
    border-color: var(--primary);
    transform: translateY(-2px);
}
[data-testid="stMetric"]::after {
    content: "";
    position: absolute;
    bottom: 0; left: 0;
    width: 100%; height: 3px;
    background: linear-gradient(90deg, var(--primary), var(--secondary));
    transform: scaleX(0);
    transform-origin: left;
    transition: transform 0.35s ease;
}
[data-testid="stMetric"]:hover::after { transform: scaleX(1); }
[data-testid="stMetricValue"] {
    color: var(--primary);
    font-size: 1.9rem;
    font-weight: 700;
    font-family: 'Orbitron', sans-serif;
}
[data-testid="stMetricLabel"] {
    color: var(--text-dim);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 500;
}

/* ---- Status cards (breathing) ---- */
.status-row {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin: 1rem 0;
}
.status-card {
    flex: 1;
    min-width: 220px;
    background: var(--panel);
    border: 1px solid var(--grid);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    align-items: center;
    gap: 0.9rem;
    transition: border-color 0.2s, transform 0.15s ease;
}
.status-card:hover {
    border-color: var(--primary);
    transform: translateX(3px);
}
.status-card .label {
    color: var(--text-dim);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin: 0 0 0.15rem 0;
}
.status-card .value {
    color: var(--text);
    font-size: 1rem;
    font-weight: 600;
    margin: 0;
}
.dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    flex-shrink: 0;
}
.dot.up { background: var(--positive); animation: pulse-green 2s infinite; }
.dot.down { background: var(--negative); animation: pulse-red 2s infinite; }
@keyframes pulse-green {
    0% { box-shadow: 0 0 0 0 rgba(62, 187, 132, 0.7); }
    70% { box-shadow: 0 0 0 12px rgba(62, 187, 132, 0); }
    100% { box-shadow: 0 0 0 0 rgba(62, 187, 132, 0); }
}
@keyframes pulse-red {
    0% { box-shadow: 0 0 0 0 rgba(225, 78, 100, 0.7); }
    70% { box-shadow: 0 0 0 12px rgba(225, 78, 100, 0); }
    100% { box-shadow: 0 0 0 0 rgba(225, 78, 100, 0); }
}

/* ---- Action cards ---- */
.action-card {
    background: var(--panel);
    padding: 1.4rem;
    border-radius: 8px;
    border: 1px solid var(--grid);
    transition: all 0.25s ease;
    height: 100%;
    min-height: 170px;
    position: relative;
    overflow: hidden;
}
.action-card:hover {
    border-color: var(--primary);
    transform: translateY(-3px);
    box-shadow: 0 10px 28px rgba(76,125,255,0.22);
}
.action-card::before {
    content: "";
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(167, 139, 250, 0.10), transparent);
    transition: left 0.7s ease;
    pointer-events: none;
}
.action-card:hover::before { left: 100%; }
.action-card .card-icon {
    font-size: 1.7rem;
    color: var(--secondary);
    margin-bottom: 0.5rem;
    display: block;
    transition: transform 0.3s ease, color 0.3s ease;
}
.action-card:hover .card-icon {
    transform: scale(1.15) rotate(6deg);
    color: var(--primary);
}
.action-card h4 {
    color: var(--text);
    margin: 0 0 0.5rem 0;
    font-size: 1.05rem;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 600;
}
.action-card p {
    color: var(--text-dim);
    font-size: 0.88rem;
    margin: 0 0 1rem 0;
    line-height: 1.4;
}
.action-card .btn-hint {
    color: var(--primary);
    font-size: 0.82rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* ---- Streamlit chrome ---- */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
[data-testid="stHeader"] { background: transparent; }

/* ---- Buttons ---- */
.stButton > button {
    background: var(--primary);
    color: white;
    border: none;
    border-radius: 6px;
    padding: 0.55rem 1.5rem;
    font-weight: 600;
    transition: all 0.2s;
    font-family: 'Space Grotesk', sans-serif;
    box-shadow: 0 2px 8px rgba(76, 125, 255, 0.2);
}
.stButton > button:hover {
    background: var(--secondary);
    color: white;
    box-shadow: 0 4px 16px rgba(167, 139, 250, 0.35);
    transform: translateY(-1px);
}

/* ---- Alerts ---- */
.stAlert { border-radius: 8px; border-left-width: 4px; }

/* ---- Sidebar caption ---- */
[data-testid="stSidebar"] .stCaption {
    color: var(--text-dim);
    font-size: 0.78rem;
    font-family: 'Space Grotesk', sans-serif;
}

/* ---- Hr ---- */
hr { border-color: var(--grid); margin: 1.5rem 0; }

/* ---- Sidebar footer — session context ---- */
.sidebar-footer {
    padding: 1.2rem 0.5rem 0.5rem 0.5rem;
    border-top: 1px solid var(--grid);
    margin-top: 1.5rem;
    background: rgba(76, 125, 255, 0.03);
    border-radius: 6px;
}
.sidebar-footer .footer-heading {
    color: var(--text-dim);
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    font-family: 'Orbitron', sans-serif;
    font-weight: 500;
    margin: 0 0 0.9rem 0.4rem;
}
.sidebar-footer .footer-item {
    display: flex;
    align-items: start;
    gap: 0.6rem;
    margin: 0 0 0.85rem 0.4rem;
}
.sidebar-footer .footer-item i {
    color: var(--secondary);
    font-size: 0.95rem;
    margin-top: 2px;
    flex-shrink: 0;
}
.sidebar-footer .footer-label {
    color: var(--text-dim);
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 0 0 0.15rem 0;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 500;
}
.sidebar-footer .footer-value {
    color: var(--text);
    font-size: 0.85rem;
    margin: 0;
    font-family: 'Space Grotesk', sans-serif;
    line-height: 1.3;
    font-weight: 500;
}
/* ---- Report Archive rows ---- */
.report-row-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 1rem;
}
.report-name {
    color: var(--text);
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.88rem;
    font-weight: 500;
}
.report-name i {
    color: var(--secondary);
    margin-right: 0.2rem;
}
.report-meta {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
}
.badge {
    padding: 0.18rem 0.55rem;
    border-radius: 4px;
    font-family: 'Orbitron', sans-serif;
    font-size: 0.64rem;
    font-weight: 500;
    letter-spacing: 0.12em;
    text-transform: uppercase;
}
.badge.period {
    background: rgba(76, 125, 255, 0.14);
    color: var(--primary);
    border: 1px solid rgba(76, 125, 255, 0.28);
}
.badge.style {
    background: rgba(167, 139, 250, 0.14);
    color: var(--secondary);
    border: 1px solid rgba(167, 139, 250, 0.28);
}
.badge.theme {
    background: rgba(196, 168, 245, 0.14);
    color: var(--accent);
    border: 1px solid rgba(196, 168, 245, 0.28);
}
.report-date {
    color: var(--text-dim);
    font-size: 0.85rem;
    font-family: 'Space Grotesk', sans-serif;
}
.report-size {
    color: var(--text-dim);
    font-size: 0.72rem;
    background: var(--grid);
    padding: 0.18rem 0.5rem;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
}

/* ---- T-Pot Bridge cards ---- */
.bridge-card-link {
    text-decoration: none !important;
    color: inherit !important;
    display: block;
    height: 100%;
}
.bridge-card {
    background: var(--panel);
    padding: 1.5rem;
    border-radius: 8px;
    border: 1px solid var(--grid);
    transition: all 0.25s ease;
    height: 100%;
    min-height: 200px;
    position: relative;
    overflow: hidden;
    margin-bottom: 1rem;
    cursor: pointer;
}
.bridge-card:hover {
    border-color: var(--primary);
    transform: translateY(-3px);
    box-shadow: 0 10px 28px rgba(76,125,255,0.22);
}
.bridge-card::before {
    content: "";
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(167, 139, 250, 0.10), transparent);
    transition: left 0.7s ease;
    pointer-events: none;
}
.bridge-card:hover::before { left: 100%; }
.bridge-card .card-icon {
    font-size: 1.9rem;
    color: var(--secondary);
    margin-bottom: 0.6rem;
    display: block;
    transition: transform 0.3s ease, color 0.3s ease;
}
.bridge-card:hover .card-icon {
    transform: scale(1.15) rotate(6deg);
    color: var(--primary);
}
.bridge-card h4 {
    color: var(--text) !important;
    margin: 0 0 0.5rem 0;
    font-size: 1.1rem;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 600;
}
.bridge-card p {
    color: var(--text-dim) !important;
    font-size: 0.9rem;
    margin: 0 0 1.2rem 0;
    line-height: 1.5;
}
.bridge-card .btn-hint {
    color: var(--primary) !important;
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* === ARGUS sidebar header (logo + wordmark) === */
.argus-sidebar-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 4px 20px;
    text-decoration: none !important;
    cursor: pointer;
    border-bottom: 1px solid rgba(74, 158, 255, 0.15);
    margin-bottom: 12px;
    transition: opacity 0.2s ease;
}
.argus-sidebar-header:hover {
    opacity: 0.85;
}
.argus-sidebar-logo {
    width: 44px;
    height: 34px;   /* preserves 1.29:1 aspect */
    flex-shrink: 0;
    filter: drop-shadow(0 0 8px rgba(74, 158, 255, 0.25));
}
.argus-sidebar-wordmark {
    font-family: 'Orbitron', sans-serif;
    font-weight: 700;
    font-size: 22px;
    color: #4A9EFF;
    letter-spacing: 4px;
    line-height: 1;
}

/* === Persistent logo when sidebar is collapsed === */
.argus-persistent-logo {
    position: fixed;
    top: 10px;
    left: 60px;         /* clears Streamlit's expand-arrow button */
    z-index: 999990;
    width: 34px;
    height: 26px;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.3s ease;
}
/* Streamlit sets aria-expanded=false on the sidebar when collapsed */
[data-testid="stSidebar"][aria-expanded="false"] ~ * .argus-persistent-logo,
body:has([data-testid="stSidebar"][aria-expanded="false"]) .argus-persistent-logo {
    opacity: 1;
    pointer-events: auto;
}

/* === Sidebar — flatter, less "boxed" === */
[data-testid="stSidebar"] {
    background: #0A0E27 !important;
    border-right: 1px solid rgba(167, 139, 250, 0.08);
}

/* Kill the option_menu container background — let it sit flush */
[data-testid="stSidebar"] .nav-container,
[data-testid="stSidebar"] div[class*="nav-container"] {
    background: transparent !important;
    padding: 0 !important;
    box-shadow: none !important;
}

/* Softer selected state — reads as "focused" not "shouted" */
[data-testid="stSidebar"] .nav-link-selected {
    background: linear-gradient(90deg,
        rgba(76, 125, 255, 0.18),
        rgba(167, 139, 250, 0.10)) !important;
    color: #EEEBFA !important;
    border-left: 3px solid #A78BFA;
    padding-left: 9px !important;   /* compensate for border */
    box-shadow: none !important;
}

/* Version caption + separator */
[data-testid="stSidebar"] .stCaptionContainer,
[data-testid="stSidebar"] p.stMarkdown small {
    color: rgba(238, 235, 250, 0.5);
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

/* Session Context footer — remove the boxed feel */
.sidebar-footer {
    background: transparent;
    border: none;
    border-top: 1px solid rgba(167, 139, 250, 0.10);
    padding: 20px 4px 0;
    margin-top: 24px;
}
.sidebar-footer .footer-heading {
    font-family: 'Space Grotesk', sans-serif;
    color: rgba(167, 139, 250, 0.7);
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 14px;
}
.sidebar-footer .footer-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 14px;
}
.sidebar-footer .footer-item i {
    color: #A78BFA;
    font-size: 15px;
    margin-top: 2px;
}
.sidebar-footer .footer-label {
    color: rgba(238, 235, 250, 0.55);
    font-size: 10.5px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin: 0 0 2px;
}
.sidebar-footer .footer-value {
    color: #EEEBFA;
    font-size: 13.5px;
    font-weight: 500;
    margin: 0;
    line-height: 1.35;
}

/* ===================================================================== */
/* === Standardized page header (Report Studio, Archive, Bridge, etc.) === */
/* ===================================================================== */
.page-header {
    padding: 12px 0 24px;
    margin-bottom: 24px;
    border-bottom: 1px solid rgba(167, 139, 250, 0.10);
}
.page-header-titlerow {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 10px;
}
.page-header-icon {
    color: var(--secondary);
    font-size: 30px;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    filter: drop-shadow(0 0 10px rgba(167, 139, 250, 0.30));
    animation: subtle-glow 3.5s ease-in-out infinite;
}
.page-header-title {
    font-family: 'Space Grotesk', sans-serif;
    color: var(--text);
    font-size: 30px;
    font-weight: 600;
    margin: 0;
    letter-spacing: -0.3px;
    line-height: 1.15;
}
.page-header-desc {
    color: rgba(238, 235, 250, 0.72);
    font-size: 15px;
    line-height: 1.55;
    margin: 0;
    max-width: 780px;
}
.page-header-desc code {
    background: rgba(167, 139, 250, 0.14);
    color: var(--secondary);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12.5px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
}

/* ===================================================================== */
/* === Explore section — clickable cards routing via query params === */
/* ===================================================================== */
.explore-heading {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 24px 0 16px;
}
.explore-heading i {
    color: var(--secondary);
    font-size: 22px;
    animation: subtle-glow 3.5s ease-in-out infinite;
}
.explore-heading h2 {
    font-family: 'Space Grotesk', sans-serif;
    color: var(--text);
    font-size: 22px;
    font-weight: 600;
    margin: 0;
}
.explore-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 32px;
}
@media (max-width: 1100px) {
    .explore-grid { grid-template-columns: repeat(2, 1fr); }
}
.explore-card {
    display: block;
    background: linear-gradient(160deg,
        rgba(76, 125, 255, 0.06),
        rgba(167, 139, 250, 0.04));
    border: 1px solid rgba(167, 139, 250, 0.15);
    border-radius: 14px;
    padding: 22px 20px 20px;
    text-decoration: none !important;
    color: inherit !important;
    cursor: pointer;
    transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
    position: relative;
    overflow: hidden;
}
.explore-card::before {
    content: "";
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(167, 139, 250, 0.10), transparent);
    transition: left 0.7s ease;
    pointer-events: none;
}
.explore-card:hover {
    transform: translateY(-2px);
    border-color: rgba(167, 139, 250, 0.45);
    box-shadow: 0 10px 30px rgba(76, 125, 255, 0.14);
}
.explore-card:hover::before { left: 100%; }
.explore-card-icon {
    color: var(--secondary);
    font-size: 26px;
    margin-bottom: 14px;
    transition: transform 0.3s ease, color 0.3s ease;
    display: block;
}
.explore-card:hover .explore-card-icon {
    transform: scale(1.10) rotate(4deg);
    color: var(--primary);
}
.explore-card-title {
    font-family: 'Space Grotesk', sans-serif;
    color: var(--text);
    font-size: 17px;
    font-weight: 600;
    margin: 0 0 8px;
}
.explore-card-desc {
    color: rgba(238, 235, 250, 0.68);
    font-size: 13px;
    line-height: 1.5;
    margin: 0 0 18px;
    min-height: 58px;
}
.explore-card-cta {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--primary);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
}
.explore-card-cta i { font-size: 18px; }
</style>
"""


def inject_aurora_css():
    st.markdown(AURORA_OPS_CSS, unsafe_allow_html=True)