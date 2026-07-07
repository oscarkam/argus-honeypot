"""Report Studio — configure, generate, preview, and download ARGUS reports."""
import sys
import os
import subprocess
import re
from pathlib import Path

import streamlit as st

# Make analyzer's modules importable
_ANALYZER = Path(__file__).parent.parent.parent / "analyzer"
sys.path.insert(0, str(_ANALYZER))
from analyzer import run_pipeline   # noqa: E402

from utils.es import get_full_data
from utils.system import check_all_systems
from config import load_argus_config


PERIOD_HOURS = {"daily": 24, "weekly": 168, "monthly": 720}


def render():
    # -------- Header --------
    st.markdown(
        '<div class="page-header">'
        '<div class="page-header-titlerow">'
        '<span class="page-header-icon"><i class="bi bi-file-earmark-text"></i></span>'
        '<h1 class="page-header-title">Report Studio</h1>'
        '</div>'
        '<p class="page-header-desc">'
        'Generate a threat intelligence report from live honeypot telemetry. '
        'Reports include framework mappings '
        '(<code>MITRE ATT&amp;CK</code>, <code>Cyber Kill Chain</code>, <code>NIST CSF</code>), '
        'themed charts, and LLM-generated prose narrative.'
        '</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    # -------- Preflight — health check --------
    status = check_all_systems()
    critical_down = [
        name for name, ok in [
            ("SSH Tunnel", status["tunnel"]),
            ("Elasticsearch", status["es"]),
            ("Ollama LLM", status["ollama"]),
        ] if not ok
    ]
    if critical_down:
        st.error(
            f"⛔ Cannot generate reports — required subsystems unreachable: **{', '.join(critical_down)}**. "
            f"Run `./scripts/session-start.sh` from the repo root."
        )
        return

    config = load_argus_config()

    # -------- Configuration form --------
    st.markdown("### Configuration")
    with st.container(border=True):
        col1, col2 = st.columns(2)
        with col1:
            period = st.selectbox(
                "Reporting Period",
                options=["daily", "weekly", "monthly"],
                index=0,
                format_func=lambda x: {
                    "daily": "Daily (last 24h)",
                    "weekly": "Weekly (last 7d)",
                    "monthly": "Monthly (last 30d)",
                }[x],
                help="Time window queried from Elasticsearch",
            )
            style = st.radio(
                "Report Style",
                options=["brief", "full"],
                index=0,
                horizontal=True,
                format_func=lambda x: "Brief (Executive Summary)" if x == "brief" else "Full (Analyst Detail)",
                help="Brief ≈ 3 pages; Full ≈ 10-15 pages with full framework tables + IOCs",
            )
        with col2:
            theme = st.radio(
                "Chart Theme",
                options=["dark", "light"],
                index=0,
                horizontal=True,
                format_func=lambda x: x.title(),
                help="Dark for on-screen viewing; light for printed PDF",
            )
            organization = st.text_input(
                "Prepared For",
                value=config["report"]["organization"],
                help="Organization or recipient name — appears in the report header",
            )

    st.markdown("")

    # -------- Generate button --------
    generate = st.button(
        "Generate Report",
        type="primary",
        use_container_width=True,
    )

    # -------- Execute generation --------
    if generate:
        _generate_report(config, period, style, theme, organization)

    # -------- Show previously generated report --------
    if "last_report" in st.session_state:
        st.markdown("---")
        _display_report(st.session_state["last_report"])


def _generate_report(config: dict, period: str, style: str, theme: str, organization: str):
    """Run the ARGUS pipeline and store result in session state."""
    hours = PERIOD_HOURS[period]

    # Shallow-copy config and inject the org override
    cfg = dict(config)
    cfg["report"] = dict(config["report"])
    cfg["report"]["organization"] = organization

    output_dir = str((_ANALYZER.parent / "reports").resolve())

    with st.status("Generating ARGUS report...", expanded=True) as status:
        try:
            st.write(f"→ Querying Elasticsearch for last {hours}h...")
            data = get_full_data(hours=hours)

            if data["total_attacks"] == 0:
                st.warning(
                    f"⚠ No attack sessions found in the last {hours}h. "
                    "Report will be sparse. Consider a longer window."
                )

            st.write(f"→ {data['total_attacks']:,} sessions retrieved · "
                     f"{data['unique_source_ips']} unique source IPs")
            st.write("→ Classifying against MITRE ATT&CK, Cyber Kill Chain, NIST CSF...")
            st.write("→ Rendering Aurora Ops themed charts...")
            st.write(f"→ Calling Ollama LLM ({cfg['ollama']['model']}) for narrative — this may take 30-90s...")

            # run_pipeline resolves relative paths against cwd. chdir into analyzer briefly.
            original_cwd = os.getcwd()
            try:
                os.chdir(str(_ANALYZER))
                filepath = run_pipeline(cfg, data, style, period, hours, output_dir, theme)
            finally:
                os.chdir(original_cwd)

            st.write(f"→ Report written: `{Path(filepath).name}`")
            status.update(label="✓ Report generated successfully", state="complete", expanded=False)

            st.session_state["last_report"] = {
                "filepath": filepath,
                "style": style,
                "theme": theme,
                "period": period,
                "organization": organization,
                "attacks": data["total_attacks"],
            }
        except Exception as e:
            status.update(label="✗ Report generation failed", state="error", expanded=True)
            st.error(f"Error: {e}")
            import traceback
            with st.expander("Show technical traceback"):
                st.code(traceback.format_exc())


def _display_report(report_info: dict):
    """Render preview + provide download buttons."""
    filepath = Path(report_info["filepath"])
    if not filepath.exists():
        st.error(f"Report file no longer exists: {filepath}")
        return

    # -------- Metadata badges --------
    st.markdown("### Latest Report")
    meta_cols = st.columns(5)
    meta_cols[0].metric("Period", report_info["period"].title())
    meta_cols[1].metric("Style", report_info["style"].title())
    meta_cols[2].metric("Theme", report_info["theme"].title())
    meta_cols[3].metric("Sessions", f"{report_info['attacks']:,}")
    meta_cols[4].metric("File", filepath.name.split("_")[-1].replace(".md", ""))

    st.markdown("")

    # -------- Preview --------
    with st.expander("Preview report", expanded=True):
        md_content = filepath.read_text()
        _render_markdown_with_images(md_content, filepath.parent)

    # -------- Downloads --------
    st.markdown("### Download")
    d1, d2, d3 = st.columns(3)

    with d1:
        with open(filepath, "rb") as f:
            st.download_button(
                "Markdown (.md)",
                data=f.read(),
                file_name=filepath.name,
                mime="text/markdown",
                use_container_width=True,
            )

    with d2:
        pdf_path = filepath.with_suffix(".pdf")
        if not pdf_path.exists():
            with st.spinner("Converting to PDF..."):
                _convert_via_pandoc(filepath, pdf_path, pdf=True)
        if pdf_path.exists():
            with open(pdf_path, "rb") as f:
                st.download_button(
                    "PDF (.pdf)",
                    data=f.read(),
                    file_name=pdf_path.name,
                    mime="application/pdf",
                    use_container_width=True,
                )
        else:
            st.button(
                "⚠  PDF unavailable",
                disabled=True,
                use_container_width=True,
                help="pandoc PDF conversion failed — install texlive-xetex if desired",
            )

    with d3:
        docx_path = filepath.with_suffix(".docx")
        if not docx_path.exists():
            with st.spinner("Converting to DOCX..."):
                _convert_via_pandoc(filepath, docx_path, pdf=False)
        if docx_path.exists():
            with open(docx_path, "rb") as f:
                st.download_button(
                    "Word (.docx)",
                    data=f.read(),
                    file_name=docx_path.name,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    use_container_width=True,
                )
        else:
            st.button("⚠  DOCX unavailable", disabled=True, use_container_width=True)


def _render_markdown_with_images(md: str, base_dir: Path) -> None:
    """Render markdown with inline PNG images (Streamlit doesn't resolve relative image paths)."""
    pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
    last_end = 0
    for match in re.finditer(pattern, md):
        # Render markdown before this image
        before = md[last_end:match.start()]
        if before.strip():
            st.markdown(before, unsafe_allow_html=False)
        # Render the image
        alt = match.group(1)
        rel_path = match.group(2)
        img_path = (base_dir / rel_path).resolve()
        if img_path.exists():
            st.image(str(img_path), caption=alt or None, use_container_width=True)
        else:
            st.warning(f"Image not found: {rel_path}")
        last_end = match.end()
    # Render remaining markdown after last image
    remaining = md[last_end:]
    if remaining.strip():
        st.markdown(remaining, unsafe_allow_html=False)


def _convert_via_pandoc(md_path: Path, out_path: Path, pdf: bool) -> bool:
    """Convert markdown to PDF or DOCX via pandoc; returns True on success."""
    cmd = ["pandoc", str(md_path), "-o", str(out_path)]
    if pdf:
        # Try xelatex, fall back to other engines
        for engine in ["xelatex", "lualatex", "pdflatex"]:
            try:
                subprocess.run(
                    cmd + [f"--pdf-engine={engine}"],
                    capture_output=True, timeout=90, cwd=str(md_path.parent),
                )
                if out_path.exists():
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return False
    else:
        try:
            subprocess.run(
                cmd, capture_output=True, timeout=60, cwd=str(md_path.parent),
            )
            return out_path.exists()
        except Exception:
            return False