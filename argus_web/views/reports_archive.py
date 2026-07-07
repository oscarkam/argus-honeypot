"""Reports Archive — browse, filter, preview, and download past ARGUS reports."""
import sys
from pathlib import Path
import subprocess
import re

import streamlit as st

_ANALYZER = Path(__file__).parent.parent.parent / "analyzer"
sys.path.insert(0, str(_ANALYZER))
from naming import parse_report_filename, format_display_datetime   # noqa: E402

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"


def render():
    st.markdown(
        '<div class="page-header">'
        '<div class="page-header-titlerow">'
        '<span class="page-header-icon"><i class="bi bi-archive-fill"></i></span>'
        '<h1 class="page-header-title">Reports Archive</h1>'
        '</div>'
        '<p class="page-header-desc">'
        'Browse and download previously generated ARGUS reports. '
        'Reports follow naming convention: '
        '<code>SYSTEM_period_style_theme_YYYYMMDD_HHMMSS</code>.'
        '</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not REPORTS_DIR.exists():
        st.info("No reports directory found yet. Generate your first report from **Report Studio**.")
        return

    md_files = sorted(REPORTS_DIR.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not md_files:
        st.info("No reports found. Generate your first report from **Report Studio**.")
        return

    # -------- Filter bar --------
    st.markdown("### Filter")
    with st.container(border=True):
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            filter_period = st.multiselect("Period", ["daily", "weekly", "monthly"])
        with f2:
            filter_style = st.multiselect("Style", ["brief", "full"])
        with f3:
            filter_theme = st.multiselect("Theme", ["dark", "light"])
        with f4:
            filter_system = st.text_input("Filename contains", value="")

    # -------- Filter reports --------
    filtered = []
    for md in md_files:
        parsed = parse_report_filename(md.name)
        if not parsed:
            parsed = {"system": "legacy", "period": "unknown",
                      "style": "unknown", "theme": "unknown",
                      "date": "", "time": "", "stem": md.stem}
        if filter_period and parsed.get("period") not in filter_period:
            continue
        if filter_style and parsed.get("style") not in filter_style:
            continue
        if filter_theme and parsed.get("theme") not in filter_theme:
            continue
        if filter_system and filter_system.lower() not in md.name.lower():
            continue
        filtered.append((md, parsed))

    st.markdown(f"### Reports  ·  {len(filtered)} of {len(md_files)} shown")

    if not filtered:
        st.warning("No reports match the current filters.")
        return

    for md_path, parsed in filtered:
        _render_report_row(md_path, parsed)


def _render_report_row(md_path: Path, parsed: dict):
    stem = md_path.stem
    size_kb = md_path.stat().st_size / 1024

    if parsed.get("date") and parsed.get("time"):
        display_dt = format_display_datetime(parsed["date"], parsed["time"])
    else:
        from datetime import datetime
        display_dt = datetime.fromtimestamp(md_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    pdf_path = md_path.with_suffix(".pdf")
    docx_path = md_path.with_suffix(".docx")

    with st.container(border=True):
        header = (
            '<div class="report-row-header">'
            '<div class="report-name">'
            f'<i class="bi bi-file-earmark-text"></i>&nbsp;{stem}'
            '</div>'
            '<div class="report-meta">'
            f'<span class="badge period">{parsed.get("period", "").upper()}</span>'
            f'<span class="badge style">{parsed.get("style", "").upper()}</span>'
            f'<span class="badge theme">{parsed.get("theme", "").upper()}</span>'
            f'<span class="report-date">{display_dt}</span>'
            f'<span class="report-size">{size_kb:.1f} KB</span>'
            '</div>'
            '</div>'
        )
        st.markdown(header, unsafe_allow_html=True)

        a1, a2, a3, a4 = st.columns([1, 1, 1, 1])

        with a1:
            with open(md_path, "rb") as f:
                st.download_button(
                    "Markdown",
                    data=f.read(),
                    file_name=md_path.name,
                    mime="text/markdown",
                    key=f"md_{stem}",
                    use_container_width=True,
                )

        with a2:
            if not pdf_path.exists():
                if st.button("Generate PDF", key=f"gen_pdf_{stem}", use_container_width=True):
                    with st.spinner("Converting to PDF..."):
                        _convert(md_path, pdf_path, pdf=True)
                    st.rerun()
            else:
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        "PDF",
                        data=f.read(),
                        file_name=pdf_path.name,
                        mime="application/pdf",
                        key=f"pdf_{stem}",
                        use_container_width=True,
                    )

        with a3:
            if not docx_path.exists():
                if st.button("Generate DOCX", key=f"gen_docx_{stem}", use_container_width=True):
                    with st.spinner("Converting to DOCX..."):
                        _convert(md_path, docx_path, pdf=False)
                    st.rerun()
            else:
                with open(docx_path, "rb") as f:
                    st.download_button(
                        "Word",
                        data=f.read(),
                        file_name=docx_path.name,
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        key=f"docx_{stem}",
                        use_container_width=True,
                    )

        with a4:
            key = f"expanded_{stem}"
            if st.button("Preview", key=f"view_{stem}", use_container_width=True):
                st.session_state[key] = not st.session_state.get(key, False)

        if st.session_state.get(f"expanded_{stem}", False):
            with st.expander("Report preview", expanded=True):
                _render_markdown_with_images(md_path.read_text(), md_path.parent)


def _render_markdown_with_images(md: str, base_dir: Path) -> None:
    pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
    last_end = 0
    for match in re.finditer(pattern, md):
        before = md[last_end:match.start()]
        if before.strip():
            st.markdown(before, unsafe_allow_html=False)
        alt = match.group(1)
        rel_path = match.group(2)
        img_path = (base_dir / rel_path).resolve()
        if img_path.exists():
            st.image(str(img_path), caption=alt or None, use_container_width=True)
        else:
            st.warning(f"Image not found: {rel_path}")
        last_end = match.end()
    remaining = md[last_end:]
    if remaining.strip():
        st.markdown(remaining, unsafe_allow_html=False)


def _convert(md_path: Path, out_path: Path, pdf: bool) -> bool:
    cmd = ["pandoc", str(md_path), "-o", str(out_path)]
    if pdf:
        for engine in ["xelatex", "lualatex", "pdflatex"]:
            try:
                subprocess.run(cmd + [f"--pdf-engine={engine}"],
                               capture_output=True, timeout=90, cwd=str(md_path.parent))
                if out_path.exists():
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return False
    else:
        try:
            subprocess.run(cmd, capture_output=True, timeout=60, cwd=str(md_path.parent))
            return out_path.exists()
        except Exception:
            return False