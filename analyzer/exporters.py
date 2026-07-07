"""
PDF/DOCX rendering via pandoc.

Runs from the MD's parent directory so relative chart paths
(e.g. charts_20260706_011304_dark/geo.png) resolve correctly.
"""
# NETWORK: local (no external calls)
# BLAST RADIUS: local file writes to reports/ only

import subprocess
from pathlib import Path
from typing import Optional


def _run_pandoc(
    md_path: Path, out_path: Path, extra_args: list[str]
) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["pandoc", md_path.name, "-o", str(out_path), *extra_args],
            cwd=str(md_path.parent),   # so charts_*/*.png resolves
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout).strip()
            return False, err[:400] or "pandoc returned non-zero with no output"
        return True, ""
    except FileNotFoundError:
        return False, "pandoc binary not found (install: apt install pandoc)"
    except subprocess.TimeoutExpired:
        return False, "pandoc timed out after 90s"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}: {e}"


def render_pdf(md_path: Path) -> tuple[Optional[Path], str]:
    """Return (pdf_path, error_message). error is '' on success."""
    pdf_path = md_path.with_suffix(".pdf")
    ok, err = _run_pandoc(md_path, pdf_path, ["--pdf-engine=xelatex"])
    return (pdf_path if ok else None), err


def render_docx(md_path: Path) -> tuple[Optional[Path], str]:
    docx_path = md_path.with_suffix(".docx")
    ok, err = _run_pandoc(md_path, docx_path, [])
    return (docx_path if ok else None), err