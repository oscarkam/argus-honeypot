"""
PDF/DOCX rendering via pandoc.

Runs from the MD's parent directory so relative chart paths
(e.g. charts_20260706_011304_dark/geo.png) resolve correctly.

All formats now render with:
  - Explicit GFM+extensions input format (fixes DOCX table rendering)
  - Table of Contents (--toc, depth 3)
"""
# NETWORK: local (no external calls)
# BLAST RADIUS: local file writes to reports/ only

import subprocess
from pathlib import Path
from typing import Optional


# Input format enables pipe tables + definition lists reliably in both PDF/DOCX.
# Notes:
#   - gfm already includes pipe_tables; listing it is redundant but harmless.
#   - table_captions is only valid for pandoc's 'markdown' flavour, not gfm.
#   - definition_lists must be explicitly added to gfm.
_INPUT_FORMAT = "gfm+definition_lists"

# Shared TOC flags — pandoc auto-inserts TOC after title, before body
_TOC_FLAGS = ["--toc", "--toc-depth=3", "--metadata=toc-title=Table of Contents"]

# PDF-only LaTeX header (centers longtables, tightens row spacing, etc.)
_PDF_HEADER = Path(__file__).parent / "templates" / "pdf_header.tex"


def _run_pandoc(
    md_path: Path, out_path: Path, extra_args: list[str]
) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [
                "pandoc",
                f"--from={_INPUT_FORMAT}",
                md_path.name,
                "-o", str(out_path),
                *extra_args,
            ],
            cwd=str(md_path.parent),   # so charts_*/*.png resolves
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout).strip()
            return False, err[:400] or "pandoc returned non-zero with no output"
        return True, ""
    except FileNotFoundError:
        return False, "pandoc binary not found (install: apt install pandoc)"
    except subprocess.TimeoutExpired:
        return False, "pandoc timed out after 120s"
    except Exception as e:
        return False, f"unexpected error: {type(e).__name__}: {e}"


def render_pdf(md_path: Path) -> tuple[Optional[Path], str]:
    """Return (pdf_path, error_message). error is '' on success.

    PDF-specific variables:
      - colorlinks / linkcolor / urlcolor / toccolor make hyperlinks
        visually distinct (colored, not black) so readers see they're
        clickable in the PDF viewer.
      - --include-in-header injects LaTeX preamble to center longtables
        and tighten row spacing (see templates/pdf_header.tex).
    """
    pdf_path = md_path.with_suffix(".pdf")
    extra = [
        "--pdf-engine=xelatex",
        "-V", "colorlinks=true",
        "-V", "linkcolor=NavyBlue",   # in-doc links (e.g. TOC → section)
        "-V", "urlcolor=NavyBlue",     # external URLs (MITRE / CSF / etc.)
        "-V", "toccolor=NavyBlue",     # TOC entry colour
        *_TOC_FLAGS,
    ]
    if _PDF_HEADER.exists():
        extra += [f"--include-in-header={_PDF_HEADER}"]
    ok, err = _run_pandoc(md_path, pdf_path, extra)
    return (pdf_path if ok else None), err


def render_docx(md_path: Path) -> tuple[Optional[Path], str]:
    """Return (docx_path, error_message). error is '' on success."""
    docx_path = md_path.with_suffix(".docx")
    ok, err = _run_pandoc(md_path, docx_path, _TOC_FLAGS)
    return (docx_path if ok else None), err