"""File naming convention for ARGUS-generated artifacts.

Format: {SYSTEM}_{period}_{style}_{theme}_{YYYYMMDD}_{HHMMSS}.{ext}
Example: ARGUS_daily_brief_dark_20260706_030613.md

Rationale — files are sortable by:
    1. System (all-caps for identity + grouping)
    2. Period (daily/weekly/monthly)
    3. Style (brief/full)
    4. Theme (dark/light)
    5. Date & time
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional


def build_report_filename(
    system_name: str,
    period: str,
    style: str,
    theme: str,
    timestamp: Optional[datetime] = None,
    extension: str = "md",
) -> str:
    """Build a standardised report filename."""
    ts = timestamp or datetime.now()
    ts_str = ts.strftime("%Y%m%d_%H%M%S")
    return f"{system_name.upper()}_{period}_{style}_{theme}_{ts_str}.{extension}"


def build_chart_dir_name(
    period: str,
    theme: str,
    timestamp: Optional[datetime] = None,
) -> str:
    """Build a standardised chart directory name (companion to a report)."""
    ts = timestamp or datetime.now()
    ts_str = ts.strftime("%Y%m%d_%H%M%S")
    return f"charts_{period}_{theme}_{ts_str}"


def parse_report_filename(filename: str) -> dict:
    """Parse a report filename back into its components.

    Returns dict: {system, period, style, theme, date, time, extension}
    Returns empty dict if the filename doesn't match the convention.
    """
    stem = Path(filename).stem
    parts = stem.split("_")
    if len(parts) < 6:
        return {}
    return {
        "system": parts[0],
        "period": parts[1],
        "style": parts[2],
        "theme": parts[3],
        "date": parts[4],
        "time": parts[5],
        "extension": Path(filename).suffix.lstrip("."),
        "stem": stem,
    }


def format_display_datetime(date_str: str, time_str: str) -> str:
    """Convert 20260706_030613 → '2026-07-06 03:06:13' for display."""
    try:
        dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return f"{date_str} {time_str}"