"""
ARGUS pipeline metrics recorder.

Purpose:
    Captures wall-clock timing and success outcomes for every analyser
    invocation. Writes one CSV row per run to analyzer/metrics.csv.

Usage (from analyzer.py main):

    from metrics import PipelineMetrics

    m = PipelineMetrics(period="daily", style="brief", theme="dark", mode="live")
    try:
        # ... pipeline work ...
        m.record_pdf(pdf_seconds, pdf_success)
        m.record_docx(docx_seconds, docx_success)
        m.mark_success()
    except Exception as e:
        m.mark_failure(str(e))
        raise
    finally:
        m.write()

Notes:
    - No dependencies beyond the Python standard library.
    - CSV file is created with header on first write, appended thereafter.
    - Failure reason is truncated to 200 characters to keep rows readable.
"""
# NETWORK: local (writes only to analyzer/metrics.csv)
# BLAST RADIUS: single CSV file append; no destructive operations

from __future__ import annotations

import csv
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo


_METRICS_PATH = Path(__file__).parent / "metrics.csv"
_TIMEZONE = ZoneInfo("Asia/Kuala_Lumpur")


_FIELDNAMES = [
    "timestamp",
    "mode",
    "period",
    "style",
    "theme",
    "success",
    "total_seconds",
    "pdf_seconds",
    "pdf_success",
    "docx_seconds",
    "docx_success",
    "failure_reason",
]


class PipelineMetrics:
    """Records timing and outcome of a single analyser run."""

    def __init__(self, period: str, style: str, theme: str, mode: str = "live") -> None:
        self.period = period
        self.style = style
        self.theme = theme
        self.mode = mode
        self._start = time.perf_counter()
        self.pdf_seconds: Optional[float] = None
        self.pdf_success: bool = False
        self.docx_seconds: Optional[float] = None
        self.docx_success: bool = False
        self.success: bool = False
        self.failure_reason: str = ""

    def record_pdf(self, seconds: float, success: bool) -> None:
        self.pdf_seconds = round(seconds, 3)
        self.pdf_success = success

    def record_docx(self, seconds: float, success: bool) -> None:
        self.docx_seconds = round(seconds, 3)
        self.docx_success = success

    def mark_success(self) -> None:
        self.success = True

    def mark_failure(self, reason: str) -> None:
        self.success = False
        self.failure_reason = str(reason)[:200]

    def write(self) -> None:
        """Append the metrics row to the CSV file."""
        total = round(time.perf_counter() - self._start, 3)
        row = {
            "timestamp": datetime.now(_TIMEZONE).isoformat(timespec="seconds"),
            "mode": self.mode,
            "period": self.period,
            "style": self.style,
            "theme": self.theme,
            "success": self.success,
            "total_seconds": total,
            "pdf_seconds": self.pdf_seconds if self.pdf_seconds is not None else "",
            "pdf_success": self.pdf_success,
            "docx_seconds": self.docx_seconds if self.docx_seconds is not None else "",
            "docx_success": self.docx_success,
            "failure_reason": self.failure_reason,
        }
        _append_row(row)


def _append_row(row: dict) -> None:
    """Append a row to the metrics CSV, writing the header on first use."""
    write_header = not _METRICS_PATH.exists() or _METRICS_PATH.stat().st_size == 0
    with open(_METRICS_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def load_summary(last_n: Optional[int] = None) -> dict:
    """Return a summary of recorded runs. Used by the ARGUS Control Center
    System Health view and by Chapter 4 reliability table generation.

    Args:
        last_n: if provided, summarise only the most recent N rows. Otherwise all.

    Returns:
        {
            'run_count': int,
            'success_count': int,
            'success_rate_percent': float,   # 0 to 100
            'total_seconds_mean': float,
            'total_seconds_min': float,
            'total_seconds_max': float,
            'total_seconds_p95': float,
            'pdf_success_count': int,
            'docx_success_count': int,
            'latest_timestamp': str,
        }
        or {'run_count': 0} if metrics.csv is empty or absent.
    """
    if not _METRICS_PATH.exists() or _METRICS_PATH.stat().st_size == 0:
        return {"run_count": 0}

    rows = list(csv.DictReader(_METRICS_PATH.open()))
    if not rows:
        return {"run_count": 0}

    rows.sort(key=lambda r: r.get("timestamp", ""))
    if last_n is not None:
        rows = rows[-last_n:]

    total_times = [float(r["total_seconds"]) for r in rows if r.get("total_seconds")]
    success_count = sum(1 for r in rows if r.get("success", "").lower() == "true")
    pdf_ok = sum(1 for r in rows if r.get("pdf_success", "").lower() == "true")
    docx_ok = sum(1 for r in rows if r.get("docx_success", "").lower() == "true")

    def _p(pct: float, values: list) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        k = max(0, min(len(s) - 1, int(round((pct / 100.0) * (len(s) - 1)))))
        return round(s[k], 3)

    return {
        "run_count": len(rows),
        "success_count": success_count,
        "success_rate_percent": round(100.0 * success_count / len(rows), 1) if rows else 0.0,
        "total_seconds_mean": round(sum(total_times) / len(total_times), 3) if total_times else 0.0,
        "total_seconds_min": round(min(total_times), 3) if total_times else 0.0,
        "total_seconds_max": round(max(total_times), 3) if total_times else 0.0,
        "total_seconds_p95": _p(95, total_times),
        "pdf_success_count": pdf_ok,
        "docx_success_count": docx_ok,
        "latest_timestamp": rows[-1].get("timestamp", "") if rows else "",
    }
