"""
Chart generation for T-Pot LLM Analyser reports.

All charts rendered with matplotlib, saved as PNG at 150 DPI. Two themes:
  - "dark"  (default) — Aurora Ops dark navy, for on-screen viewing
  - "light"           — for printed PDF / traditional business report

Every chart function accepts an optional `theme` argument ("dark" or "light"),
so a single analyzer run can generate both variants without code changes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


# ---- Themes -------------------------------------------------------------
THEME_DARK = {
    "bg": "#0D1329",
    "panel": "#1A2040",
    "primary": "#4C7DFF",
    "secondary": "#A78BFA",
    "accent": "#C4A8F5",
    "text": "#EEEBFA",
    "text_dim": "#8B90B8",
    "grid": "#252B4A",
    "positive": "#3EBB84",
    "negative": "#E14E64",
    "warning": "#F0A64E",
}

THEME_LIGHT = {
    "bg": "#FBFAFF",
    "panel": "#F2F0FA",
    "primary": "#3B67E0",
    "secondary": "#7B5FCC",
    "accent": "#9C7EDE",
    "text": "#1A2040",
    "text_dim": "#6B7295",
    "grid": "#E4E1F0",
    "positive": "#2FA76F",
    "negative": "#CC4054",
    "warning": "#D48E3E",
}


def get_theme(name: str = "dark") -> Dict[str, str]:
    """Return the theme dict for the given name ('dark' or 'light')."""
    return THEME_LIGHT if name == "light" else THEME_DARK


def _apply_theme(ax, fig, theme: Dict[str, str], title: str | None = None) -> None:
    """Apply theme colours to a figure and axes."""
    fig.patch.set_facecolor(theme["bg"])
    ax.set_facecolor(theme["panel"])
    for spine in ax.spines.values():
        spine.set_color(theme["grid"])
    ax.tick_params(colors=theme["text_dim"], which="both")
    ax.xaxis.label.set_color(theme["text"])
    ax.yaxis.label.set_color(theme["text"])
    ax.grid(True, color=theme["grid"], linewidth=0.5, alpha=0.6)
    if title:
        ax.set_title(title, color=theme["text"], fontsize=13, pad=14, fontweight="bold")


def _save(fig, filepath: str, theme: Dict[str, str]) -> str:
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(filepath, dpi=150, bbox_inches="tight",
                facecolor=theme["bg"], edgecolor="none")
    plt.close(fig)
    return filepath


# ---- Charts -------------------------------------------------------------

def plot_geo_origins(top_countries: List[Dict], filepath: str, theme: str = "dark") -> str:
    t = get_theme(theme)
    top = list(reversed(top_countries[:10]))
    labels = [c["country"] for c in top]
    counts = [c["count"] for c in top]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.barh(labels, counts, color=t["primary"], edgecolor=t["bg"], linewidth=1.2)
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{count:,}", va="center", color=t["text"], fontsize=9)
    ax.set_xlabel("Attack sessions", fontsize=10)
    _apply_theme(ax, fig, t, "Attack Origin — Top Source Countries")
    return _save(fig, filepath, t)


def plot_port_targeting(top_ports: List[Dict], filepath: str, theme: str = "dark") -> str:
    t = get_theme(theme)
    top = list(reversed(top_ports[:10]))
    labels = [f"{p['port']} ({p['service']})" for p in top]
    counts = [p["count"] for p in top]
    # Highlight port 22 in negative colour (highest-signal targeting)
    colors = [t["negative"] if p["port"] == 22 else t["primary"] for p in top]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.barh(labels, counts, color=colors, edgecolor=t["bg"], linewidth=1.2)
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{count:,}", va="center", color=t["text"], fontsize=9)
    ax.set_xlabel("Attack attempts", fontsize=10)
    _apply_theme(ax, fig, t, "Service Targeting — Most-Attacked Ports")
    return _save(fig, filepath, t)


def plot_kill_chain_distribution(distribution: Dict[str, int], filepath: str, theme: str = "dark") -> str:
    from frameworks.kill_chain import KILL_CHAIN_STAGES  # noqa: E402
    t = get_theme(theme)
    labels = [s for s in KILL_CHAIN_STAGES if distribution.get(s, 0) > 0]
    counts = [distribution[s] for s in labels]

    fig, ax = plt.subplots(figsize=(9, 4.5))
    bars = ax.barh(list(reversed(labels)), list(reversed(counts)),
                   color=t["secondary"], edgecolor=t["bg"], linewidth=1.2)
    for bar, count in zip(bars, reversed(counts)):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{count:,}", va="center", color=t["text"], fontsize=9)
    ax.set_xlabel("Sessions", fontsize=10)
    _apply_theme(ax, fig, t, "Cyber Kill Chain — Session Stage Distribution")
    return _save(fig, filepath, t)


def plot_attack_tactics_heatmap(heatmap_data: Dict, filepath: str, theme: str = "dark") -> str:
    t = get_theme(theme)
    tactics = heatmap_data["tactics"]
    tech_per = heatmap_data["techniques_per_tactic"]
    max_count = max(heatmap_data.get("max_count", 1), 1)
    max_rows = max((len(tech_per[tac]) for tac in tactics), default=1)
    max_rows = max(max_rows, 1)

    grid = np.zeros((max_rows, len(tactics)))
    labels = [["" for _ in range(len(tactics))] for _ in range(max_rows)]

    for col_idx, tactic in enumerate(tactics):
        techs = tech_per[tactic]
        for row_idx, (tid, tname, count) in enumerate(techs[:max_rows]):
            grid[row_idx, col_idx] = count
            labels[row_idx][col_idx] = tid

    fig_w = max(len(tactics) * 1.05, 12)
    fig_h = max(max_rows * 0.6 + 2, 5)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))

    from matplotlib.colors import LinearSegmentedColormap
    # Gradient: panel bg → primary blue → negative crimson (heat intensifies)
    cmap = LinearSegmentedColormap.from_list(
        "aurora_ops", [t["panel"], t["primary"], t["negative"]]
    )
    im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=max_count, aspect="auto")

    for r in range(max_rows):
        for c in range(len(tactics)):
            if labels[r][c]:
                ax.text(c, r, labels[r][c], ha="center", va="center",
                        color=t["text"], fontsize=7)

    ax.set_xticks(np.arange(len(tactics)))
    ax.set_xticklabels(tactics, rotation=45, ha="right", fontsize=9, color=t["text"])
    ax.set_yticks([])

    cbar = fig.colorbar(im, ax=ax, shrink=0.6, pad=0.02)
    cbar.set_label("Observations", color=t["text"], fontsize=9)
    cbar.ax.yaxis.set_tick_params(color=t["text_dim"])
    plt.setp(plt.getp(cbar.ax.axes, "yticklabels"), color=t["text_dim"])
    cbar.outline.set_edgecolor(t["grid"])

    _apply_theme(ax, fig, t, "MITRE ATT&CK — Observed Techniques by Tactic")
    ax.grid(False)
    return _save(fig, filepath, t)


def plot_hourly_trend(hourly_counts: List[int], filepath: str, theme: str = "dark") -> str:
    t = get_theme(theme)
    hours = list(range(len(hourly_counts)))

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(hours, hourly_counts, color=t["primary"], linewidth=2.2,
            marker="o", markersize=4, markerfacecolor=t["secondary"])
    ax.fill_between(hours, hourly_counts, color=t["primary"], alpha=0.18)
    ax.set_xlabel("Hour of window", fontsize=10)
    ax.set_ylabel("Attack sessions", fontsize=10)
    ax.set_xticks(range(0, len(hourly_counts), max(1, len(hourly_counts) // 12)))
    _apply_theme(ax, fig, t, "Attack Volume — Hourly Trend")
    return _save(fig, filepath, t)