#!/usr/bin/env python3
"""
Generate Chapter 4 evaluation figures for the ARGUS final report.

Produces six print-ready PNG figures at 150 DPI on a white background,
sized for single-column insertion in a Word document.

All values are hard-coded from the frozen evaluation dataset (1 Aug 2026,
01:35 +08) so the figures are reproducible without a live Elasticsearch
connection or a running sensor instance.

Usage:
    python make_ch4_figures.py                  # writes to ./ch4_figures/
    python make_ch4_figures.py --out /some/dir  # custom output directory

Requires only matplotlib, already present in the analyzer virtual
environment. No network access and no Elasticsearch connection.
"""
# RUN ON: WSL2 operator workstation
# NETWORK: none required — no external calls, no ES query
# BLAST RADIUS: writes PNG files to the output directory only

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


# ------------------------------------------------------------------ style
DPI = 150
FIGSIZE_WIDE = (9.0, 4.6)
FIGSIZE_SQUARE = (7.2, 5.2)

INK = "#1A1A2E"
MUTED = "#6B7280"
GRID = "#D8DCE6"

PRIMARY = "#2F5FD0"
SECONDARY = "#7C5CD6"
ACCENT = "#0E9F6E"
WARN = "#D97706"
DANGER = "#C0392B"
NEUTRAL = "#9AA3B2"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "font.family": "DejaVu Sans",
    "font.size": 10.5,
    "axes.labelcolor": INK,
    "axes.edgecolor": GRID,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.titlecolor": INK,
    "text.color": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.7,
    "grid.alpha": 0.8,
    "axes.axisbelow": True,
})

_thousands = FuncFormatter(lambda v, _: f"{int(v):,}")


def _despine(ax, keep_left=True):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    if not keep_left:
        ax.spines["left"].set_visible(False)


def _save(fig, out_dir: Path, name: str):
    path = out_dir / name
    fig.tight_layout()
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {path.name}")


# ------------------------------------------------------------------ fig 1
def fig_population_filtering(out_dir: Path):
    """Raw indexed events split into excluded infrastructure and external."""
    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)

    external, excluded = 144_020, 85_463

    ax.barh([0], [external], color=PRIMARY, height=0.5,
            label=f"External sources  {external:,}  (62.76%)")
    ax.barh([0], [excluded], left=[external], color=NEUTRAL, height=0.5,
            label=f"Excluded infrastructure  {excluded:,}  (37.24%)")

    ax.text(external / 2, 0, f"{external:,}", ha="center", va="center",
            color="white", fontweight="bold", fontsize=12)
    ax.text(external + excluded / 2, 0, f"{excluded:,}", ha="center",
            va="center", color="white", fontweight="bold", fontsize=12)

    ax.set_yticks([])
    ax.set_xlim(0, 229_483 * 1.02)
    ax.xaxis.set_major_formatter(_thousands)
    ax.set_xlabel("Indexed events")
    ax.set_title("Population filtering: 229,483 raw indexed events")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22),
              ncol=2, frameon=False)
    ax.grid(axis="y", visible=False)
    _despine(ax, keep_left=False)

    _save(fig, out_dir, "fig4-1_population_filtering.png")


# ------------------------------------------------------------------ fig 2
def fig_collection_days(out_dir: Path):
    """Indexed events per discrete collection day."""
    days = ["2 Jul", "3 Jul", "5 Jul", "6 Jul", "7 Jul",
            "9 Jul", "13 Jul", "14 Jul", "31 Jul"]
    counts = [10_713, 336, 29_680, 128_886, 34_168, 659, 1_099, 1_793, 6_176]

    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)
    colors = [PRIMARY if c < 100_000 else SECONDARY for c in counts]
    bars = ax.bar(days, counts, color=colors, width=0.62)

    for bar, c in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, c + 2_600, f"{c:,}",
                ha="center", va="bottom", fontsize=9, color=INK)

    ax.set_ylabel("Indexed events")
    ax.set_ylim(0, max(counts) * 1.16)
    ax.yaxis.set_major_formatter(_thousands)
    ax.set_title("Event volume across nine discrete collection days")
    ax.grid(axis="x", visible=False)
    _despine(ax)

    ax.annotate("60.4% of all indexed events",
                xy=(3, 128_886), xytext=(4.6, 112_000),
                fontsize=9.5, color=SECONDARY,
                arrowprops=dict(arrowstyle="->", color=SECONDARY, lw=1.3))

    _save(fig, out_dir, "fig4-2_collection_days.png")


# ------------------------------------------------------------------ fig 3
def fig_stratum_comparison(out_dir: Path):
    """Stratum A vs Stratum B corroboration rates."""
    labels = ["Abuse confidence\n≥ 80", "Vendor detections\n≥ 1",
              "Corroborated by\n≥ 1 feed"]
    stratum_a = [49, 77, 77]
    stratum_b = [65, 91, 93]

    x = range(len(labels))
    w = 0.36

    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)
    b1 = ax.bar([i - w / 2 for i in x], stratum_a, w, color=NEUTRAL,
                label="Stratum A — top 100 by volume (mean 1,270 sessions)")
    b2 = ax.bar([i + w / 2 for i in x], stratum_b, w, color=PRIMARY,
                label="Stratum B — 100 random tail (mean 13 sessions)")

    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1.6, f"{h}%",
                    ha="center", va="bottom", fontsize=10, color=INK)

    for i, (a, b) in enumerate(zip(stratum_a, stratum_b)):
        ax.text(i, max(a, b) + 9, f"+{b - a} pp", ha="center",
                fontsize=9.5, color=ACCENT, fontweight="bold")

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Percentage of stratum (N = 100 each)")
    ax.set_ylim(0, 112)
    ax.set_title("Corroboration by stratum: the low-volume tail is flagged more often")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16),
              ncol=1, frameon=False, fontsize=9.5)
    ax.grid(axis="x", visible=False)
    _despine(ax)

    _save(fig, out_dir, "fig4-3_stratum_comparison.png")


# ------------------------------------------------------------------ fig 4
def fig_cross_feed(out_dir: Path):
    """Cross-feed agreement over the 200-address sample."""
    fig, ax = plt.subplots(figsize=FIGSIZE_SQUARE)

    segments = [
        ("Both feeds", 126, PRIMARY),
        ("Vendor classification only", 42, SECONDARY),
        ("Abuse reporting only", 2, ACCENT),
        ("Neither feed", 30, NEUTRAL),
    ]

    wedges, _ = ax.pie(
        [s[1] for s in segments],
        colors=[s[2] for s in segments],
        startangle=90, counterclock=False,
        wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2),
    )

    ax.text(0, 0.10, "170", ha="center", va="center",
            fontsize=30, fontweight="bold", color=INK)
    ax.text(0, -0.16, "of 200 corroborated", ha="center", va="center",
            fontsize=11, color=MUTED)
    ax.text(0, -0.34, "85.0%", ha="center", va="center",
            fontsize=13, fontweight="bold", color=PRIMARY)

    ax.legend(wedges,
              [f"{lbl} — {cnt} ({100 * cnt / 200:.1f}%)"
               for lbl, cnt, _ in segments],
              loc="upper center", bbox_to_anchor=(0.5, -0.02),
              ncol=1, frameon=False, fontsize=9.5)
    ax.set_title("Cross-feed agreement over 200 sampled source addresses")

    _save(fig, out_dir, "fig4-4_cross_feed_agreement.png")


# ------------------------------------------------------------------ fig 5
def fig_rule_census(out_dir: Path):
    """Rule census outcome across the 42-rule classification set."""
    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)

    correct, broad, incorrect = 32, 9, 1

    ax.barh([0], [correct], color=ACCENT, height=0.5,
            label=f"Correct and appropriately scoped — {correct} (76.2%)")
    ax.barh([0], [broad], left=[correct], color=WARN, height=0.5,
            label=f"Correct identifier, over-broad pattern — {broad} (21.4%)")
    ax.barh([0], [incorrect], left=[correct + broad], color=DANGER, height=0.5,
            label=f"Incorrect technique identifier — {incorrect} (2.4%)")

    ax.text(correct / 2, 0, "32", ha="center", va="center",
            color="white", fontweight="bold", fontsize=13)
    ax.text(correct + broad / 2, 0, "9", ha="center", va="center",
            color="white", fontweight="bold", fontsize=12)

    ax.set_yticks([])
    ax.set_xlim(0, 42)
    ax.set_xlabel("Classification rules (census of all 42)")
    ax.set_title("Rule census: 97.6% assign the correct technique identifier")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.24),
              ncol=1, frameon=False, fontsize=9.5)
    ax.grid(axis="y", visible=False)
    _despine(ax, keep_left=False)

    _save(fig, out_dir, "fig4-5_rule_census.png")


# ------------------------------------------------------------------ fig 6
def fig_pipeline_timing(out_dir: Path):
    """Report generation elapsed time across all recorded invocations."""
    labels = ["stub\ndaily/brief", "daily\nbrief", "daily\nfull",
              "weekly\nbrief", "weekly\nfull", "monthly\nfull(d)",
              "monthly\nfull(l)"]
    totals = [23.557, 42.731, 15.295, 8.490, 13.269, 16.249, 27.699]
    pdfs = [8.303, 4.027, 4.301, 3.510, 4.261, 4.781, 5.221]

    mean_total = sum(totals) / len(totals)

    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)
    x = range(len(labels))

    ax.bar(x, totals, 0.6, color=PRIMARY, label="Total elapsed time")
    ax.bar(x, pdfs, 0.6, color=SECONDARY, label="of which PDF conversion")

    for i, t in enumerate(totals):
        ax.text(i, t + 0.9, f"{t:.1f}s", ha="center", va="bottom",
                fontsize=9, color=INK)

    ax.axhline(mean_total, color=ACCENT, linestyle="--", linewidth=1.5,
               label=f"Mean {mean_total:.2f}s")

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Elapsed time (seconds)")
    ax.set_ylim(0, max(totals) * 1.20)
    ax.set_title("Report generation time across 7 invocations, all successful")
    ax.legend(loc="upper right", frameon=False, fontsize=9.5)
    ax.grid(axis="x", visible=False)
    _despine(ax)

    _save(fig, out_dir, "fig4-6_pipeline_timing.png")


# ------------------------------------------------------------------ main
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Chapter 4 evaluation figures for the ARGUS report"
    )
    parser.add_argument("--out", default="ch4_figures",
                        help="Output directory (default: ./ch4_figures)")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Writing Chapter 4 figures to {out_dir.resolve()}")
    fig_population_filtering(out_dir)
    fig_collection_days(out_dir)
    fig_stratum_comparison(out_dir)
    fig_cross_feed(out_dir)
    fig_rule_census(out_dir)
    fig_pipeline_timing(out_dir)
    print("\nDone. Six figures written at 150 DPI on white background.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
