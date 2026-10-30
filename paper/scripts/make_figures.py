"""Generate the data-driven figures of the review (Figs. 1-3) as vector PDFs.

Every value is read from ../data/*.csv, whose header comments cite the source table.
Run from any directory:  python paper/scripts/make_figures.py
"""

import csv
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA, OUT = ROOT / "data", ROOT / "figures"
OUT.mkdir(exist_ok=True)

# IEEE single column is 3.5 in wide; keep text at 8 pt so it matches the caption size.
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.spines.top": False,
    "axes.spines.right": False, "pdf.fonttype": 42, "savefig.bbox": "tight",
})
GREYS = ["#bdbdbd", "#737373", "#252525"]


def read_csv(name):
    with open(DATA / name, encoding="utf-8") as handle:
        return list(csv.DictReader(line for line in handle if not line.startswith("#")))


def fig1_publication_years():
    years = Counter(int(row["year"]) for row in read_csv("fig1_included_studies.csv"))
    labels = ["<2015"] + [str(y) for y in range(2015, 2026)]
    counts = [sum(c for y, c in years.items() if y < 2015)] + [years.get(y, 0) for y in range(2015, 2026)]
    fig, ax = plt.subplots(figsize=(3.5, 1.7))
    bars = ax.bar(labels, counts, color=GREYS[1], width=0.7)
    ax.bar_label(bars, padding=1, fontsize=6.5)
    ax.set_ylabel("Included sources")
    ax.set_xlabel("Publication year")
    ax.set_ylim(0, max(counts) + 2)
    ax.tick_params(axis="x", rotation=45)
    fig.savefig(OUT / "fig1_publication_years.pdf")
    plt.close(fig)


def fig2_feature_sets():
    rows = read_csv("fig2_feature_sets_f1.csv")
    datasets = list(dict.fromkeys(r["dataset"] for r in rows))
    sets = [("original", "Original features"), ("netflow_basic", "NetFlow basic"),
            ("netflow_extended", "NetFlow extended")]
    lookup = {(r["dataset"], r["feature_set"]): r for r in rows}
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(3.5, 2.9), sharex=True)
    width = 0.26
    for i, (key, label) in enumerate(sets):
        xs = [d + (i - 1) * width for d in range(len(datasets))]
        ax1.bar(xs, [float(lookup[(d, key)]["f1"]) for d in datasets], width, label=label,
                color=GREYS[i], edgecolor="black", linewidth=0.3)
        ax2.bar(xs, [float(lookup[(d, key)]["far_pct"]) for d in datasets], width,
                color=GREYS[i], edgecolor="black", linewidth=0.3)
    ax1.set_ylabel("F1-score")
    ax1.set_ylim(0.75, 1.02)
    ax1.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.25), frameon=False)
    ax2.set_ylabel("False alarm rate (%)")
    ax2.set_xticks(range(len(datasets)), datasets)
    fig.savefig(OUT / "fig2_feature_sets.pdf")
    plt.close(fig)


def fig3_class_imbalance():
    rows = read_csv("fig3_unsw_nb15_classes.csv")
    names = [r["class"] for r in rows]
    records = [int(r["records"]) for r in rows]
    f1 = [float(r["f1_original"]) for r in rows]
    fig, ax = plt.subplots(figsize=(3.5, 2.1))
    ax.bar(names, records, color=GREYS[0], edgecolor="black", linewidth=0.3, label="Records (log scale)")
    ax.set_yscale("log")
    ax.set_ylabel("Records in data set")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
    ax2 = ax.twinx()
    ax2.plot(names, f1, color="black", marker="o", markersize=3, linewidth=1, label="Per-class F1")
    ax2.axhline(0.98, color="black", linestyle="--", linewidth=0.7)
    ax2.text(len(names) - 0.6, 0.95, "weighted F1 = 0.98", ha="right", va="top", fontsize=6.5)
    ax2.set_ylim(0, 1.05)
    ax2.set_ylabel("F1-score")
    ax2.spines["right"].set_visible(True)
    handles = ax.get_legend_handles_labels()[0] + ax2.get_legend_handles_labels()[0]
    ax.legend(handles, ["Records (log scale)", "Per-class F1"], ncol=2, loc="upper center",
              bbox_to_anchor=(0.5, 1.16), frameon=False)
    fig.savefig(OUT / "fig3_class_imbalance.pdf")
    plt.close(fig)


def fig_results_comparison():
    rows = read_csv("fig_results_comparison.csv")
    labels = [r["label"] for r in rows]
    y = range(len(rows))
    fig, ax = plt.subplots(figsize=(3.5, 2.4))
    ax.barh([i - 0.18 for i in y], [float(r["headline"]) for r in rows], 0.34, color=GREYS[2], label="Headline result")
    ax.barh([i + 0.18 for i in y], [float(r["stricter"]) for r in rows], 0.34, color=GREYS[0],
            edgecolor="black", linewidth=0.3, label="Stricter view")
    ax.set_yticks(list(y), labels, fontsize=6)
    ax.invert_yaxis()
    ax.set_xlim(0, 105)
    ax.set_xlabel("Reported score (%)")
    ax.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.15), frameon=False)
    fig.savefig(OUT / "fig_results_comparison.pdf")
    plt.close(fig)


if __name__ == "__main__":
    fig1_publication_years()
    fig2_feature_sets()
    fig3_class_imbalance()
    fig_results_comparison()
    print("Figures written to", OUT)
