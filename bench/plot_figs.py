from __future__ import annotations

import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

plt.rcParams.update({
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "legend.fontsize": 10,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
})

SUMMARY_PATH = "bench/outputs/summary_all_sec128_v2.csv"
OUT_DIR = "bench/figures"

# ---- NEW: hatch/line style maps (BW-friendly) ----
HATCHES = {
    "schnorr": "///",
    "gq": "\\\\\\",
    "bls": "xx",
}
LINESTYLES = {
    "schnorr": ("-", "o"),
    "gq": ("--", "s"),
    "bls": (":", "^"),
}


def ns_to_ms(ns: float) -> float:
    return ns / 1e6


def _load_summary():
    df = pd.read_csv(SUMMARY_PATH)

    op_order = ["Setup", "iCertGen", "SKGen", "PKRecon"]
    scheme_order = ["schnorr", "gq", "bls"]

    df["op"] = pd.Categorical(df["op"], categories=op_order, ordered=True)
    df["scheme"] = pd.Categorical(df["scheme"], categories=scheme_order, ordered=True)
    df = df.sort_values(["op", "scheme"])
    return df


def _save(fig, stem: str):
    os.makedirs(OUT_DIR, exist_ok=True)
    pdf_path = os.path.join(OUT_DIR, f"{stem}.pdf")
    png_path = os.path.join(OUT_DIR, f"{stem}.png")
    fig.savefig(pdf_path)
    fig.savefig(png_path, dpi=300)
    plt.close(fig)
    print(f"[{stem}] Saved to {pdf_path} and {png_path}")


# ---- NEW: helper to apply hatches + BW-friendly legend ----
def _apply_hatches_and_bw_legend(ax: plt.Axes, schemes_in_order: list[str], legend_title: str = "Scheme"):
    # Pandas bar/barh creates one container per column (= per scheme)
    for i, cont in enumerate(ax.containers):
        if i >= len(schemes_in_order):
            break
        scheme = schemes_in_order[i]
        hatch = HATCHES.get(scheme, "")
        for p in cont.patches:
            p.set_hatch(hatch)
            p.set_edgecolor("black")
            p.set_linewidth(0.8)

    # Replace legend with hatch-based handles (so legend still works in BW)
    handles = [
        Patch(facecolor="white", edgecolor="black", hatch=HATCHES.get(s, ""), label=s)
        for s in schemes_in_order
    ]
    ax.legend(handles=handles, title=legend_title, frameon=False)


def plot_fig1_cost_breakdown():
    df = _load_summary()
    df["mean_ms"] = df["mean_ns"].apply(ns_to_ms)
    pivot = df.pivot(index="op", columns="scheme", values="mean_ms")

    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    pivot.plot(kind="bar", ax=ax, width=0.75)

    ax.set_ylabel("Latency (ms)")
    ax.set_xlabel("")
    ax.set_title("Cost Breakdown of Implicit-Certificate Operations (Mean)")
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.7)

    # NEW
    _apply_hatches_and_bw_legend(ax, [str(c) for c in pivot.columns], legend_title="Scheme")

    fig.tight_layout()
    _save(fig, "fig1_cost_breakdown")


def plot_fig2_tail_latency_p95():
    df = _load_summary()
    df["p95_ms"] = df["p95_ns"].apply(ns_to_ms)
    pivot = df.pivot(index="op", columns="scheme", values="p95_ms")

    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    pivot.plot(kind="bar", ax=ax, width=0.75)

    ax.set_ylabel("Latency (ms)")
    ax.set_xlabel("")
    ax.set_title("Tail Latency of Implicit-Certificate Operations (p95)")
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.7)

    # NEW
    _apply_hatches_and_bw_legend(ax, [str(c) for c in pivot.columns], legend_title="Scheme")

    fig.tight_layout()
    _save(fig, "fig2_tail_latency_p95")


def plot_fig3_size_footprint():
    """
    Fig.3: Size footprint (bytes) of iCer / pk / sk for each instantiation.
    Sizes are constant across ops in the summary; we use iCertGen rows.
    """
    df = _load_summary()

    sub = df[df["op"] == "iCertGen"][["scheme", "icert_len_bytes", "pk_len_bytes", "sk_len_bytes"]].copy()
    sub = sub.sort_values("scheme")

    metrics = ["icert_len_bytes", "pk_len_bytes", "sk_len_bytes"]
    labels = ["|iCer|", "|pk|", "|sk|"]

    pivot = sub.set_index("scheme")[metrics]

    fig, ax = plt.subplots(figsize=(6.8, 3.6))
    pivot.rename(columns=dict(zip(metrics, labels))).plot(kind="barh", ax=ax)

    ax.set_xlabel("Size (bytes)")
    ax.set_ylabel("")
    ax.set_title("Size Footprint of Public Materials and Keys")
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.7)

    # NEW: apply hatches per *metric* (because barh columns are |iCer|,|pk|,|sk|)
    metric_hatches = {"|iCer|": "///", "|pk|": "\\\\\\", "|sk|": "xx"}
    for i, cont in enumerate(ax.containers):
        # container order matches columns order in the plotted data
        if i >= len(pivot.columns):
            break
        col = labels[i]
        hatch = metric_hatches.get(col, "")
        for p in cont.patches:
            p.set_hatch(hatch)
            p.set_edgecolor("black")
            p.set_linewidth(0.8)

    handles = [
        Patch(facecolor="white", edgecolor="black", hatch=metric_hatches[l], label=l)
        for l in labels
    ]
    ax.legend(handles=handles, title="", frameon=False)

    fig.tight_layout()
    _save(fig, "fig3_size_footprint")


def plot_fig4_scale_out_model():
    """
    Fig.4: Model-based scale-out analysis.
    Total public material size vs. number of devices.

    Model:
      Per device public material = |iCer| + |pk|
      (sk is excluded since it is not distributed/stored publicly)
    """
    df = _load_summary()

    sub = df[df["op"] == "iCertGen"][["scheme", "icert_len_bytes", "pk_len_bytes"]].copy()
    sub["per_device_bytes"] = sub["icert_len_bytes"] + sub["pk_len_bytes"]
    sub = sub.sort_values("scheme")

    devices = np.array([1e3, 1e4, 1e5, 1e6], dtype=float)

    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    for _, row in sub.iterrows():
        scheme = str(row["scheme"])
        per_dev = float(row["per_device_bytes"])
        total_mb = (devices * per_dev) / (1024.0 * 1024.0)

        ls, mk = LINESTYLES.get(scheme, ("-", "o"))
        ax.plot(
            devices,
            total_mb,
            linestyle=ls,
            marker=mk,
            markerfacecolor="none",   # BW-friendly
            markeredgecolor="black",
            label=scheme,
        )

    ax.set_xscale("log")
    ax.set_xlabel("Number of Devices")
    ax.set_ylabel("Total Public Material (MB)")
    ax.set_title("Scale-out Deployment Model (|iCer| + |pk| per Device)")
    ax.legend(title="Scheme", frameon=False)

    ax.grid(True, which="both", linestyle="--", linewidth=0.5, alpha=0.7)
    fig.tight_layout()
    _save(fig, "fig4_scale_out_model")


def main():
    plot_fig1_cost_breakdown()
    plot_fig2_tail_latency_p95()
    plot_fig3_size_footprint()
    plot_fig4_scale_out_model()


if __name__ == "__main__":
    main()
