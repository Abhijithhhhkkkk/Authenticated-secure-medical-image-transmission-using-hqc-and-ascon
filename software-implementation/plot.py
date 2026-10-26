#!/usr/bin/env python3
"""
Plot sender/receiver performance CSVs robustly.

Expected input: TWO separate files:
  performance_sender.csv
  performance_receiver.csv

This script also detects the specific malformed format where the sender and
receiver headers were concatenated into one line. It will not silently assign
values to incorrect columns.
"""
from pathlib import Path
import argparse
import csv
import math
import re
import sys

import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "performance_plots"


def apply_plot_style():
    """Consistent, presentation-ready Matplotlib styling."""
    plt.rcParams.update({
        "figure.dpi": 120,
        "savefig.dpi": 220,
        "font.size": 10,
        "axes.titlesize": 14,
        "axes.titleweight": "bold",
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.22,
        "grid.linestyle": "--",
        "figure.facecolor": "white",
        "axes.facecolor": "white",
    })

SENDER_COLUMNS = [
    "Image size (MB)",
    "HQC encaps time (ms)",
    "Encryption time (ms)",
    "Throughput (MB/s)",
    "Latency (ms)",
    "Overall delay (ms)",
    "Overall energy (J)",
]
RECEIVER_COLUMNS = [
    "Image size (MB)",
    "HQC decaps time (ms)",
    "Decryption time (ms)",
    "Throughput (MB/s)",
    "Overall delay (ms)",
    "Overall energy (J)",
]

SENDER_METRICS = [
    "HQC encaps time (ms)",
    "Encryption time (ms)",
    "Throughput (MB/s)",
    "Latency (ms)",
    "Overall delay (ms)",
    "Overall energy (J)",
]
RECEIVER_METRICS = [
    "HQC decaps time (ms)",
    "Decryption time (ms)",
    "Throughput (MB/s)",
    "Overall delay (ms)",
    "Overall energy (J)",
]


def normalize(text):
    return re.sub(r"\s+", " ", str(text).replace("\ufeff", "").strip()).casefold()


def find_csv(explicit, filename):
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"CSV not found: {path}")
        return path

    candidates = [
        BASE_DIR / filename,
        BASE_DIR / "sender" / filename,
        BASE_DIR / "receiver" / filename,
        Path.cwd() / filename,
        Path.cwd() / "sender" / filename,
        Path.cwd() / "receiver" / filename,
    ]
    for path in candidates:
        if path.is_file():
            return path

    matches = list(BASE_DIR.rglob(filename)) if BASE_DIR.exists() else []
    if matches:
        return matches[0]
    raise FileNotFoundError(
        f"Could not find {filename}. Put it beside this script, in sender/receiver, "
        "or pass its path with --sender / --receiver."
    )


def inspect_header(path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        first_line = f.readline().strip()
    if not first_line:
        raise ValueError(f"{path.name} is empty.")

    # Detect the exact error shown in the user's pasted text.
    if "Overall energy (J)Image size (MB)" in first_line:
        raise ValueError(
            f"\n{path}\nThe sender and receiver headers are concatenated on one line.\n"
            "They must be saved as TWO separate files: performance_sender.csv and "
            "performance_receiver.csv. Do not combine their headers."
        )


def load_csv(path, expected_columns, label):
    inspect_header(path)
    df = pd.read_csv(path, encoding="utf-8-sig", dtype=str)
    df.columns = [str(c).replace("\ufeff", "").strip() for c in df.columns]

    # Remove repeated header rows sometimes appended into the file.
    if "Image size (MB)" in df.columns:
        df = df[df["Image size (MB)"].astype(str).str.strip().str.casefold()
                != "image size (mb)"]

    # Keep known columns only; warn about missing/extra columns.
    missing = [c for c in expected_columns if c not in df.columns]
    extra = [c for c in df.columns if c not in expected_columns]
    if missing:
        print(f"WARNING ({label}): missing columns: {missing}")
    if extra:
        print(f"WARNING ({label}): unexpected columns: {extra}")

    if len(df.columns) != len(expected_columns):
        raise ValueError(
            f"{path.name} has {len(df.columns)} columns, expected "
            f"{len(expected_columns)}.\nFound: {list(df.columns)}"
        )

    # Normalize whitespace in headers, but retain original header names.
    # Convert N/A, blank, and invalid numeric cells to NaN.
    for col in df.columns:
        df[col] = pd.to_numeric(
            df[col].astype(str).str.strip().replace(
                {"": None, "N/A": None, "n/a": None, "NA": None, "nan": None}
            ),
            errors="coerce",
        )

    df = df.dropna(how="all").reset_index(drop=True)
    print(f"{label}: loaded {len(df)} data rows from {path}")
    return df


def metric_column(df, metric):
    # Match exact normalized names first.
    target = normalize(metric)
    for col in df.columns:
        if normalize(col) == target:
            return col
    return None


def plot_metric(df, metric, label, output_dir):
    """Create an individual plot for one metric."""
    col = metric_column(df, metric)
    if col is None:
        print(f"SKIP {label} / {metric}: column not found.")
        return False
    valid = df[df[col].notna()].copy()
    if valid.empty:
        print(f"SKIP {label} / {metric}: no numeric values (all blank/N/A).")
        return False
    size_col = metric_column(df, "Image size (MB)")
    labels = []
    for i, (_, row) in enumerate(valid.iterrows(), start=1):
        labels.append(f"Run {i}\\n{row[size_col]:g} MB" if size_col and pd.notna(row[size_col]) else f"Run {i}")
    values = valid[col].astype(float).tolist()
    fig, ax = plt.subplots(figsize=(9.5, 5.5), constrained_layout=True)
    bars = ax.bar(
        labels, values, width=0.62, color="#3977C3",
        edgecolor="white", linewidth=0.8, zorder=3
    )
    ax.set_title(f"{label} — {metric}", loc="left", pad=14)
    ax.set_xlabel("Experiment / image size", labelpad=9)
    ax.set_ylabel(metric, labelpad=9)
    ax.grid(axis="y", zorder=0)
    ax.set_axisbelow(True)
    ax.bar_label(bars, fmt="%.3g", padding=4, fontsize=9, fontweight="bold")
    if len(labels) > 5:
        ax.tick_params(axis="x", labelrotation=25)
    top = max(values) if values else 1
    ax.set_ylim(0, top * 1.18 if top > 0 else 1)
    safe = re.sub(r"[^A-Za-z0-9]+", "_", f"{label}_{metric}").strip("_").lower()
    fig.savefig(output_dir / f"{safe}.png", dpi=160)
    plt.close(fig)
    return True


def plot_combined_metrics(df, metrics, label, output_dir, filename):
    """Combined grouped chart; normalize each metric because units differ."""
    available = []
    for metric in metrics:
        col = metric_column(df, metric)
        if col is None:
            print(f"SKIP combined {label} / {metric}: column not found.")
            continue
        values = pd.to_numeric(df[col], errors="coerce")
        if values.notna().any():
            available.append((metric, col, values))
        else:
            print(f"SKIP combined {label} / {metric}: all values are N/A or blank.")
    if not available:
        print(f"SKIP combined {label}: no numeric metrics.")
        return False

    size_col = metric_column(df, "Image size (MB)")
    run_labels = [
        (f"Run {i}\\n{row[size_col]:g} MB" if size_col and pd.notna(row[size_col]) else f"Run {i}")
        for i, (_, row) in enumerate(df.iterrows(), start=1)
    ]
    normalized = {}
    for metric, col, values in available:
        maximum = values.abs().max(skipna=True)
        if pd.isna(maximum) or maximum == 0:
            maximum = 1.0
        normalized[metric] = values / maximum

    fig, ax = plt.subplots(
        figsize=(max(11, len(df) * 1.7), 6.8), constrained_layout=True
    )
    x = list(range(len(df)))
    group_width = 0.82
    bar_width = group_width / len(available)
    palette = ["#3977C3", "#E58B35", "#399B72", "#C65353",
               "#8768B5", "#5D9DA8", "#B07A9E"]
    for j, (metric, col, values) in enumerate(available):
        positions = [v - group_width / 2 + bar_width * (j + 0.5) for v in x]
        heights = normalized[metric].tolist()
        bars = ax.bar(
            positions, heights, width=bar_width, label=metric,
            color=palette[j % len(palette)], edgecolor="white",
            linewidth=0.6, zorder=3
        )
        # Keep labels readable: original values are shown vertically above bars.
        for k, bar in enumerate(bars):
            original = values.iloc[k]
            if pd.notna(original) and pd.notna(heights[k]):
                ax.annotate(
                    f"{float(original):.3g}",
                    (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=7, rotation=90
                )
    ax.set_title(f"{label} — Combined Performance Metrics", loc="left", pad=16)
    ax.set_xlabel("Experiment / image size", labelpad=9)
    ax.set_ylabel("Normalized value (each metric scaled to its own maximum)")
    ax.set_xticks(x)
    ax.set_xticklabels(run_labels)
    ax.set_ylim(0, 1.28)
    ax.set_axisbelow(True)
    ax.legend(
        loc="upper left", bbox_to_anchor=(1.01, 1), frameon=False,
        title="Metric", title_fontsize=9
    )
    fig.savefig(output_dir / filename, dpi=160)
    plt.close(fig)
    print(f"\\n{label} original metric values:")
    for metric, col, values in available:
        print(f"  {metric}: {values.tolist()}")
    return True

def plot_paired_metric(sender, receiver, sender_metric, receiver_metric,
                       title, ylabel, output_dir, filename):
    """Plot corresponding sender and receiver measurements side by side per run."""
    sender_col = metric_column(sender, sender_metric) if sender_metric else None
    receiver_col = metric_column(receiver, receiver_metric) if receiver_metric else None

    if sender_col is None and receiver_col is None:
        print(f"SKIP {title}: neither metric column exists.")
        return False

    # Use image size as the matching key when possible; otherwise align by row/run.
    def rows_for(df, col):
        if col is None:
            return {}
        size_col = metric_column(df, "Image size (MB)")
        result = {}
        for idx, (_, row) in enumerate(df.iterrows(), start=1):
            val = pd.to_numeric(pd.Series([row[col]]), errors="coerce").iloc[0]
            if pd.isna(val):
                continue
            size = pd.to_numeric(pd.Series([row[size_col]]), errors="coerce").iloc[0] if size_col else float("nan")
            key = round(float(size), 6) if pd.notna(size) else ("run", idx)
            # Preserve repeated sizes by using an occurrence number.
            if key in result:
                key = (key, idx)
            result[key] = (idx, float(val), float(size) if pd.notna(size) else float("nan"))
        return result

    s_rows = rows_for(sender, sender_col)
    r_rows = rows_for(receiver, receiver_col)

    # Pair by image size when both sides have sizes; if not, pair by run order.
    if s_rows and r_rows:
        s_has_sizes = all(not isinstance(k, tuple) or (isinstance(k[0], str) and k[0] == "run") for k in s_rows)
        # Build robust lists and pair by matching image-size values, preserving duplicates.
        def make_list(df, col):
            if col is None:
                return []
            size_col = metric_column(df, "Image size (MB)")
            out = []
            for idx, (_, row) in enumerate(df.iterrows(), start=1):
                value = pd.to_numeric(pd.Series([row[col]]), errors="coerce").iloc[0]
                if pd.isna(value):
                    continue
                size = pd.to_numeric(pd.Series([row[size_col]]), errors="coerce").iloc[0] if size_col else float("nan")
                out.append({"run": idx, "size": float(size) if pd.notna(size) else float("nan"), "value": float(value)})
            return out

        s_list, r_list = make_list(sender, sender_col), make_list(receiver, receiver_col)
        pairs = []
        used = set()
        for s in s_list:
            match = None
            if pd.notna(s["size"]):
                for j, r in enumerate(r_list):
                    if j not in used and pd.notna(r["size"]) and abs(s["size"] - r["size"]) < 1e-5:
                        match = (j, r)
                        break
            if match is None and len(s_list) == len(r_list):
                j = s["run"] - 1
                if j < len(r_list) and j not in used:
                    match = (j, r_list[j])
            if match:
                j, r = match
                used.add(j)
                pairs.append((f'{s["size"]:g} MB' if pd.notna(s["size"]) else f'Run {s["run"]}', s["value"], r["value"]))
        # If only one side has data, still plot its values rather than hiding them.
        if not pairs:
            max_len = max(len(s_list), len(r_list))
            for i in range(max_len):
                s = s_list[i] if i < len(s_list) else None
                r = r_list[i] if i < len(r_list) else None
                size = s["size"] if s and pd.notna(s["size"]) else (r["size"] if r and pd.notna(r["size"]) else float("nan"))
                label = f"{size:g} MB" if pd.notna(size) else f"Run {i+1}"
                pairs.append((label, s["value"] if s else float("nan"), r["value"] if r else float("nan")))
    else:
        s_list = []
        r_list = []
        for df, col, dest in ((sender, sender_col, s_list), (receiver, receiver_col, r_list)):
            if col is None:
                continue
            for _, row in df.iterrows():
                val = pd.to_numeric(pd.Series([row[col]]), errors="coerce").iloc[0]
                if pd.notna(val):
                    dest.append(float(val))
        pairs = []
        for i in range(max(len(s_list), len(r_list))):
            pairs.append((f"Run {i+1}", s_list[i] if i < len(s_list) else float("nan"),
                          r_list[i] if i < len(r_list) else float("nan")))

    if not pairs:
        print(f"SKIP {title}: no numeric values.")
        return False

    labels = [p[0] for p in pairs]
    s_values = [p[1] for p in pairs]
    r_values = [p[2] for p in pairs]
    x = list(range(len(pairs)))
    width = 0.36

    fig, ax = plt.subplots(figsize=(max(9, len(pairs) * 1.5), 5.5), constrained_layout=True)
    palette_sender, palette_receiver = "#3977C3", "#E58B35"
    if sender_col is not None:
        bars = ax.bar([v - width/2 for v in x], s_values, width, label="Sender",
                      color=palette_sender, edgecolor="white", linewidth=0.8, zorder=3)
        for bar, val in zip(bars, s_values):
            if pd.notna(val):
                ax.annotate(f"{val:.3g}", (bar.get_x()+bar.get_width()/2, bar.get_height()),
                            xytext=(0, 4), textcoords="offset points", ha="center",
                            va="bottom", fontsize=8, fontweight="bold")
    if receiver_col is not None:
        bars = ax.bar([v + width/2 for v in x], r_values, width, label="Receiver",
                      color=palette_receiver, edgecolor="white", linewidth=0.8, zorder=3)
        for bar, val in zip(bars, r_values):
            if pd.notna(val):
                ax.annotate(f"{val:.3g}", (bar.get_x()+bar.get_width()/2, bar.get_height()),
                            xytext=(0, 4), textcoords="offset points", ha="center",
                            va="bottom", fontsize=8, fontweight="bold")

    ax.set_title(title, loc="left", pad=14)
    ax.set_xlabel("Image size / experiment", labelpad=9)
    ax.set_ylabel(ylabel, labelpad=9)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_axisbelow(True)
    ax.grid(axis="y", zorder=0)
    ax.legend(frameon=False)
    max_val = max([v for v in s_values + r_values if pd.notna(v)], default=1)
    ax.set_ylim(0, max_val * 1.2 if max_val > 0 else 1)
    fig.savefig(output_dir / filename, dpi=220)
    plt.close(fig)
    return True


def plot_combined_delay(sender, receiver, output_dir):
    series = []
    for label, df in (("Sender", sender), ("Receiver", receiver)):
        col = metric_column(df, "Overall delay (ms)")
        if col:
            valid = df[df[col].notna()]
            for i, value in enumerate(valid[col], start=1):
                size_col = metric_column(df, "Image size (MB)")
                size = valid.iloc[i - 1][size_col] if size_col else float("nan")
                run_label = f"{label} {i}"
                if pd.notna(size):
                    run_label += f"\n{size:g} MB"
                series.append((run_label, float(value)))

    if not series:
        print("SKIP combined overall delay: no numeric values.")
        return False

    labels = [item[0] for item in series]
    values = [item[1] for item in series]
    fig, ax = plt.subplots(figsize=(10, 5.5), constrained_layout=True)
    colors = ["#3977C3" if label.startswith("Sender") else "#E58B35"
              for label in labels]
    bars = ax.bar(
        labels, values, width=0.62, color=colors,
        edgecolor="white", linewidth=0.8, zorder=3
    )
    ax.set_title("Overall Delay — Sender vs Receiver", loc="left", pad=14)
    ax.set_xlabel("Device / experiment", labelpad=9)
    ax.set_ylabel("Overall delay (ms)", labelpad=9)
    ax.set_axisbelow(True)
    ax.bar_label(bars, fmt="%.3g", padding=4, fontsize=9, fontweight="bold")
    top = max(values) if values else 1
    ax.set_ylim(0, top * 1.18 if top > 0 else 1)
    fig.savefig(output_dir / "combined_overall_delay.png", dpi=160)
    plt.close(fig)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", help="Path to performance_sender.csv")
    parser.add_argument("--receiver", help="Path to performance_receiver.csv")
    args = parser.parse_args()

    try:
        sender_path = find_csv(args.sender, "performance_sender.csv")
        receiver_path = find_csv(args.receiver, "performance_receiver.csv")
        sender = load_csv(sender_path, SENDER_COLUMNS, "SENDER")
        receiver = load_csv(receiver_path, RECEIVER_COLUMNS, "RECEIVER")
    except (FileNotFoundError, ValueError, pd.errors.ParserError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        print(
            "\nFix: keep the sender and receiver logs in separate CSV files. "
            "Each file must have one header row and each data row must have the "
            "same number of values as its header.",
            file=sys.stderr,
        )
        sys.exit(2)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    apply_plot_style()
    made = 0

    # Individual plots for detailed analysis.
    for metric in SENDER_METRICS:
        made += plot_metric(sender, metric, "Sender", OUTPUT_DIR)
    for metric in RECEIVER_METRICS:
        made += plot_metric(receiver, metric, "Receiver", OUTPUT_DIR)

    # Pair related sender and receiver metrics in the SAME chart:
    # sender encryption vs receiver decryption, HQC encapsulation vs decapsulation,
    # and sender vs receiver throughput / overall delay / energy where available.
    made += plot_paired_metric(
        sender, receiver, "Encryption time (ms)", "Decryption time (ms)",
        "Encryption vs Decryption Time", "Time (ms)", OUTPUT_DIR,
        "encryption_vs_decryption.png"
    )
    made += plot_paired_metric(
        sender, receiver, "HQC encaps time (ms)", "HQC decaps time (ms)",
        "HQC Encapsulation vs Decapsulation Time", "Time (ms)", OUTPUT_DIR,
        "hqc_encapsulation_vs_decapsulation.png"
    )
    made += plot_paired_metric(
        sender, receiver, "Throughput (MB/s)", "Throughput (MB/s)",
        "Sender vs Receiver Throughput", "Throughput (MB/s)", OUTPUT_DIR,
        "sender_vs_receiver_throughput.png"
    )
    made += plot_paired_metric(
        sender, receiver, "Overall delay (ms)", "Overall delay (ms)",
        "Sender vs Receiver Overall Delay", "Overall delay (ms)", OUTPUT_DIR,
        "sender_vs_receiver_overall_delay.png"
    )
    made += plot_paired_metric(
        sender, receiver, "Overall energy (J)", "Overall energy (J)",
        "Sender vs Receiver Overall Energy", "Overall energy (J)", OUTPUT_DIR,
        "sender_vs_receiver_overall_energy.png"
    )
    made += plot_paired_metric(
        sender, receiver, "Latency (ms)", None,
        "Sender Latency", "Latency (ms)", OUTPUT_DIR,
        "sender_latency.png"
    )

    print(f"\\nCreated {made} plot(s) in: {OUTPUT_DIR}")
    if made == 0:
        print("No plots were generated because no valid numeric metric values were found.")


if __name__ == "__main__":
    main()
