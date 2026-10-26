import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Main project directory (where this script is located)
BASE_DIR = Path(__file__).resolve().parent

SENDER_NAME = "performance_sender.csv"
RECEIVER_NAME = "performance_receiver.csv"


def find_csv(name):
    """medical_peer.py writes the CSV into the folder it was run from,
    so look in the usual places, then search below this script's folder."""
    candidates = [
        BASE_DIR / name,
        BASE_DIR / "sender" / name,
        BASE_DIR / "receiver" / name,
        Path.cwd() / name,
    ]
    for path in candidates:
        if path.is_file():
            return path
    for path in BASE_DIR.rglob(name):
        return path
    return None

# Folder for saving plots
PLOT_DIR = BASE_DIR / "performance_plots"
PLOT_DIR.mkdir(exist_ok=True)


def load_csv(path):
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    df = pd.read_csv(path)

    # Remove repeated header rows if present.
    first = df.iloc[:, 0].astype(str).str.strip().str.lower()
    df = df[~first.str.startswith("image size")].copy()

    # Convert columns to numeric values ("N/A" energy values become NaN).
    for column in df.columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df.dropna(how="all", inplace=True)
    return df.reset_index(drop=True)


def find_col(df, prefix):
    """Return the column whose name starts with prefix (ignores the unit suffix)."""
    for column in df.columns:
        if str(column).strip().lower().startswith(prefix.lower()):
            return column
    return None


def plot_bar(df, y_prefix, title, ylabel, filename):
    x_column = find_col(df, "Image size")
    y_column = find_col(df, y_prefix)
    if x_column is None or y_column is None:
        print(f"Skipping {title}: column '{y_prefix}' not found in CSV.")
        return

    # Ignore rows missing the values required for this plot.
    data = df[[x_column, y_column]].dropna().reset_index(drop=True)
    if data.empty:
        print(f"Skipping {title}: no valid data.")
        return

    # Measurement order is the category, so repeated image sizes are preserved.
    labels = [f"{size:.3f} MB\nRun {i + 1}" for i, size in enumerate(data[x_column])]
    x = np.arange(len(data))

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(x, data[y_column])

    ax.set_title(title)
    ax.set_xlabel("Image size / experiment")
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.bar_label(bars, fmt="%.3f", padding=3)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    output_path = PLOT_DIR / filename
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {output_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sender", type=Path, help="path to performance_sender.csv")
    parser.add_argument("--receiver", type=Path, help="path to performance_receiver.csv")
    args = parser.parse_args()

    sender_path = args.sender or find_csv(SENDER_NAME)
    receiver_path = args.receiver or find_csv(RECEIVER_NAME)

    # Each device only produces one of the two files, so a missing one is skipped.
    sender = load_csv(sender_path) if sender_path else None
    receiver = load_csv(receiver_path) if receiver_path else None
    print(f"Sender CSV  : {sender_path or 'NOT FOUND (sender plots skipped)'}")
    print(f"Receiver CSV: {receiver_path or 'NOT FOUND (receiver plots skipped)'}")
    if sender is None and receiver is None:
        print(f"\nNo CSV files found. Looked for {SENDER_NAME} / {RECEIVER_NAME} in "
              f"{BASE_DIR} and below, and in {Path.cwd()}.\n"
              "Pass them explicitly: python plot_performance.py --sender <file> --receiver <file>")
        return

    # ---------------- SENDER PLOTS ----------------
    if sender is not None:
        plot_sender(sender)
    if receiver is not None:
        plot_receiver(receiver)

    print("\nDone.")


def plot_sender(sender):
    plot_bar(sender, "HQC encaps time", "Sender: HQC Encapsulation Time",
             "Time (ms)", "sender_hqc_encapsulation.png")
    plot_bar(sender, "Encryption time", "Sender: Ascon Encryption Time",
             "Time (ms)", "sender_encryption_time.png")
    plot_bar(sender, "Throughput", "Sender: Encryption Throughput",
             "Throughput (MB/s)", "sender_encryption_throughput.png")
    plot_bar(sender, "Latency", "Sender: Delivery Latency",
             "Latency (ms)", "sender_latency.png")
    plot_bar(sender, "Overall delay", "Sender: Overall Send Delay",
             "Delay (ms)", "sender_overall_delay.png")
    plot_bar(sender, "Overall energy", "Sender: Overall Energy",
             "Energy (J)", "sender_overall_energy.png")



def plot_receiver(receiver):
    plot_bar(receiver, "HQC decaps time", "Receiver: HQC Decapsulation Time",
             "Time (ms)", "receiver_hqc_decapsulation.png")
    plot_bar(receiver, "Decryption time", "Receiver: Ascon Decryption Time",
             "Time (ms)", "receiver_decryption_time.png")
    plot_bar(receiver, "Throughput", "Receiver: Decryption Throughput",
             "Throughput (MB/s)", "receiver_decryption_throughput.png")
    plot_bar(receiver, "Overall delay", "Receiver: Overall Receive Delay",
             "Delay (ms)", "receiver_overall_delay.png")
    plot_bar(receiver, "Overall energy", "Receiver: Overall Energy",
             "Energy (J)", "receiver_overall_energy.png")


if __name__ == "__main__":
    main()