
import csv 
import os
from pathlib import Path

from watchdog.observers import Observer
from ascon import encrypt
import time

# ----------------------------
# SANITIZE PATIENT NAME
# ----------------------------
WATCH_FOLDER = Path(
    "/home/abhijithk/Authenticated-secure-medical-image-transmission-using-hqc-and-ascon/sender/img"
)
AAD = b"medical-image"
SOCKET_TIMEOUT = 10
READY_TIMEOUT = 20
READY_STABLE_CHECKS = 4
READY_SLEEP = 0.3

VALID_EXTENSIONS = {".jpg", ".jpeg", ".png"}

CSV_FILE = "performance_log.csv"

sent_files = set()

# ----------------------------
# CREATE CSV HEADER
# ----------------------------
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "Filename",
            "ImageSizeKB",
            "ASCON_Time",
            "RSA_Time",
            "Total_Encryption_Time",
            "Transmission_Time",
            "Overall_Delay",
            "Throughput_KBps"
        ])

def sanitize_name(name: str) -> str:
    allowed = []

    for ch in name.strip():
        if ch.isalnum() or ch in (" ", "_", "-"):
            allowed.append(ch)

    cleaned = "".join(allowed).strip()

    return cleaned if cleaned else "unknown_patient"


# ----------------------------
# WAIT UNTIL FILE READY
# ----------------------------
def wait_until_file_ready(path: Path, timeout=READY_TIMEOUT) -> bool:
    stable = 0
    last_size = -1
    start = time.time()

    while time.time() - start < timeout:
        try:
            size = path.stat().st_size

        except FileNotFoundError:
            time.sleep(0.2)
            continue

        if size > 0 and size == last_size:
            stable += 1

            if stable >= READY_STABLE_CHECKS:
                return True

        else:
            stable = 0

        last_size = size
        time.sleep(READY_SLEEP)

    return False


# ----------------------------
# GET PATIENT NAME
# ----------------------------
def get_patient_name(image_path: Path) -> str:
    return sanitize_name(image_path.parent.name)


# ----------------------------
# BUILD PAYLOAD
# ----------------------------
def build_secure_payload(
    patient_name: str,
    filename: str,
    image_bytes: bytes
) -> bytes:

    patient_name_b = patient_name.encode(
        "utf-8",
        errors="replace"
    )

    filename_b = filename.encode(
        "utf-8",
        errors="replace"
    )

    print(f"Patient name bytes : {len(patient_name_b)}")
    print(f"Filename bytes     : {len(filename_b)}")

    if len(patient_name_b) > 255:
        patient_name_b = patient_name_b[:255]

    if len(filename_b) > 500:
        filename_b = filename_b[:500]

    return (
        len(patient_name_b).to_bytes(2, "big")
        + patient_name_b
        + len(filename_b).to_bytes(2, "big")
        + filename_b
        + image_bytes
    )


# ----------------------------
# SEND IMAGE
# ----------------------------
def send_image(path: Path) -> None:

    patient_name = get_patient_name(path)

    image_bytes = path.read_bytes()

    ascon_key = os.urandom(16)
    nonce = os.urandom(16)

    print("\n========================================")
    print(f"Preparing to send : {path.name}")
    print(f"Patient           : {patient_name}")
    print(f"Image Size        : {len(image_bytes)} bytes")
    print("========================================")

    secure_payload = build_secure_payload(
        patient_name,
        path.name,
        image_bytes
    )

    # -----------------------------------
    # TOTAL PROCESS START
    # -----------------------------------
    total_start = time.perf_counter()

    # -----------------------------------
    # ASCON ENCRYPTION
    # -----------------------------------
    ascon_start = time.perf_counter()

    ciphertext = encrypt(
        ascon_key,
        nonce,
        AAD,
        secure_payload
    )

    ascon_end = time.perf_counter()
    ascon_time = ascon_end - ascon_start
