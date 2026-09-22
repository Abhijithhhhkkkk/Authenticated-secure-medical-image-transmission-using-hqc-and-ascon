import socket
import struct
import secrets
import hmac
import hashlib
import os
from pathlib import Path
import time

from dotenv import load_dotenv
from ascon import encrypt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

TCP_PORT = int(os.getenv("TCP_PORT", "5000"))
SOCKET_TIMEOUT = 15

AAD = b"medical-image"

HMAC_SIZE = 32
CHALLENGE_SIZE = 32
ASCON_TAG_SIZE = 16

IMAGE_FOLDER = Path(__file__).resolve().parent / "img"

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png"
}


# ============================================================
# RECEIVERS
# ============================================================

RECEIVERS = {
    "receiver1": {
        "ip": os.getenv("RECEIVER1_IP"),
        "key": os.getenv("RECEIVER1_KEY", "").encode()
    },

    "receiver2": {
        "ip": os.getenv("RECEIVER2_IP"),
        "key": os.getenv("RECEIVER2_KEY", "").encode()
    },

    "receiver3": {
        "ip": os.getenv("RECEIVER3_IP"),
        "key": os.getenv("RECEIVER3_KEY", "").encode()
    }
}


# ============================================================
# HMAC
# ============================================================

def calculate_hmac(key, data):

    return hmac.new(
        key,
        data,
        hashlib.sha256
    ).digest()


# ============================================================
# SEND CHALLENGE TO EVERY RECEIVER
# ============================================================

def send_challenge_to_all(challenge):

    print("\nSending common challenge to all receivers...")

    for receiver_id, config in RECEIVERS.items():

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(SOCKET_TIMEOUT)

            sock.connect(
                (config["ip"], TCP_PORT)
            )

            receiver_id_bytes = receiver_id.encode()

            # Packet:
            # A
            # Receiver ID length : 2 bytes
            # Receiver ID
            # Challenge : 32 bytes

            packet = (
                b"A"
                + struct.pack(
                    "!H",
                    len(receiver_id_bytes)
                )
                + receiver_id_bytes
                + challenge
            )

            sock.sendall(packet)

            print(
                f"Challenge sent to {receiver_id}"
            )

            sock.close()

        except Exception as e:

            print(
                f"Error sending challenge to {receiver_id}: {e}"
            )


# ============================================================
# BUILD IMAGE PAYLOAD
# ============================================================

def build_image_payload(image_path):

    filename = image_path.name

    patient_name = input(
        f"Enter patient name for {filename}: "
    ).strip()

    if not patient_name:
        patient_name = "unknown_patient"

    patient_bytes = patient_name.encode()

    filename_bytes = filename.encode()

    image_data = image_path.read_bytes()

    payload = (
        struct.pack(
            "!H",
            len(patient_bytes)
        )
        + patient_bytes

        + struct.pack(
            "!H",
            len(filename_bytes)
        )
        + filename_bytes

        + image_data
    )

    return payload, patient_name


# ============================================================
# ASCON ENCRYPTION
# ============================================================

def encrypt_image(image_path):

    payload, patient_name = (
        build_image_payload(image_path)
    )

    # Fresh ASCON key
    ascon_key = secrets.token_bytes(16)

    # Fresh nonce
    nonce = secrets.token_bytes(16)

    ciphertext = encrypt(
        ascon_key,
        nonce,
        AAD,
        payload
    )

    # Last 16 bytes = ASCON authentication tag
    ascon_tag = ciphertext[-ASCON_TAG_SIZE:]

    return (
        ascon_key,
        nonce,
        ciphertext,
        ascon_tag,
        patient_name
    )


# ============================================================
# BUILD SECURE PACKET
# ============================================================

def build_secure_packet(
    hmac_value,
    ascon_key,
    nonce,
    ciphertext
):

    packet = (

        # HMAC length
        struct.pack(
            "!B",
            len(hmac_value)
        )

        # HMAC
        + hmac_value

        # ASCON key length
        + struct.pack(
            "!B",
            len(ascon_key)
        )

        # ASCON key
        + ascon_key

        # Nonce
        + nonce

        # Ciphertext length
        + struct.pack(
            "!I",
            len(ciphertext)
        )

        # Ciphertext + ASCON tag
        + ciphertext
    )

    return packet


# ============================================================
# SEND IMAGE
# ============================================================

def send_image(
    sock,
    receiver_id,
    receiver_key,
    challenge,
    image_path
):

    try:

        # ----------------------------------------------------
        # 1. ASCON ENCRYPTION
        # ----------------------------------------------------

        (
            ascon_key,
            nonce,
            ciphertext,
            ascon_tag,
            patient_name
        ) = encrypt_image(image_path)

        print("\nASCON encryption completed.")

        # ----------------------------------------------------
        # 2. CREATE HMAC
        # ----------------------------------------------------

        receiver_id_bytes = receiver_id.encode()
        print("SEND receiver_id:   ", receiver_id_bytes)
        authentication_data = (
            challenge
            + receiver_id_bytes
            + ascon_tag

            
        )

        hmac_value = calculate_hmac(
            receiver_key,
            authentication_data
        )

        print("HMAC generated.")

        # ----------------------------------------------------
        # 3. BUILD PACKET
        # ----------------------------------------------------

        packet = build_secure_packet(
            hmac_value,
            ascon_key,
            nonce,
            ciphertext
        )

        # ----------------------------------------------------
        # 4. SEND IMAGE
        # ----------------------------------------------------

        sock.sendall(b"I")

        sock.sendall(
            struct.pack(
                "!Q",
                len(packet)
            )
        )

        sock.sendall(packet)

        print(
            f"Encrypted image sent to {receiver_id}"
        )

        return True

    except Exception as e:

        print(
            f"Image transmission error: {e}"
        )

        return False


# ============================================================
# SEND TO SELECTED RECEIVER
# ============================================================

def send_to_required_receiver(
    image_path,
    required_receiver,
    challenge
):

    receiver_config = RECEIVERS[
        required_receiver
    ]

    receiver_ip = receiver_config["ip"]

    receiver_key = receiver_config["key"]

    sock = None

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            SOCKET_TIMEOUT
        )

        print(
            f"\nConnecting to {required_receiver}..."
        )

        sock.connect(
            (receiver_ip, TCP_PORT)
        )

        print(
            "TCP connection established."
        )

        # Send encrypted image.
        # Receiver will authenticate using
        # challenge + receiver ID + ASCON tag
        # before decrypting.

        return send_image(
            sock,
            required_receiver,
            receiver_key,
            challenge,
            image_path
        )

    except Exception as e:

        print(
            f"Network error: {e}"
        )

        return False

    finally:

        if sock is not None:
            sock.close()


# ============================================================
# SELECT RECEIVER
# ============================================================

def select_receiver():

    receiver_list = list(
        RECEIVERS.keys()
    )

    print("\nAVAILABLE RECEIVERS")

    for index, receiver_id in enumerate(
        receiver_list,
        start=1
    ):

        print(
            f"{index}. {receiver_id}"
        )

    while True:

        try:

            choice = int(
                input(
                    "Select required receiver: "
                )
            )

            if 1 <= choice <= len(receiver_list):

                return receiver_list[
                    choice - 1
                ]

            print("Invalid selection.")

        except ValueError:

            print(
                "Enter a valid number."
            )


# ============================================================
# FILE WATCHDOG
# ============================================================

class MedicalImageHandler(
    FileSystemEventHandler
):

    def __init__(
        self,
        receiver_id
    ):

        super().__init__()

        self.receiver_id = receiver_id

    def on_created(self, event):

        if event.is_directory:
            return

        image_path = Path(
            event.src_path
        )

        if image_path.suffix.lower() not in IMAGE_EXTENSIONS:
            return

        time.sleep(1)

        # ----------------------------------------------------
        # Generate ONE challenge
        # ----------------------------------------------------

        challenge = secrets.token_bytes(
            CHALLENGE_SIZE
        )

        # ----------------------------------------------------
        # Send SAME challenge to every receiver
        # ----------------------------------------------------

        send_challenge_to_all(
            challenge
        )

        # ----------------------------------------------------
        # Send image only to selected receiver
        # ----------------------------------------------------

        send_to_required_receiver(
            image_path,
            self.receiver_id,
            challenge
        )


# ============================================================
# MAIN
# ============================================================

def main():

    if not IMAGE_FOLDER.exists():

        print(
            "Image folder does not exist."
        )

        return

    receiver_id = select_receiver()

    print(
        f"\nSelected receiver: {receiver_id}"
    )

    observer = Observer()

    handler = MedicalImageHandler(
        receiver_id
    )

    observer.schedule(
        handler,
        str(IMAGE_FOLDER),
        recursive=False
    )

    observer.start()

    print(
        "\nWaiting for medical images..."
    )

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()