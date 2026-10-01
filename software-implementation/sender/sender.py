import hashlib
import hmac
import os
import secrets
import socket
import struct
import time
import ctypes

from pathlib import Path

from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


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
# LOAD C ASCON LIBRARY
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

ASCON_LIBRARY = BASE_DIR / "libascon.so"

if not ASCON_LIBRARY.exists():
    raise FileNotFoundError(
        f"ASCON library not found: {ASCON_LIBRARY}\n"
        f"Compile it using:\n"
        f"gcc -O3 -fPIC -shared ascon_wrapper.c -o libascon.so"
    )


ascon_lib = ctypes.CDLL(str(ASCON_LIBRARY))


# ============================================================
# C FUNCTION DEFINITION
# ============================================================

ascon_lib.ascon_encrypt_c.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # key
    ctypes.POINTER(ctypes.c_ubyte),   # nonce
    ctypes.POINTER(ctypes.c_ubyte),   # aad
    ctypes.c_size_t,                  # aad length
    ctypes.POINTER(ctypes.c_ubyte),   # plaintext
    ctypes.c_size_t,                  # plaintext length
    ctypes.POINTER(ctypes.c_ubyte),   # ciphertext
]

ascon_lib.ascon_encrypt_c.restype = ctypes.c_int


# ============================================================
# RECEIVERS
# ============================================================

RECEIVERS = {

    "receiver1": {
        "ip": os.getenv("RECEIVER1_IP"),
        "key": os.getenv(
            "RECEIVER1_KEY",
            ""
        ).encode(),
    },

    "receiver2": {
        "ip": os.getenv("RECEIVER2_IP"),
        "key": os.getenv(
            "RECEIVER2_KEY",
            ""
        ).encode(),
    },

    "receiver3": {
        "ip": os.getenv("RECEIVER3_IP"),
        "key": os.getenv(
            "RECEIVER3_KEY",
            ""
        ).encode(),
    },

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
# C ASCON ENCRYPTION
# ============================================================

def ascon_encrypt_c(key, nonce, aad, plaintext):

    plaintext_len = len(plaintext)

    # Ciphertext = plaintext + 16-byte authentication tag
    ciphertext = bytearray(
        plaintext_len + ASCON_TAG_SIZE
    )

    key_buffer = (
        ctypes.c_ubyte * len(key)
    ).from_buffer_copy(key)

    nonce_buffer = (
        ctypes.c_ubyte * len(nonce)
    ).from_buffer_copy(nonce)

    aad_buffer = (
        ctypes.c_ubyte * len(aad)
    ).from_buffer_copy(aad)

    plaintext_buffer = (
        ctypes.c_ubyte * len(plaintext)
    ).from_buffer_copy(plaintext)

    ciphertext_buffer = (
        ctypes.c_ubyte * len(ciphertext)
    ).from_buffer(ciphertext)

    result = ascon_lib.ascon_encrypt_c(

        key_buffer,

        nonce_buffer,

        aad_buffer,

        len(aad),

        plaintext_buffer,

        plaintext_len,

        ciphertext_buffer
    )

    if result != 0:

        raise RuntimeError(
            "C ASCON encryption failed"
        )

    return bytes(ciphertext)


# ============================================================
# CHALLENGE BROADCAST
# ============================================================

def send_challenge_to_all(challenge):

    print(
        "\nSending common challenge "
        "to all receivers..."
    )

    for receiver_id, config in RECEIVERS.items():

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(
                SOCKET_TIMEOUT
            )

            sock.connect(
                (
                    config["ip"],
                    TCP_PORT
                )
            )

            receiver_id_bytes = (
                receiver_id.encode()
            )

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
                f"Challenge sent to "
                f"{receiver_id}"
            )

            sock.close()

        except Exception as e:

            print(
                f"Error sending challenge "
                f"to {receiver_id}: {e}"
            )


# ============================================================
# BUILD IMAGE PAYLOAD
# ============================================================

def build_image_payload(image_path):

    filename = image_path.name

    patient_name = input(
        f"Enter patient name for "
        f"{filename}: "
    ).strip()

    if not patient_name:

        patient_name = (
            "unknown_patient"
        )

    patient_bytes = (
        patient_name.encode()
    )

    filename_bytes = (
        filename.encode()
    )

    image_data = (
        image_path.read_bytes()
    )

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
# ENCRYPT IMAGE
# ============================================================

def encrypt_image(image_path):

    payload, patient_name = (
        build_image_payload(
            image_path
        )
    )

    # Generate ASCON key
    ascon_key = secrets.token_bytes(16)

    # Generate ASCON nonce
    nonce = secrets.token_bytes(16)

    # --------------------------------------------------------
    # ONLY ASCON ENCRYPTION IS TIMED
    # --------------------------------------------------------

    start_time = time.perf_counter()

    ciphertext = ascon_encrypt_c(
        ascon_key,
        nonce,
        AAD,
        payload
    )

    elapsed = (
        time.perf_counter()
        - start_time
    )

    # --------------------------------------------------------
    # PERFORMANCE
    # --------------------------------------------------------

    image_size_mb = (
        len(payload)
        / (1024 * 1024)
    )
    print(f"Image size: {image_size_mb:.2f} MB")
    encryption_time_ms = (
        elapsed * 1000
    )

    if elapsed > 0:

        throughput_mb_s = (
            image_size_mb
            / elapsed
        )

    else:

        throughput_mb_s = 0

    print(
        "\n========== ASCON PERFORMANCE =========="
    )

    print(
        f"Payload size       : "
        f"{image_size_mb:.3f} MB"
    )

    print(
        f"Encryption time     : "
        f"{encryption_time_ms:.3f} ms"
    )

    print(
        f"Encryption throughput: "
        f"{throughput_mb_s:.3f} MB/s"
    )

    print(
        "========================================"
    )

    # Last 16 bytes = ASCON authentication tag
    ascon_tag = (
        ciphertext[-ASCON_TAG_SIZE:]
    )

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

    return (

        struct.pack(
            "!B",
            len(hmac_value)
        )

        + hmac_value

        + struct.pack(
            "!B",
            len(ascon_key)
        )

        + ascon_key

        + nonce

        + struct.pack(
            "!I",
            len(ciphertext)
        )

        + ciphertext
    )


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
        # ASCON ENCRYPTION
        # ----------------------------------------------------

        (
            ascon_key,
            nonce,
            ciphertext,
            ascon_tag,
            patient_name
        ) = encrypt_image(
            image_path
        )

       
        # ----------------------------------------------------
        # HMAC AUTHENTICATION
        # ----------------------------------------------------

        receiver_id_bytes = (
            receiver_id.encode()
        )

        authentication_data = (

            challenge

            + receiver_id_bytes

            + ascon_tag
        )

        hmac_value = calculate_hmac(
            receiver_key,
            authentication_data
        )

        
        # ----------------------------------------------------
        # BUILD PACKET
        # ----------------------------------------------------

        packet = build_secure_packet(

            hmac_value,

            ascon_key,

            nonce,

            ciphertext
        )

        # ----------------------------------------------------
        # SEND
        # ----------------------------------------------------

        sock.sendall(b"I")

        sock.sendall(
            struct.pack(
                "!Q",
                len(packet)
            )
        )

        sock.sendall(packet)

      

        return True

    except Exception as e:

        print(
            f"Image transmission error: "
            f"{e}"
        )

        return False


# ============================================================
# SEND TO REQUIRED RECEIVER
# ============================================================

def send_to_required_receiver(
    image_path,
    required_receiver,
    challenge
):

    receiver_config = (
        RECEIVERS[
            required_receiver
        ]
    )

    receiver_ip = (
        receiver_config["ip"]
    )

    receiver_key = (
        receiver_config["key"]
    )

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
            f"\nConnecting to "
            f"{required_receiver}..."
        )

        sock.connect(
            (
                receiver_ip,
                TCP_PORT
            )
        )

        
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

    print(
        "\nAVAILABLE RECEIVERS"
    )

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

            if (
                1 <= choice
                <= len(receiver_list)
            ):

                return receiver_list[
                    choice - 1
                ]

            print(
                "Invalid selection."
            )

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

        self.receiver_id = (
            receiver_id
        )

    def on_created(self, event):

        if event.is_directory:

            return

        image_path = Path(
            event.src_path
        )

        if (
            image_path.suffix.lower()
            not in IMAGE_EXTENSIONS
        ):

            return

        # Wait for file writing to finish
        time.sleep(1)

        # Fresh challenge
        challenge = (
            secrets.token_bytes(
                CHALLENGE_SIZE
            )
        )

        # Send challenge
        send_challenge_to_all(
            challenge
        )

        # Encrypt and send
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

    receiver_id = (
        select_receiver()
    )

    print(
        f"\nSelected receiver: "
        f"{receiver_id}"
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
        "\nUpload the Image..."
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