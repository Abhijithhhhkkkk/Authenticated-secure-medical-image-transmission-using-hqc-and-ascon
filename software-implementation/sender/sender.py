import socket
import struct
import secrets
import hmac
import hashlib
import csv
import time
import os
from pathlib import Path

from dotenv import load_dotenv
from ascon import encrypt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# LOAD .ENV
# ============================================================

load_dotenv()

TCP_PORT = int(os.getenv("TCP_PORT", "5000"))

SOCKET_TIMEOUT = 15

AAD = b"medical-image"


# ============================================================
# IMAGE FOLDER
# ============================================================

IMAGE_FOLDER = Path(
    "/home/abhijithk/Authenticated-secure-medical-image-transmission-using-hqc-and-ascon/"
    "software-implementation/sender/img"
)

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png"
}


# ============================================================
# RECEIVER CONFIGURATION
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
# HMAC CONFIGURATION
# ============================================================

HMAC_SIZE = 32
CHALLENGE_SIZE = 32


# ============================================================
# PERFORMANCE CSV
# ============================================================

CSV_FILE = Path(
    "performance_log_sender.csv"
)

CSV_FIELDS = [
    "Receiver_ID",
    "Filename",
    "ImageSizeKB",
    "ASCON_Time",
    "Transmission_Time",
    "Overall_Delay",
    "Throughput_KBps"
]


# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

def validate_configuration():

    for receiver_id, config in RECEIVERS.items():

        if not config["ip"]:
            raise ValueError(
                f"{receiver_id} IP missing in .env"
            )

        if not config["key"]:
            raise ValueError(
                f"{receiver_id} key missing in .env"
            )


# ============================================================
# CSV INITIALIZATION
# ============================================================

def initialize_csv():

    if not CSV_FILE.exists():

        with open(
            CSV_FILE,
            "w",
            newline=""
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=CSV_FIELDS
            )

            writer.writeheader()


# ============================================================
# RECEIVE EXACT NUMBER OF BYTES
# ============================================================

def recv_exact(sock, size):

    data = b""

    while len(data) < size:

        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            return None

        data += chunk

    return data


# ============================================================
# HMAC
# ============================================================

def calculate_hmac(
    key,
    data
):

    return hmac.new(
        key,
        data,
        hashlib.sha256
    ).digest()


# ============================================================
# AUTHENTICATE RECEIVER
# ============================================================

def authenticate_receiver(
    sock,
    receiver_id,
    receiver_key
):

    authentication_start = (
        time.perf_counter()
    )

    # --------------------------------------------------------
    # Generate random challenge
    # --------------------------------------------------------

    challenge = secrets.token_bytes(
        CHALLENGE_SIZE
    )

    # --------------------------------------------------------
    # Send authentication request
    #
    # A + challenge
    # --------------------------------------------------------

    sock.sendall(
        b"A" + challenge
    )

    print(
        "Challenge sent."
    )

    # --------------------------------------------------------
    # Receive response type
    # --------------------------------------------------------

    response_type = recv_exact(
        sock,
        1
    )

    if response_type != b"R":

        print(
            "Invalid authentication response."
        )

        return False

    # --------------------------------------------------------
    # Receive HMAC
    # --------------------------------------------------------

    received_hmac = recv_exact(
        sock,
        HMAC_SIZE
    )

    if received_hmac is None:

        print(
            "HMAC response not received."
        )

        return False

    # --------------------------------------------------------
    # Calculate expected HMAC
    # --------------------------------------------------------

    authentication_data = (
        challenge
        + receiver_id.encode()
    )

    expected_hmac = calculate_hmac(
        receiver_key,
        authentication_data
    )

    # --------------------------------------------------------
    # Verify HMAC
    # --------------------------------------------------------

    if not hmac.compare_digest(
        received_hmac,
        expected_hmac
    ):

        print(
            "\nHMAC verification FAILED."
        )

        sock.sendall(b"F")

        return False

    authentication_time = (
        time.perf_counter()
        - authentication_start
    )

    print(
        "\nHMAC verification SUCCESSFUL."
    )

    print(
        f"Receiver ID          : {receiver_id}"
    )

    print(
        f"Authentication time  : "
        f"{authentication_time:.6f} sec"
    )

    # --------------------------------------------------------
    # Authentication successful
    # --------------------------------------------------------

    sock.sendall(b"O")

    return True


# ============================================================
# BUILD IMAGE PAYLOAD
# ============================================================

def build_image_payload(
    image_path
):

    filename = image_path.name

    patient_name = input(
        f"Enter patient name for {filename}: "
    ).strip()

    if not patient_name:
        patient_name = "unknown_patient"

    patient_bytes = (
        patient_name.encode()
    )

    filename_bytes = (
        filename.encode()
    )

    image_data = (
        image_path.read_bytes()
    )

    # --------------------------------------------------------
    # Payload format
    #
    # [patient length : 2 bytes]
    # [patient name]
    # [filename length : 2 bytes]
    # [filename]
    # [image data]
    # --------------------------------------------------------

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

    return (
        payload,
        patient_name
    )


# ============================================================
# ASCON ENCRYPTION
# ============================================================

def encrypt_image(
    image_path
):

    payload, patient_name = (
        build_image_payload(
            image_path
        )
    )

    # --------------------------------------------------------
    # Fresh ASCON-128 key
    # --------------------------------------------------------

    ascon_key = secrets.token_bytes(
        16
    )

    # --------------------------------------------------------
    # Fresh nonce
    # --------------------------------------------------------

    nonce = secrets.token_bytes(
        16
    )

    # --------------------------------------------------------
    # Encryption timing
    # --------------------------------------------------------

    start_time = (
        time.perf_counter()
    )

    ciphertext = encrypt(

        ascon_key,

        nonce,

        AAD,

        payload
    )

    encryption_time = (
        time.perf_counter()
        - start_time
    )

    return (
        ascon_key,
        nonce,
        ciphertext,
        patient_name,
        encryption_time
    )


# ============================================================
# BUILD SECURE PACKET
# ============================================================

def build_secure_packet(
    ascon_key,
    nonce,
    ciphertext
):

    # --------------------------------------------------------
    # Packet format
    #
    # [ASCON key length : 1 byte]
    # [ASCON key]
    # [nonce : 16 bytes]
    # [ciphertext length : 4 bytes]
    # [ciphertext]
    # --------------------------------------------------------

    packet = (

        struct.pack(
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

    return packet


# ============================================================
# SEND MEDICAL IMAGE
# ============================================================

def send_image(
    sock,
    receiver_id,
    image_path
):

    try:

        print(
            "\n============================================"
        )

        print(
            "ASCON ENCRYPTION"
        )

        print(
            "============================================"
        )

        # ----------------------------------------------------
        # Encrypt image
        # ----------------------------------------------------

        (
            ascon_key,
            nonce,
            ciphertext,
            patient_name,
            encryption_time
        ) = encrypt_image(
            image_path
        )

        # ----------------------------------------------------
        # Build packet
        # ----------------------------------------------------

        packet = build_secure_packet(

            ascon_key,

            nonce,

            ciphertext
        )

        # ----------------------------------------------------
        # Tell receiver image is ready
        # ----------------------------------------------------

        sock.sendall(
            b"I"
        )

        # ----------------------------------------------------
        # Send packet length
        # ----------------------------------------------------

        sock.sendall(

            struct.pack(
                "!Q",
                len(packet)
            )
        )

        # ----------------------------------------------------
        # Send packet
        # ----------------------------------------------------

        transmission_start = (
            time.perf_counter()
        )

        sock.sendall(
            packet
        )

        transmission_time = (
            time.perf_counter()
            - transmission_start
        )

        # ----------------------------------------------------
        # Performance calculation
        # ----------------------------------------------------

        image_size_kb = (
            image_path.stat().st_size
            / 1024
        )

        overall_delay = (
            encryption_time
            + transmission_time
        )

        throughput = (

            image_size_kb
            / transmission_time

            if transmission_time > 0
            else 0
        )

        # ----------------------------------------------------
        # Save performance data
        # ----------------------------------------------------

        initialize_csv()

        with open(
            CSV_FILE,
            "a",
            newline=""
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=CSV_FIELDS
            )

            writer.writerow({

                "Receiver_ID":
                    receiver_id,

                "Filename":
                    image_path.name,

                "ImageSizeKB":
                    f"{image_size_kb:.2f}",

                "ASCON_Time":
                    f"{encryption_time:.6f}",

                "Transmission_Time":
                    f"{transmission_time:.6f}",

                "Overall_Delay":
                    f"{overall_delay:.6f}",

                "Throughput_KBps":
                    f"{throughput:.2f}"
            })

        # ----------------------------------------------------
        # Display result
        # ----------------------------------------------------

        print(
            "\n============================================"
        )

        print(
            "MEDICAL IMAGE SENT"
        )

        print(
            "============================================"
        )

        print(
            f"Receiver        : "
            f"{receiver_id}"
        )

        print(
            f"Patient         : "
            f"{patient_name}"
        )

        print(
            f"Filename        : "
            f"{image_path.name}"
        )

        print(
            f"Image size      : "
            f"{image_size_kb:.2f} KB"
        )

        print(
            f"ASCON time      : "
            f"{encryption_time:.6f} sec"
        )

        print(
            f"Transmission    : "
            f"{transmission_time:.6f} sec"
        )

        print(
            f"Overall delay   : "
            f"{overall_delay:.6f} sec"
        )

        print(
            f"Throughput      : "
            f"{throughput:.2f} KB/s"
        )

        print(
            "============================================"
        )

        return True

    except Exception as e:

        print(
            f"\nImage transmission error: {e}"
        )

        return False


# ============================================================
# SEND TO REQUIRED RECEIVER
# ============================================================

def send_to_required_receiver(
    image_path,
    required_receiver
):

    receiver_config = RECEIVERS[
        required_receiver
    ]

    receiver_ip = receiver_config[
        "ip"
    ]

    receiver_key = receiver_config[
        "key"
    ]

    print(
        "\n============================================"
    )

    print(
        "CONNECTING TO REQUIRED RECEIVER"
    )

    print(
        "============================================"
    )

    print(
        f"Receiver ID : "
        f"{required_receiver}"
    )

    print(
        f"Receiver IP : "
        f"{receiver_ip}"
    )

    print(
        f"TCP Port    : "
        f"{TCP_PORT}"
    )

    sock = None

    try:

        # ----------------------------------------------------
        # Create TCP socket
        # ----------------------------------------------------

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            SOCKET_TIMEOUT
        )

        # ----------------------------------------------------
        # Connect
        # ----------------------------------------------------

        sock.connect(

            (
                receiver_ip,
                TCP_PORT
            )
        )

        print(
            "\nTCP connection established."
        )

        # ----------------------------------------------------
        # Authenticate receiver
        # ----------------------------------------------------

        authenticated = (
            authenticate_receiver(

                sock,

                required_receiver,

                receiver_key
            )
        )

        if not authenticated:

            print(
                "\nReceiver authentication failed."
            )

            print(
                "Medical image NOT sent."
            )

            return False

        # ----------------------------------------------------
        # Send image
        # ----------------------------------------------------

        return send_image(

            sock,

            required_receiver,

            image_path
        )

    except socket.timeout:

        print(
            "\nConnection timed out."
        )

        return False

    except ConnectionRefusedError:

        print(
            "\nConnection refused."
        )

        print(
            "Make sure the receiver is running."
        )

        return False

    except OSError as e:

        print(
            f"\nNetwork error: {e}"
        )

        return False

    except Exception as e:

        print(
            f"\nError: {e}"
        )

        return False

    finally:

        if sock is not None:

            sock.close()

            print(
                "\nTCP connection closed."
            )


# ============================================================
# WAIT UNTIL FILE IS COMPLETELY WRITTEN
# ============================================================

def wait_for_file_ready(
    image_path
):

    previous_size = -1
    stable_count = 0

    while stable_count < 3:

        try:

            current_size = (
                image_path.stat().st_size
            )

        except FileNotFoundError:

            return False

        if current_size == previous_size:

            stable_count += 1

        else:

            stable_count = 0

        previous_size = current_size

        time.sleep(0.5)

    return True


# ============================================================
# WATCHDOG HANDLER
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

        self.processing = set()

    # --------------------------------------------------------
    # Process image
    # --------------------------------------------------------

    def process_image(
        self,
        image_path
    ):

        image_path = Path(
            image_path
        )

        # ----------------------------------------------------
        # Check extension
        # ----------------------------------------------------

        if (
            image_path.suffix.lower()
            not in IMAGE_EXTENSIONS
        ):

            return

        # ----------------------------------------------------
        # Prevent duplicate processing
        # ----------------------------------------------------

        if image_path in self.processing:

            return

        if not image_path.exists():

            return

        self.processing.add(
            image_path
        )

        try:

            print(
                "\n============================================"
            )

            print(
                "NEW MEDICAL IMAGE DETECTED"
            )

            print(
                "============================================"
            )

            print(
                f"Image    : "
                f"{image_path.name}"
            )

            print(
                f"Receiver : "
                f"{self.receiver_id}"
            )

            print(
                "============================================"
            )

            # ------------------------------------------------
            # Wait until file is completely copied
            # ------------------------------------------------

            print(
                "Waiting for file to become stable..."
            )

            ready = wait_for_file_ready(
                image_path
            )

            if not ready:

                print(
                    "File disappeared."
                )

                return

            print(
                "File ready."
            )

            # ------------------------------------------------
            # Send image
            # ------------------------------------------------

            success = (
                send_to_required_receiver(

                    image_path,

                    self.receiver_id
                )
            )

            if success:

                print(
                    "\nTransmission completed successfully."
                )

            else:

                print(
                    "\nTransmission failed."
                )

        except Exception as e:

            print(
                f"\nWatchdog processing error: {e}"
            )

        finally:

            self.processing.discard(
                image_path
            )

    # --------------------------------------------------------
    # New file created
    # --------------------------------------------------------

    def on_created(
        self,
        event
    ):

        if event.is_directory:

            return

        image_path = Path(
            event.src_path
        )

        self.process_image(
            image_path
        )

    # --------------------------------------------------------
    # File moved into folder
    # --------------------------------------------------------

    def on_moved(
        self,
        event
    ):

        if event.is_directory:

            return

        image_path = Path(
            event.dest_path
        )

        self.process_image(
            image_path
        )


# ============================================================
# SELECT RECEIVER
# ============================================================

def select_receiver():

    receiver_list = list(
        RECEIVERS.keys()
    )

    print(
        "\n============================================"
    )

    print(
        "AVAILABLE RECEIVERS"
    )

    print(
        "============================================"
    )

    for index, receiver_id in enumerate(
        receiver_list,
        start=1
    ):

        print(
            f"{index}. "
            f"{receiver_id} "
            f"({RECEIVERS[receiver_id]['ip']})"
        )

    print(
        "============================================"
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
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Validate configuration
    # --------------------------------------------------------

    validate_configuration()

    initialize_csv()

    # --------------------------------------------------------
    # Display system information
    # --------------------------------------------------------

    print(
        "\n============================================"
    )

    print(
        " SECURE MEDICAL IMAGE WATCHDOG SENDER"
    )

    print(
        "============================================"
    )

    print(
        "Protocol       : TCP"
    )

    print(
        "Authentication : HMAC-SHA256"
    )

    print(
        "Encryption     : ASCON-128"
    )

    print(
        f"TCP Port       : {TCP_PORT}"
    )

    print(
        f"Watch Folder   : {IMAGE_FOLDER}"
    )

    print(
        "============================================"
    )

    # --------------------------------------------------------
    # Check image folder
    # --------------------------------------------------------

    if not IMAGE_FOLDER.exists():

        print(
            "\nERROR: Image folder does not exist."
        )

        print(
            IMAGE_FOLDER
        )

        return

    # --------------------------------------------------------
    # Select receiver once
    # --------------------------------------------------------

    receiver_id = select_receiver()

    print(
        "\n============================================"
    )

    print(
        "WATCHDOG STARTED"
    )

    print(
        "============================================"
    )

    print(
        f"Receiver : {receiver_id}"
    )

    print(
        f"Folder   : {IMAGE_FOLDER}"
    )

    print(
        "\nWaiting for new medical images..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print(
        "============================================"
    )

    # --------------------------------------------------------
    # Create watchdog handler
    # --------------------------------------------------------

    event_handler = MedicalImageHandler(
        receiver_id
    )

    # --------------------------------------------------------
    # Create observer
    # --------------------------------------------------------

    observer = Observer()

    observer.schedule(
        event_handler,
        str(IMAGE_FOLDER),
        recursive=False
    )

    observer.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print(
            "\n\nStopping watchdog..."
        )

        observer.stop()

    observer.join()

    print(
        "\nSender stopped."
    )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()
