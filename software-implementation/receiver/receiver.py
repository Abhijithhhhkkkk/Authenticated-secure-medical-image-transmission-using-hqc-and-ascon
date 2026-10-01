import hashlib
import hmac
import os
import socket
import struct
import ctypes
import time

from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

TCP_PORT = int(os.getenv("TCP_PORT", "5000"))

AAD = b"medical-image"

HMAC_SIZE = 32
CHALLENGE_SIZE = 32
ASCON_TAG_SIZE = 16

RECEIVER_ID = os.getenv(
    "RECEIVER_ID",
    "receiver1"
)

IDENTITY_KEY = os.getenv(
    "RECEIVER_KEY",
    ""
).encode()

OUTPUT_FOLDER = "received_images"

os.makedirs(
    OUTPUT_FOLDER,
    exist_ok=True
)


# ============================================================
# LOAD C ASCON LIBRARY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

ASCON_LIBRARY = os.path.join(
    BASE_DIR,
    "libascon.so"
)

if not os.path.exists(ASCON_LIBRARY):

    raise FileNotFoundError(
        f"ASCON library not found: "
        f"{ASCON_LIBRARY}\n\n"
        f"Compile it using:\n"
        f"gcc -O3 -fPIC -shared "
        f"ascon_wrapper.c -o libascon.so"
    )

ascon_lib = ctypes.CDLL(
    ASCON_LIBRARY
)


# ============================================================
# C ASCON FUNCTION
# ============================================================

ascon_lib.ascon_decrypt_c.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # key
    ctypes.POINTER(ctypes.c_ubyte),   # nonce
    ctypes.POINTER(ctypes.c_ubyte),   # aad
    ctypes.c_size_t,                  # aad length
    ctypes.POINTER(ctypes.c_ubyte),   # ciphertext
    ctypes.c_size_t,                  # ciphertext length
    ctypes.POINTER(ctypes.c_ubyte)    # plaintext
]

ascon_lib.ascon_decrypt_c.restype = ctypes.c_int


# ============================================================
# C ASCON DECRYPTION
# ============================================================

def ascon_decrypt_c(
    key,
    nonce,
    aad,
    ciphertext
):

    if len(ciphertext) < ASCON_TAG_SIZE:

        raise ValueError(
            "Ciphertext is too short."
        )

    plaintext_length = (
        len(ciphertext)
        - ASCON_TAG_SIZE
    )

    plaintext = bytearray(
        plaintext_length
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

    ciphertext_buffer = (
        ctypes.c_ubyte * len(ciphertext)
    ).from_buffer_copy(ciphertext)

    plaintext_buffer = (
        ctypes.c_ubyte * len(plaintext)
    ).from_buffer(plaintext)

    result = ascon_lib.ascon_decrypt_c(
        key_buffer,
        nonce_buffer,
        aad_buffer,
        len(aad),
        ciphertext_buffer,
        len(ciphertext),
        plaintext_buffer
    )

    if result != 0:

        raise ValueError(
            "ASCON authentication "
            "or decryption failed."
        )

    return bytes(plaintext)


# ============================================================
# RECEIVE EXACT
# ============================================================

def recv_exact(sock, size):

    data = bytearray()

    while len(data) < size:

        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            return None

        data.extend(chunk)

    return bytes(data)


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
# SANITIZE PATIENT NAME
# ============================================================

def sanitize_folder_name(name):

    name = (
        name.strip()
        or "unknown_patient"
    )

    invalid_chars = (
        '/\\:*?"<>|'
    )

    for char in invalid_chars:

        name = name.replace(
            char,
            "_"
        )

    return name


# ============================================================
# AUTHENTICATION
# ============================================================

def authenticate_receiver(
    challenge,
    receiver_id,
    received_hmac,
    ascon_tag
):

    receiver_id_bytes = (
        receiver_id.encode()
    )

    authentication_data = (
        challenge
        + receiver_id_bytes
        + ascon_tag
    )

    expected_hmac = calculate_hmac(
        IDENTITY_KEY,
        authentication_data
    )

    return hmac.compare_digest(
        received_hmac,
        expected_hmac
    )


# ============================================================
# PACKET PARSING
# ============================================================

def parse_packet(packet):

    offset = 0

    # --------------------------------------------------------
    # HMAC
    # --------------------------------------------------------

    if len(packet) < offset + 1:

        raise ValueError(
            "Invalid packet."
        )

    hmac_length = struct.unpack(
        "!B",
        packet[
            offset:
            offset + 1
        ]
    )[0]

    offset += 1

    received_hmac = packet[
        offset:
        offset + hmac_length
    ]

    if len(received_hmac) != hmac_length:

        raise ValueError(
            "Invalid HMAC."
        )

    offset += hmac_length

    # --------------------------------------------------------
    # ASCON KEY
    # --------------------------------------------------------

    if len(packet) < offset + 1:

        raise ValueError(
            "Invalid packet."
        )

    key_length = struct.unpack(
        "!B",
        packet[
            offset:
            offset + 1
        ]
    )[0]

    offset += 1

    ascon_key = packet[
        offset:
        offset + key_length
    ]

    if len(ascon_key) != key_length:

        raise ValueError(
            "Invalid ASCON key."
        )

    offset += key_length

    # --------------------------------------------------------
    # NONCE
    # --------------------------------------------------------

    if len(packet) < offset + 16:

        raise ValueError(
            "Invalid nonce."
        )

    nonce = packet[
        offset:
        offset + 16
    ]

    offset += 16

    # --------------------------------------------------------
    # CIPHERTEXT LENGTH
    # --------------------------------------------------------

    if len(packet) < offset + 4:

        raise ValueError(
            "Invalid ciphertext length."
        )

    ciphertext_length = struct.unpack(
        "!I",
        packet[
            offset:
            offset + 4
        ]
    )[0]

    offset += 4

    # --------------------------------------------------------
    # CIPHERTEXT
    # --------------------------------------------------------

    if len(packet) < offset + ciphertext_length:

        raise ValueError(
            "Incomplete ciphertext."
        )

    ciphertext = packet[
        offset:
        offset + ciphertext_length
    ]

    if len(ciphertext) != ciphertext_length:

        raise ValueError(
            "Incomplete ciphertext."
        )

    return (
        received_hmac,
        ascon_key,
        nonce,
        ciphertext
    )


# ============================================================
# EXTRACT PAYLOAD
# ============================================================

def extract_payload_fields(
    plaintext
):

    offset = 0

    # --------------------------------------------------------
    # PATIENT NAME
    # --------------------------------------------------------

    if len(plaintext) < offset + 2:

        raise ValueError(
            "Invalid patient field."
        )

    patient_length = struct.unpack(
        "!H",
        plaintext[
            offset:
            offset + 2
        ]
    )[0]

    offset += 2

    if len(plaintext) < offset + patient_length:

        raise ValueError(
            "Invalid patient name."
        )

    patient_name = plaintext[
        offset:
        offset + patient_length
    ].decode(
        "utf-8"
    )

    offset += patient_length

    # --------------------------------------------------------
    # FILENAME
    # --------------------------------------------------------

    if len(plaintext) < offset + 2:

        raise ValueError(
            "Invalid filename field."
        )

    filename_length = struct.unpack(
        "!H",
        plaintext[
            offset:
            offset + 2
        ]
    )[0]

    offset += 2

    if len(plaintext) < offset + filename_length:

        raise ValueError(
            "Invalid filename."
        )

    filename = plaintext[
        offset:
        offset + filename_length
    ].decode(
        "utf-8"
    )

    offset += filename_length

    # --------------------------------------------------------
    # IMAGE DATA
    # --------------------------------------------------------

    image_data = plaintext[
        offset:
    ]

    return (
        patient_name,
        filename,
        image_data
    )


# ============================================================
# RECEIVE IMAGE
# ============================================================

def receive_image(
    sock,
    challenge
):

    # --------------------------------------------------------
    # RECEIVE PACKET LENGTH
    # --------------------------------------------------------

    packet_length_data = recv_exact(
        sock,
        8
    )

    if packet_length_data is None:
        return

    packet_length = struct.unpack(
        "!Q",
        packet_length_data
    )[0]

    if packet_length == 0:
        return

    # --------------------------------------------------------
    # RECEIVE PACKET
    # --------------------------------------------------------

    packet = recv_exact(
        sock,
        packet_length
    )

    if packet is None:
        return

    # --------------------------------------------------------
    # PARSE PACKET
    # --------------------------------------------------------

    try:

        (
            received_hmac,
            ascon_key,
            nonce,
            ciphertext
        ) = parse_packet(
            packet
        )

    except Exception:
        return

    if len(ciphertext) < ASCON_TAG_SIZE:
        return

    # --------------------------------------------------------
    # EXTRACT ASCON TAG
    # --------------------------------------------------------

    ascon_tag = (
        ciphertext[
            -ASCON_TAG_SIZE:
        ]
    )

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    authenticated = authenticate_receiver(
        challenge,
        RECEIVER_ID,
        received_hmac,
        ascon_tag
    )

    if not authenticated:
        return

    # --------------------------------------------------------
    # ASCON DECRYPTION
    # --------------------------------------------------------

    try:

        start_time = time.perf_counter()

        plaintext = ascon_decrypt_c(
            ascon_key,
            nonce,
            AAD,
            ciphertext
        )

        elapsed = (
            time.perf_counter()
            - start_time
        )

    except Exception:
        return

    # --------------------------------------------------------
    # EXTRACT PATIENT / FILE
    # --------------------------------------------------------

    try:

        (
            patient_name,
            filename,
            image_data
        ) = extract_payload_fields(
            plaintext
        )

    except Exception:
        return

    # --------------------------------------------------------
    # PERFORMANCE
    # --------------------------------------------------------

    image_size_mb = (
        len(image_data)
        / (1024 * 1024)
    )

    decryption_time_ms = (
        elapsed * 1000
    )

    if elapsed > 0:

        throughput = (
            image_size_mb
            / elapsed
        )

    else:

        throughput = 0

    # --------------------------------------------------------
    # SAVE IMAGE
    # --------------------------------------------------------

    patient_folder = os.path.join(
        OUTPUT_FOLDER,
        sanitize_folder_name(
            patient_name
        )
    )

    os.makedirs(
        patient_folder,
        exist_ok=True
    )

    output_path = os.path.join(
        patient_folder,
        filename
    )

    with open(
        output_path,
        "wb"
    ) as file:

        file.write(
            image_data
        )

    # --------------------------------------------------------
    # ONLY PRINT THESE VALUES
    # --------------------------------------------------------

    print(
        f"Patient name : {patient_name}"
    )

    print(
        f"File name    : {filename}"
    )

    print(
        f"Image size   : {image_size_mb:.3f} MB"
    )

    print(
        f"Decryption   : {decryption_time_ms:.3f} ms"
    )

    print(
        f"Throughput   : {throughput:.3f} MB/s"
    )


# ============================================================
# HANDLE CHALLENGE
# ============================================================

def handle_challenge(sock):

    id_length_data = recv_exact(
        sock,
        2
    )

    if id_length_data is None:

        raise ValueError(
            "Missing receiver ID length."
        )

    id_length = struct.unpack(
        "!H",
        id_length_data
    )[0]

    received_receiver_id = recv_exact(
        sock,
        id_length
    )

    if received_receiver_id is None:

        raise ValueError(
            "Missing receiver ID."
        )

    received_receiver_id = (
        received_receiver_id.decode(
            "utf-8"
        )
    )

    challenge = recv_exact(
        sock,
        CHALLENGE_SIZE
    )

    if challenge is None:

        raise ValueError(
            "Missing challenge."
        )

    return challenge


# ============================================================
# CONNECTION HANDLING
# ============================================================

def handle_connection(
    sock,
    challenge
):

    message_type = recv_exact(
        sock,
        1
    )

    if message_type is None:

        return challenge

    # --------------------------------------------------------
    # CHALLENGE
    # --------------------------------------------------------

    if message_type == b"A":

        challenge = handle_challenge(
            sock
        )

    # --------------------------------------------------------
    # IMAGE
    # --------------------------------------------------------

    elif message_type == b"I":

        if challenge is not None:

            receive_image(
                sock,
                challenge
            )

    return challenge


# ============================================================
# SERVER
# ============================================================

def main():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (
            "0.0.0.0",
            TCP_PORT
        )
    )

    server.listen(5)

    challenge = None

    try:

        while True:

            sock, address = (
                server.accept()
            )

            try:

                challenge = (
                    handle_connection(
                        sock,
                        challenge
                    )
                )

            except Exception:
                pass

            finally:

                sock.close()

    except KeyboardInterrupt:

        pass

    finally:

        server.close()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()