import socket
from pathlib import Path
from ascon import decrypt

HOST = "0.0.0.0"
PORT = 5000
AAD = b"medical-image"

SAVE_FOLDER = Path("receiver/img")
SAVE_FOLDER.mkdir(parents=True, exist_ok=True)


def receive_exact(conn, size):
    data = b""

    while len(data) < size:
        chunk = conn.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data += chunk

    return data


def receive_image(conn):

    # Receive packet size
    packet_size = int.from_bytes(
        receive_exact(conn, 8), "big"
    )

    # Receive complete packet
    packet = receive_exact(conn, packet_size)

    # ----------------------------
    # EXTRACT ASCON KEY
    # ----------------------------

    key_length = int.from_bytes(packet[0:2], "big")

    offset = 2

    ascon_key = packet[
        offset:offset + key_length
    ]

    offset += key_length

    # ----------------------------
    # EXTRACT NONCE
    # ----------------------------

    nonce = packet[
        offset:offset + 16
    ]

    offset += 16

    # ----------------------------
    # EXTRACT CIPHERTEXT
    # ----------------------------

    ciphertext_length = int.from_bytes(
        packet[offset:offset + 4],
        "big"
    )

    offset += 4

    ciphertext = packet[
        offset:offset + ciphertext_length
    ]

    # ----------------------------
    # ASCON DECRYPT + AUTHENTICATE
    # ----------------------------

    plaintext = decrypt(
        ascon_key,
        nonce,
        AAD,
        ciphertext
    )

    print("✓ Authentication successful")

    # ----------------------------
    # EXTRACT PATIENT NAME
    # ----------------------------

    offset = 0

    name_length = int.from_bytes(
        plaintext[offset:offset + 2],
        "big"
    )

    offset += 2

    patient_name = plaintext[
        offset:offset + name_length
    ].decode()

    offset += name_length

    # ----------------------------
    # EXTRACT FILENAME
    # ----------------------------

    filename_length = int.from_bytes(
        plaintext[offset:offset + 2],
        "big"
    )

    offset += 2

    filename = plaintext[
        offset:offset + filename_length
    ].decode()

    offset += filename_length

    # ----------------------------
    # IMAGE
    # ----------------------------

    image = plaintext[offset:]

    # ----------------------------
    # SAVE IMAGE
    # ----------------------------

    patient_folder = SAVE_FOLDER / patient_name
    patient_folder.mkdir(
        parents=True,
        exist_ok=True
    )

    output = patient_folder / filename
    output.write_bytes(image)

    print("Patient :", patient_name)
    print("Filename:", filename)
    print("Saved   :", output)


# ----------------------------
# RECEIVER
# ----------------------------

with socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
) as server:

    server.bind((HOST, PORT))
    server.listen(1)

    print(f"Waiting on port {PORT}...")

    while True:

        conn, address = server.accept()

        with conn:

            print("Connection:", address)

            try:
                receive_image(conn)

            except Exception as e:
                print("Authentication/receiving failed:", e)
