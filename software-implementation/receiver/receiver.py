import socket
import struct
import hmac
import hashlib
import csv
import time
import os
from pathlib import Path

from dotenv import load_dotenv
from ascon import decrypt


# ============================================================
# LOAD .ENV
# ============================================================

load_dotenv()

RECEIVER_ID = os.getenv("RECEIVER_ID", "receiver1")
TCP_HOST = os.getenv("TCP_HOST", "0.0.0.0")
TCP_PORT = int(os.getenv("TCP_PORT", "5000"))
RECEIVER_KEY = os.getenv("RECEIVER_KEY", "").encode()


# ============================================================
# CONFIGURATION
# ============================================================

SOCKET_TIMEOUT = 30
AAD = b"medical-image"

HMAC_SIZE = 32
CHALLENGE_SIZE = 32

MAX_PACKET_SIZE = 100 * 1024 * 1024


# ============================================================
# OUTPUT FOLDER
# ============================================================

RECEIVED_FOLDER = Path("received_images")


# ============================================================
# PERFORMANCE CSV
# ============================================================

CSV_FILE = Path("performance_log_receiver.csv")

CSV_FIELDS = [
    "Receiver_ID",
    "Filename",
    "Patient",
    "ImageSizeKB",
    "Decryption_Time",
    "Reception_Time",
    "Overall_Delay",
    "Throughput_KBps"
]


# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

def validate_configuration():
    if not RECEIVER_KEY:
        raise ValueError("RECEIVER_KEY missing in .env")

    if len(RECEIVER_KEY) == 0:
        raise ValueError("Receiver HMAC key cannot be empty.")


# ============================================================
# INITIALIZE DIRECTORIES
# ============================================================

def initialize_directories():
    RECEIVED_FOLDER.mkdir(parents=True, exist_ok=True)


# ============================================================
# INITIALIZE CSV
# ============================================================

def initialize_csv():
    if not CSV_FILE.exists():
        with open(CSV_FILE, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
            writer.writeheader()


# ============================================================
# RECEIVE EXACT NUMBER OF BYTES
# ============================================================

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ============================================================
# HMAC
# ============================================================

def calculate_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


# ============================================================
# AUTHENTICATE SENDER
# ============================================================

def authenticate_sender(sock):
    authentication_start = time.perf_counter()

    # --------------------------------------------------------
    # Receive authentication request: A + 32-byte challenge
    # --------------------------------------------------------
    request_type = recv_exact(sock, 1)
    if request_type != b"A":
        print("Invalid authentication request.")
        return False

    challenge = recv_exact(sock, CHALLENGE_SIZE)
    if challenge is None:
        print("Challenge not received.")
        return False

    print("\nChallenge received.")

    # --------------------------------------------------------
    # Calculate HMAC(Receiver_Key, Challenge || Receiver_ID)
    # --------------------------------------------------------
    authentication_data = challenge + RECEIVER_ID.encode()
    response_hmac = calculate_hmac(RECEIVER_KEY, authentication_data)

    # --------------------------------------------------------
    # Send response: R + HMAC
    # --------------------------------------------------------
    sock.sendall(b"R" + response_hmac)

    # --------------------------------------------------------
    # Receive authentication result
    # --------------------------------------------------------
    result = recv_exact(sock, 1)
    if result != b"O":
        print("\nAuthentication rejected by sender.")
        return False

    authentication_time = time.perf_counter() - authentication_start

    print("\n============================================")
    print("AUTHENTICATION SUCCESSFUL")
    print("============================================")
    print(f"Receiver ID         : {RECEIVER_ID}")
    print(f"Authentication time : {authentication_time:.6f} sec")
    print("============================================")

    return True


# ============================================================
# RECEIVE SECURE PACKET
# ============================================================

def receive_secure_packet(sock):
    # --------------------------------------------------------
    # Receive message type: I = image
    # --------------------------------------------------------
    message_type = recv_exact(sock, 1)
    if message_type != b"I":
        print("Invalid message type.")
        return None

    # --------------------------------------------------------
    # Receive packet length (8-byte unsigned integer)
    # --------------------------------------------------------
    packet_length_data = recv_exact(sock, 8)
    if packet_length_data is None:
        print("Packet length not received.")
        return None

    packet_length = struct.unpack("!Q", packet_length_data)[0]
    print(f"\nEncrypted packet size : {packet_length} bytes")

    # --------------------------------------------------------
    # Security check
    # --------------------------------------------------------
    if packet_length <= 0:
        print("Invalid packet size.")
        return None

    if packet_length > MAX_PACKET_SIZE:
        print("Packet exceeds maximum allowed size.")
        return None

    # --------------------------------------------------------
    # Receive packet
    # --------------------------------------------------------
    reception_start = time.perf_counter()
    packet = recv_exact(sock, packet_length)
    reception_time = time.perf_counter() - reception_start

    if packet is None:
        print("Incomplete packet received.")
        return None

    print(f"Packet received in {reception_time:.6f} sec")

    return packet, reception_time


# ============================================================
# PARSE SECURE PACKET
# ============================================================

def parse_secure_packet(packet):
    offset = 0

    # --------------------------------------------------------
    # ASCON key length
    # --------------------------------------------------------
    if len(packet) < 1:
        raise ValueError("Invalid packet.")

    key_length = struct.unpack("!B", packet[offset:offset + 1])[0]
    offset += 1

    if key_length != 16:
        raise ValueError("Invalid ASCON-128 key length.")

    # --------------------------------------------------------
    # ASCON key
    # --------------------------------------------------------
    if offset + key_length > len(packet):
        raise ValueError("Incomplete ASCON key.")

    ascon_key = packet[offset:offset + key_length]
    offset += key_length

    # --------------------------------------------------------
    # Nonce
    # --------------------------------------------------------
    nonce_length = 16

    if offset + nonce_length > len(packet):
        raise ValueError("Incomplete nonce.")

    nonce = packet[offset:offset + nonce_length]
    offset += nonce_length

    # --------------------------------------------------------
    # Ciphertext length
    # --------------------------------------------------------
    if offset + 4 > len(packet):
        raise ValueError("Missing ciphertext length.")

    ciphertext_length = struct.unpack("!I", packet[offset:offset + 4])[0]
    offset += 4

    if ciphertext_length <= 0:
        raise ValueError("Invalid ciphertext length.")

    if offset + ciphertext_length > len(packet):
        raise ValueError("Incomplete ciphertext.")

    # --------------------------------------------------------
    # Ciphertext
    # --------------------------------------------------------
    ciphertext = packet[offset:offset + ciphertext_length]

    return ascon_key, nonce, ciphertext


# ============================================================
# ASCON DECRYPTION
# ============================================================

def decrypt_image(ascon_key, nonce, ciphertext):
    start_time = time.perf_counter()
    plaintext = decrypt(ascon_key, nonce, AAD, ciphertext)
    decryption_time = time.perf_counter() - start_time

    if plaintext is None:
        raise ValueError("ASCON authentication failed.")

    return plaintext, decryption_time


# ============================================================
# EXTRACT IMAGE PAYLOAD
# ============================================================

def extract_image_payload(plaintext):
    offset = 0

    # --------------------------------------------------------
    # Patient name
    # --------------------------------------------------------
    if len(plaintext) < 2:
        raise ValueError("Invalid plaintext.")

    patient_length = struct.unpack("!H", plaintext[offset:offset + 2])[0]
    offset += 2

    if offset + patient_length > len(plaintext):
        raise ValueError("Invalid patient name.")

    patient_name = plaintext[offset:offset + patient_length].decode(
        "utf-8", errors="replace"
    )
    offset += patient_length

    # --------------------------------------------------------
    # Filename
    # --------------------------------------------------------
    if offset + 2 > len(plaintext):
        raise ValueError("Missing filename length.")

    filename_length = struct.unpack("!H", plaintext[offset:offset + 2])[0]
    offset += 2

    if offset + filename_length > len(plaintext):
        raise ValueError("Invalid filename.")

    filename = plaintext[offset:offset + filename_length].decode(
        "utf-8", errors="replace"
    )
    offset += filename_length

    # --------------------------------------------------------
    # Image data
    # --------------------------------------------------------
    image_data = plaintext[offset:]

    if not image_data:
        raise ValueError("Image data is empty.")

    return patient_name, filename, image_data


# ============================================================
# SANITIZE FOLDER / FILE NAME
# ============================================================

def sanitize_name(name):
    invalid_chars = '<>:"/\\|?*'

    for char in invalid_chars:
        name = name.replace(char, "_")

    name = name.strip()

    return name if name else "unknown"


# ============================================================
# SAVE MEDICAL IMAGE
# ============================================================

def save_image(patient_name, filename, image_data):
    safe_patient = sanitize_name(patient_name)
    safe_filename = sanitize_name(Path(filename).name)

    patient_folder = RECEIVED_FOLDER / safe_patient
    patient_folder.mkdir(parents=True, exist_ok=True)

    output_path = patient_folder / safe_filename

    # Prevent accidental overwrite
    if output_path.exists():
        timestamp = int(time.time())
        output_path = (
            patient_folder / f"{output_path.stem}_{timestamp}{output_path.suffix}"
        )

    output_path.write_bytes(image_data)

    return output_path


# ============================================================
# SAVE PERFORMANCE
# ============================================================

def save_performance(
    receiver_id, filename, patient_name, image_size_kb,
    decryption_time, reception_time
):
    overall_delay = decryption_time + reception_time
    throughput = image_size_kb / reception_time if reception_time > 0 else 0

    initialize_csv()

    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writerow({
            "Receiver_ID": receiver_id,
            "Filename": filename,
            "Patient": patient_name,
            "ImageSizeKB": f"{image_size_kb:.2f}",
            "Decryption_Time": f"{decryption_time:.6f}",
            "Reception_Time": f"{reception_time:.6f}",
            "Overall_Delay": f"{overall_delay:.6f}",
            "Throughput_KBps": f"{throughput:.2f}"
        })

    return overall_delay, throughput


# ============================================================
# PROCESS ONE IMAGE
# ============================================================

def process_image(packet, reception_time):
    # --------------------------------------------------------
    # Parse packet
    # --------------------------------------------------------
    ascon_key, nonce, ciphertext = parse_secure_packet(packet)

    print("\n============================================")
    print("ASCON DECRYPTION")
    print("============================================")

    # --------------------------------------------------------
    # Decrypt
    # --------------------------------------------------------
    plaintext, decryption_time = decrypt_image(ascon_key, nonce, ciphertext)

    print("ASCON authentication successful.")
    print(f"Decryption time : {decryption_time:.6f} sec")

    # --------------------------------------------------------
    # Extract payload
    # --------------------------------------------------------
    patient_name, filename, image_data = extract_image_payload(plaintext)

    # --------------------------------------------------------
    # Save image
    # --------------------------------------------------------
    output_path = save_image(patient_name, filename, image_data)
    image_size_kb = len(image_data) / 1024

    # --------------------------------------------------------
    # Performance
    # --------------------------------------------------------
    overall_delay, throughput = save_performance(
        RECEIVER_ID, filename, patient_name, image_size_kb,
        decryption_time, reception_time
    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------
    print("\n============================================")
    print("MEDICAL IMAGE RECEIVED")
    print("============================================")
    print(f"Receiver        : {RECEIVER_ID}")
    print(f"Patient         : {patient_name}")
    print(f"Filename        : {filename}")
    print(f"Image size      : {image_size_kb:.2f} KB")
    print(f"Decryption time : {decryption_time:.6f} sec")
    print(f"Reception time  : {reception_time:.6f} sec")
    print(f"Overall delay   : {overall_delay:.6f} sec")
    print(f"Throughput      : {throughput:.2f} KB/s")
    print(f"Saved to        : {output_path}")
    print("============================================")


# ============================================================
# HANDLE CLIENT
# ============================================================

def handle_client(client_socket, client_address):
    print("\n============================================")
    print("NEW TCP CONNECTION")
    print("============================================")
    print(f"Client : {client_address[0]}")
    print(f"Port   : {client_address[1]}")

    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        # --------------------------------------------------------
        # Authenticate sender
        # --------------------------------------------------------
        authenticated = authenticate_sender(client_socket)

        if not authenticated:
            print("\nSender authentication failed.")
            return

        # --------------------------------------------------------
        # Receive image
        # --------------------------------------------------------
        result = receive_secure_packet(client_socket)

        if result is None:
            return

        packet, reception_time = result

        # --------------------------------------------------------
        # Process image
        # --------------------------------------------------------
        process_image(packet, reception_time)

    except socket.timeout:
        print("\nConnection timed out.")

    except ConnectionResetError:
        print("\nConnection reset by sender.")

    except ValueError as e:
        print(f"\nPacket/decryption error: {e}")

    except Exception as e:
        print(f"\nReceiver error: {e}")

    finally:
        client_socket.close()
        print("\nTCP connection closed.")


# ============================================================
# START RECEIVER
# ============================================================

def main():
    print("\n============================================")
    print(" SECURE MEDICAL IMAGE RECEIVER")
    print("============================================")
    print(f"Receiver ID    : {RECEIVER_ID}")
    print(f"Listen address : {TCP_HOST}")
    print(f"TCP Port       : {TCP_PORT}")
    print("Authentication : HMAC-SHA256")
    print("Encryption     : ASCON-128")
    print(f"Output folder  : {RECEIVED_FOLDER}")
    print("============================================")

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------
    validate_configuration()
    initialize_directories()
    initialize_csv()

    # --------------------------------------------------------
    # Create TCP server
    # --------------------------------------------------------
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow quick restart
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((TCP_HOST, TCP_PORT))
    server_socket.listen(5)

    print("\n============================================")
    print("RECEIVER STARTED")
    print("============================================")
    print(f"Listening on {TCP_HOST}:{TCP_PORT}")
    print("Waiting for medical image...")
    print("Press Ctrl+C to stop.")
    print("============================================")

    try:
        while True:
            client_socket, client_address = server_socket.accept()

            handle_client(client_socket, client_address)

            print("\nWaiting for next image...")

    except KeyboardInterrupt:
        print("\n\nStopping receiver...")

    finally:
        server_socket.close()
        print("Receiver stopped.")


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
