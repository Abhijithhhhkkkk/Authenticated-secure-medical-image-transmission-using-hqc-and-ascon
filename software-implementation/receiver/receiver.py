import hashlib
import hmac
import os
import socket
import struct

from dotenv import load_dotenv
from ascon import decrypt

# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

TCP_PORT = int(os.getenv("TCP_PORT", "5000"))

AAD = b"medical-image"

HMAC_SIZE = 32
CHALLENGE_SIZE = 32
ASCON_TAG_SIZE = 16

RECEIVER_ID = os.getenv("RECEIVER_ID", "receiver1")
IDENTITY_KEY = os.getenv("RECEIVER_KEY", "").encode()

OUTPUT_FOLDER = "received_images"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# ============================================================
# HELPERS
# ============================================================

def recv_exact(sock, size):
    """Read exactly `size` bytes from `sock`, or return None on EOF."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def calculate_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def sanitize_folder_name(name):
    """Make a patient name safe to use as a single folder component."""
    name = name.strip() or "unknown_patient"

    # Strip path separators and other characters that could escape
    # OUTPUT_FOLDER or break on the filesystem.
    invalid_chars = '/\\:*?"<>|'
    for char in invalid_chars:
        name = name.replace(char, "_")

    return name


# ============================================================
# AUTHENTICATION
# ============================================================

def authenticate_receiver(challenge, receiver_id, received_hmac, ascon_tag):
    receiver_id_bytes = receiver_id.encode()
    authentication_data = challenge + receiver_id_bytes + ascon_tag

    expected_hmac = calculate_hmac(IDENTITY_KEY, authentication_data)

    # --- debug ---
    print("RECV receiver_id :", receiver_id_bytes)
    print("RECV challenge   :", challenge.hex())
    print("RECV ascon_tag   :", ascon_tag.hex())
    print("RECV received_hmac:", received_hmac.hex())
    print("RECV expected_hmac:", expected_hmac.hex())
    # -------------

    if hmac.compare_digest(received_hmac, expected_hmac):
        print("HMAC authentication successful.")
        return True

    print("HMAC authentication failed.")
    return False


# ============================================================
# PACKET PARSING
# ============================================================

def parse_packet(packet):
    """Unpack the wire format into its component fields."""
    offset = 0

    hmac_length = struct.unpack("!B", packet[offset:offset + 1])[0]
    offset += 1

    received_hmac = packet[offset:offset + hmac_length]
    offset += hmac_length

    key_length = struct.unpack("!B", packet[offset:offset + 1])[0]
    offset += 1

    ascon_key = packet[offset:offset + key_length]
    offset += key_length

    nonce = packet[offset:offset + 16]
    offset += 16

    ciphertext_length = struct.unpack("!I", packet[offset:offset + 4])[0]
    offset += 4

    ciphertext = packet[offset:offset + ciphertext_length]

    return received_hmac, ascon_key, nonce, ciphertext


def extract_payload_fields(plaintext):
    """Pull patient name / filename / image bytes out of decrypted payload."""
    offset = 0

    patient_length = struct.unpack("!H", plaintext[offset:offset + 2])[0]
    offset += 2
    patient_name = plaintext[offset:offset + patient_length].decode()
    offset += patient_length

    filename_length = struct.unpack("!H", plaintext[offset:offset + 2])[0]
    offset += 2
    filename = plaintext[offset:offset + filename_length].decode()
    offset += filename_length

    image_data = plaintext[offset:]

    return patient_name, filename, image_data


# ============================================================
# IMAGE RECEPTION
# ============================================================

def receive_image(sock, challenge):
    packet_length_data = recv_exact(sock, 8)
    if packet_length_data is None:
        return

    packet_length = struct.unpack("!Q", packet_length_data)[0]

    packet = recv_exact(sock, packet_length)
    if packet is None:
        return

    received_hmac, ascon_key, nonce, ciphertext = parse_packet(packet)
    ascon_tag = ciphertext[-ASCON_TAG_SIZE:]
    print("ASCON authentication tag extracted.")

    # -------- authentication --------
    authenticated = authenticate_receiver(
        challenge, RECEIVER_ID, received_hmac, ascon_tag
    )

    if not authenticated:
        print("Authentication failed. Image will NOT be decrypted.")
        return

    # -------- decryption --------
    print("Authentication successful. Starting ASCON decryption...")
    try:
        plaintext = decrypt(ascon_key, nonce, AAD, ciphertext)
    except Exception:
        print("ASCON authentication/decryption failed.")
        return

    patient_name, filename, image_data = extract_payload_fields(plaintext)

    # One subfolder per patient, named after the patient.
    patient_folder = os.path.join(OUTPUT_FOLDER, sanitize_folder_name(patient_name))
    os.makedirs(patient_folder, exist_ok=True)

    output_path = os.path.join(patient_folder, filename)

    with open(output_path, "wb") as file:
        file.write(image_data)

    print("\n================================")
    print("IMAGE RECEIVED SUCCESSFULLY")
    print("================================")
    print(f"Patient  : {patient_name}")
    print(f"Filename : {filename}")
    print(f"Saved to : {output_path}")


# ============================================================
# CONNECTION HANDLING
# ============================================================

def handle_challenge(sock):
    """Read an 'A' (challenge) message and return (receiver_id, challenge)."""
    id_length_data = recv_exact(sock, 2)
    id_length = struct.unpack("!H", id_length_data)[0]

    received_receiver_id = recv_exact(sock, id_length).decode()
    challenge = recv_exact(sock, CHALLENGE_SIZE)

    print(f"Challenge received for {received_receiver_id}")
    return challenge


def handle_connection(sock, challenge):
    """Process one accepted connection; returns the (possibly updated) challenge."""
    message_type = recv_exact(sock, 1)

    if message_type == b"A":
        challenge = handle_challenge(sock)

    elif message_type == b"I":
        if challenge is None:
            print("No challenge available.")
        else:
            receive_image(sock, challenge)

    return challenge


# ============================================================
# SERVER
# ============================================================

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", TCP_PORT))
    server.listen(5)

    print(f"{RECEIVER_ID} listening on port {TCP_PORT}")

    challenge = None

    try:
        while True:
            sock, address = server.accept()
            try:
                challenge = handle_connection(sock, challenge)
            except Exception as e:
                print(f"Receiver error: {e}")
            finally:
                sock.close()
    except KeyboardInterrupt:
        print("\nShutting down receiver...")
    finally:
        server.close()


if __name__ == "__main__":
    main()