import ctypes
import hashlib
import hmac
import os
import queue
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Bidirectional medical-image peer. Every device runs this same script.
load_dotenv()

DEVICE_ID = os.getenv("DEVICE_ID", "device1").strip()
# LISTEN_PORT is this device's incoming/receiver port. PEERn_PORT is the
# remote device's listening port used when this device sends an image.
# TCP_PORT remains a backwards-compatible default for older .env files.
LISTEN_PORT = int(os.getenv("LISTEN_PORT", os.getenv("TCP_PORT", "5000")))
DEFAULT_PEER_PORT = int(os.getenv("TCP_PORT", str(LISTEN_PORT)))
SOCKET_TIMEOUT = int(os.getenv("SOCKET_TIMEOUT", "30"))
IMAGE_FOLDER = Path(os.getenv("IMAGE_FOLDER", str(Path(__file__).resolve().parent / "img"))).resolve()
OUTPUT_FOLDER = Path(os.getenv("OUTPUT_FOLDER", str(Path(__file__).resolve().parent / "received_images"))).resolve()
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
CHALLENGE_SIZE = 32
ASCON_KEY_SIZE = 16
ASCON_NONCE_SIZE = 16
ASCON_TAG_SIZE = 16
HMAC_SIZE = 32
MAX_PACKET_SIZE = int(os.getenv("MAX_PACKET_SIZE", str(512 * 1024 * 1024)))
PROTOCOL_LABEL = b"medical-image-peer-v1"

# Keep the C wrapper/library beside this script. Expected functions:
# int ascon_encrypt_c(key, nonce, aad, aad_len, plaintext, plaintext_len, ciphertext)
# int ascon_decrypt_c(key, nonce, aad, aad_len, ciphertext, ciphertext_len, plaintext)
BASE_DIR = Path(__file__).resolve().parent
ASCON_LIBRARY = Path(os.getenv("ASCON_LIBRARY", str(BASE_DIR / "libascon.so")))
if not ASCON_LIBRARY.exists():
    raise FileNotFoundError(
        f"ASCON library not found: {ASCON_LIBRARY}\n"
        "Compile your existing C wrapper with: gcc -O3 -fPIC -shared ascon_wrapper.c -o libascon.so"
    )
ascon_lib = ctypes.CDLL(str(ASCON_LIBRARY))
_u8p = ctypes.POINTER(ctypes.c_ubyte)
ascon_lib.ascon_encrypt_c.argtypes = [_u8p, _u8p, _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p]
ascon_lib.ascon_encrypt_c.restype = ctypes.c_int
ascon_lib.ascon_decrypt_c.argtypes = [_u8p, _u8p, _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p]
ascon_lib.ascon_decrypt_c.restype = ctypes.c_int


def env_secret(name: str) -> bytes:
    value = os.getenv(name, "").strip()
    if not value:
        return b""
    # A 64-character hexadecimal value is treated as a 32-byte secret.
    if len(value) == 64:
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass
    return value.encode("utf-8")


# Configure peers with PEER1_ID, PEER1_IP, PEER1_SHARED_SECRET, PEER2_..., etc.
# For backward compatibility, PEER1_SHARED_SECRET can fall back to RECEIVER1_KEY.
def load_peers():
    peers = {}
    for index in range(1, 33):
        peer_id = os.getenv(f"PEER{index}_ID", "").strip()
        peer_ip = os.getenv(f"PEER{index}_IP", "").strip()
        secret = env_secret(f"PEER{index}_SHARED_SECRET")
        if not secret:
            secret = env_secret(f"RECEIVER{index}_KEY")
        # The original receiver code used RECEIVER_KEY for its configured peer.
        if not secret and index == 1:
            secret = env_secret("RECEIVER_KEY")
        if not peer_id and not peer_ip and not secret:
            continue
        if not peer_id or not peer_ip or not secret:
            raise ValueError(
                f"Incomplete peer configuration PEER{index}_*: set ID, IP, and SHARED_SECRET"
            )
        if peer_id == DEVICE_ID:
            raise ValueError(f"Peer ID {peer_id!r} cannot equal DEVICE_ID")
        if peer_id in peers:
            raise ValueError(f"Duplicate peer ID: {peer_id}")
        if len(secret) < 16:
            raise ValueError(
                f"Shared secret for {peer_id} is too short. Use at least 16 random bytes; 32 bytes is recommended."
            )
        peer_port_text = os.getenv(f"PEER{index}_PORT", str(DEFAULT_PEER_PORT)).strip()
        try:
            peer_port = int(peer_port_text)
        except ValueError as exc:
            raise ValueError(f"PEER{index}_PORT must be an integer") from exc
        if not 1 <= peer_port <= 65535:
            raise ValueError(f"PEER{index}_PORT must be between 1 and 65535")
        peers[peer_id] = {"ip": peer_ip, "port": peer_port, "secret": secret}
    return peers


PEERS = load_peers()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_session_keys(shared_secret: bytes, challenge: bytes, id_a: str, id_b: str):
    # Stable identity ordering ensures both sides derive the same keys regardless of direction.
    first, second = sorted((id_a.encode("utf-8"), id_b.encode("utf-8")))
    salt = hashlib.sha256(PROTOCOL_LABEL + challenge).digest()
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    context = PROTOCOL_LABEL + struct.pack("!H", len(first)) + first + struct.pack("!H", len(second)) + second
    ascon_key = hkdf_expand(prk, b"ascon-key\x00" + context, ASCON_KEY_SIZE)
    hmac_key = hkdf_expand(prk, b"hmac-key\x00" + context, HMAC_SIZE)
    return ascon_key, hmac_key


def calculate_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _buffer(data: bytes):
    # ctypes cannot create a zero-length buffer reliably; use a one-byte placeholder.
    raw = data if data else b"\x00"
    return (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)


def ascon_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    if len(key) != ASCON_KEY_SIZE or len(nonce) != ASCON_NONCE_SIZE:
        raise ValueError("Ascon key and nonce must each be 16 bytes for this wrapper.")
    ciphertext = bytearray(len(plaintext) + ASCON_TAG_SIZE)
    key_b, nonce_b, aad_b, plain_b = map(_buffer, (key, nonce, aad, plaintext))
    cipher_b = (ctypes.c_ubyte * len(ciphertext)).from_buffer(ciphertext)
    result = ascon_lib.ascon_encrypt_c(key_b, nonce_b, aad_b, len(aad), plain_b, len(plaintext), cipher_b)
    if result != 0:
        raise RuntimeError("C Ascon encryption failed")
    return bytes(ciphertext)


def ascon_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    if len(key) != ASCON_KEY_SIZE or len(nonce) != ASCON_NONCE_SIZE:
        raise ValueError("Ascon key and nonce must each be 16 bytes for this wrapper.")
    if len(ciphertext) < ASCON_TAG_SIZE:
        raise ValueError("Ciphertext is shorter than the Ascon tag.")
    plaintext = bytearray(len(ciphertext) - ASCON_TAG_SIZE)
    key_b, nonce_b, aad_b, cipher_b = map(_buffer, (key, nonce, aad, ciphertext))
    plain_b = (ctypes.c_ubyte * len(plaintext)).from_buffer(plaintext) if plaintext else _buffer(b"")
    result = ascon_lib.ascon_decrypt_c(key_b, nonce_b, aad_b, len(aad), cipher_b, len(ciphertext), plain_b)
    if result != 0:
        raise ValueError("Ascon authentication/decryption failed")
    return bytes(plaintext)


def send_frame(sock: socket.socket, payload: bytes):
    if len(payload) > MAX_PACKET_SIZE:
        raise ValueError("Packet exceeds configured maximum size")
    sock.sendall(struct.pack("!Q", len(payload)) + payload)


def recv_exact(sock: socket.socket, size: int):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock: socket.socket):
    header = recv_exact(sock, 8)
    if header is None:
        return None
    length = struct.unpack("!Q", header)[0]
    if length <= 0 or length > MAX_PACKET_SIZE:
        raise ValueError("Invalid packet length")
    return recv_exact(sock, length)


def pack_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 65535:
        raise ValueError("Text field too long")
    return struct.pack("!H", len(encoded)) + encoded


def unpack_text(data: bytes, offset: int):
    if len(data) < offset + 2:
        raise ValueError("Truncated text field")
    size = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    if len(data) < offset + size:
        raise ValueError("Truncated text value")
    value = data[offset:offset + size].decode("utf-8")
    return value, offset + size


def make_aad(challenge: bytes, sender_id: str, receiver_id: str) -> bytes:
    return PROTOCOL_LABEL + b"/image/" + challenge + pack_text(sender_id) + pack_text(receiver_id)


def make_proof(label: bytes, key: bytes, challenge: bytes, sender_id: str, receiver_id: str) -> bytes:
    transcript = label + challenge + pack_text(sender_id) + pack_text(receiver_id)
    return calculate_hmac(key, transcript)


def build_payload(image_path: Path, patient_name: str) -> bytes:
    patient_bytes = patient_name.encode("utf-8")
    filename_bytes = image_path.name.encode("utf-8")
    image_bytes = image_path.read_bytes()
    if not image_bytes:
        raise ValueError("Image file is empty")
    return pack_text(patient_name) + pack_text(image_path.name) + image_bytes


def parse_payload(payload: bytes):
    patient, offset = unpack_text(payload, 0)
    filename, offset = unpack_text(payload, offset)
    image_data = payload[offset:]
    if not image_data:
        raise ValueError("Image payload is empty")
    safe_filename = Path(filename).name
    if safe_filename != filename or Path(filename).suffix.lower() not in IMAGE_EXTENSIONS:
        raise ValueError("Invalid image filename/extension")
    return patient, safe_filename, image_data


def sanitize_folder_name(name: str) -> str:
    name = name.strip() or "unknown_patient"
    for char in '/\\:*?"<>|':
        name = name.replace(char, "_")
    name = name.strip(" .")
    return name or "unknown_patient"


def send_image_to_peer(image_path: Path, peer_id: str, patient_name: str):
    peer = PEERS[peer_id]
    shared_secret = peer["secret"]
    start_overall = time.perf_counter()
    with socket.create_connection((peer["ip"], peer["port"]), timeout=SOCKET_TIMEOUT) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        hello = b"H" + pack_text(DEVICE_ID) + pack_text(peer_id)
        send_frame(sock, hello)

        challenge_packet = recv_frame(sock)
        if not challenge_packet or len(challenge_packet) != 1 + CHALLENGE_SIZE or challenge_packet[:1] != b"C":
            raise ValueError("Invalid challenge from peer")
        challenge = challenge_packet[1:]
        ascon_key, hmac_key = derive_session_keys(shared_secret, challenge, DEVICE_ID, peer_id)

        client_proof = make_proof(b"client-proof-v1", hmac_key, challenge, DEVICE_ID, peer_id)
        send_frame(sock, b"P" + client_proof)

        server_proof_packet = recv_frame(sock)
        expected_server_proof = make_proof(b"server-proof-v1", hmac_key, challenge, DEVICE_ID, peer_id)
        if not server_proof_packet or server_proof_packet != b"R" + expected_server_proof:
            raise PermissionError("Peer authentication failed")

        payload = build_payload(image_path, patient_name)
        nonce = secrets.token_bytes(ASCON_NONCE_SIZE)
        aad = make_aad(challenge, DEVICE_ID, peer_id)
        encrypt_start = time.perf_counter()
        ciphertext = ascon_encrypt(ascon_key, nonce, aad, payload)
        encrypt_elapsed = time.perf_counter() - encrypt_start

        # HMAC binds the complete encrypted image packet; neither derived key is transmitted.
        packet_mac = calculate_hmac(
            hmac_key,
            b"image-packet-v1" + challenge + pack_text(DEVICE_ID) + pack_text(peer_id) + nonce + ciphertext,
        )
        image_packet = b"I" + nonce + struct.pack("!Q", len(ciphertext)) + ciphertext + packet_mac
        send_frame(sock, image_packet)

    size_mb = len(payload) / (1024 * 1024)
    print("\n========== ASCON PERFORMANCE ==========")
    print(f"File name            : {image_path.name}")
    print(f"Patient name         : {patient_name}")
    print(f"Image size           : {size_mb:.3f} MB")
    print(f"Encryption time      : {encrypt_elapsed * 1000:.3f} ms")
    print(f"Encryption throughput: {size_mb / encrypt_elapsed:.3f} MB/s" if encrypt_elapsed > 0 else "Encryption throughput: 0.000 MB/s")
    print(f"Overall send delay   : {(time.perf_counter() - start_overall) * 1000:.3f} ms")
    print("Image transmission completed.")


def handle_incoming_connection(sock: socket.socket, address):
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        hello = recv_frame(sock)
        if not hello or not hello.startswith(b"H"):
            raise ValueError("Expected handshake")
        sender_id, offset = unpack_text(hello, 1)
        receiver_id, offset = unpack_text(hello, offset)
        if offset != len(hello):
            raise ValueError("Malformed handshake")
        if receiver_id != DEVICE_ID:
            raise PermissionError("Connection addressed to a different device")
        if sender_id not in PEERS:
            raise PermissionError("Unknown peer")

        shared_secret = PEERS[sender_id]["secret"]
        challenge = secrets.token_bytes(CHALLENGE_SIZE)
        send_frame(sock, b"C" + challenge)
        ascon_key, hmac_key = derive_session_keys(shared_secret, challenge, sender_id, receiver_id)

        proof_packet = recv_frame(sock)
        expected_client_proof = make_proof(b"client-proof-v1", hmac_key, challenge, sender_id, receiver_id)
        if proof_packet != b"P" + expected_client_proof:
            raise PermissionError("Sender authentication failed")

        server_proof = make_proof(b"server-proof-v1", hmac_key, challenge, sender_id, receiver_id)
        send_frame(sock, b"R" + server_proof)

        image_packet = recv_frame(sock)
        if not image_packet or len(image_packet) < 1 + ASCON_NONCE_SIZE + 8 + ASCON_TAG_SIZE + HMAC_SIZE or image_packet[:1] != b"I":
            raise ValueError("Invalid image packet")
        offset = 1
        nonce = image_packet[offset:offset + ASCON_NONCE_SIZE]
        offset += ASCON_NONCE_SIZE
        ciphertext_len = struct.unpack("!Q", image_packet[offset:offset + 8])[0]
        offset += 8
        if ciphertext_len < ASCON_TAG_SIZE or ciphertext_len > MAX_PACKET_SIZE:
            raise ValueError("Invalid ciphertext size")
        if len(image_packet) != offset + ciphertext_len + HMAC_SIZE:
            raise ValueError("Image packet length mismatch")
        ciphertext = image_packet[offset:offset + ciphertext_len]
        received_mac = image_packet[offset + ciphertext_len:]
        expected_mac = calculate_hmac(
            hmac_key,
            b"image-packet-v1" + challenge + pack_text(sender_id) + pack_text(receiver_id) + nonce + ciphertext,
        )
        if not hmac.compare_digest(received_mac, expected_mac):
            raise PermissionError("Image packet HMAC verification failed")

        aad = make_aad(challenge, sender_id, receiver_id)
        decrypt_start = time.perf_counter()
        plaintext = ascon_decrypt(ascon_key, nonce, aad, ciphertext)
        decrypt_elapsed = time.perf_counter() - decrypt_start
        patient_name, filename, image_data = parse_payload(plaintext)

        patient_folder = OUTPUT_FOLDER / sanitize_folder_name(patient_name)
        patient_folder.mkdir(parents=True, exist_ok=True)
        output_path = patient_folder / filename
        temp_path = output_path.with_name(output_path.name + ".part")
        temp_path.write_bytes(image_data)
        temp_path.replace(output_path)

        size_mb = len(image_data) / (1024 * 1024)
        print("\n========== IMAGE RECEIVED ==========")
        print(f"Sender               : {sender_id}")
        print(f"Patient name         : {patient_name}")
        print(f"File name            : {filename}")
        print(f"Image size           : {size_mb:.3f} MB")
        print(f"Decryption time      : {decrypt_elapsed * 1000:.3f} ms")
        print(f"Decryption throughput: {size_mb / decrypt_elapsed:.3f} MB/s" if decrypt_elapsed > 0 else "Decryption throughput: 0.000 MB/s")
        print(f"Saved to             : {output_path}")
    except Exception as exc:
        # Do not expose keys, proofs, challenges, or raw packet contents.
        print(f"Incoming transfer from {address[0]} rejected/failed: {exc}")


def server_loop():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(16)
    print(f"[{DEVICE_ID}] Listening for incoming transfers on TCP port {LISTEN_PORT}")
    try:
        while True:
            conn, address = server.accept()
            threading.Thread(target=handle_incoming_connection, args=(conn, address), daemon=True).start()
    finally:
        server.close()


class UploadHandler(FileSystemEventHandler):
    def __init__(self, upload_queue):
        self.upload_queue = upload_queue

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in IMAGE_EXTENSIONS:
            self.upload_queue.put(path)

    def on_moved(self, event):
        if event.is_directory:
            return
        path = Path(event.dest_path)
        if path.suffix.lower() in IMAGE_EXTENSIONS:
            self.upload_queue.put(path)


def select_peer():
    peer_ids = list(PEERS)
    if not peer_ids:
        raise RuntimeError("No peers configured. Add PEER1_ID/IP/SHARED_SECRET to .env")
    print("\nAVAILABLE PEERS")
    for index, peer_id in enumerate(peer_ids, 1):
        print(f"{index}. {peer_id} ({PEERS[peer_id]['ip']})")
    while True:
        choice = input("Select receiving peer: ").strip()
        try:
            number = int(choice)
            if 1 <= number <= len(peer_ids):
                return peer_ids[number - 1]
        except ValueError:
            pass
        print("Enter a valid number.")


def upload_worker(upload_queue):
    while True:
        image_path = upload_queue.get()
        try:
            # Wait until copying finishes: file size must remain stable for 3 checks.
            last_size = -1
            stable_checks = 0
            for _ in range(30):
                if not image_path.exists():
                    break
                current_size = image_path.stat().st_size
                if current_size > 0 and current_size == last_size:
                    stable_checks += 1
                    if stable_checks >= 3:
                        break
                else:
                    stable_checks = 0
                last_size = current_size
                time.sleep(0.4)
            if not image_path.exists() or image_path.stat().st_size == 0:
                print(f"Upload skipped: {image_path.name} is missing or empty")
                continue
            print(f"\nImage uploaded: {image_path.name}")
            patient_name = input(f"Enter patient name for {image_path.name}: ").strip() or "unknown_patient"
            peer_id = select_peer()
            send_image_to_peer(image_path, peer_id, patient_name)
        except Exception as exc:
            print(f"Upload failed for {image_path.name}: {exc}")
        finally:
            upload_queue.task_done()


def main():
    if not DEVICE_ID:
        raise ValueError("Set DEVICE_ID in .env")
    IMAGE_FOLDER.mkdir(parents=True, exist_ok=True)
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    print(f"Device ID : {DEVICE_ID}")
    print(f"Watch folder: {IMAGE_FOLDER}")
    print(f"Receive folder: {OUTPUT_FOLDER}")
    if not PEERS:
        print("WARNING: no peers configured; incoming connections will be rejected")

    upload_queue = queue.Queue()
    threading.Thread(target=upload_worker, args=(upload_queue,), daemon=True).start()
    observer = Observer()
    observer.schedule(UploadHandler(upload_queue), str(IMAGE_FOLDER), recursive=False)
    observer.start()
    try:
        server_loop()
    except KeyboardInterrupt:
        print("\nStopping peer...")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
