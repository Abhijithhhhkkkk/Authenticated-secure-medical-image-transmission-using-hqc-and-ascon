# Authenticated Secure Medical Image Transmission Using HQC and Ascon

## Overview

This software implementation demonstrates a **post-quantum secure medical image transmission system** that combines:
- **HQC (Hamming Quasi-Cyclic)** post-quantum key encapsulation mechanism (KEM)
- **Ascon-128** authenticated encryption with associated data (AEAD)
- **HMAC-SHA256** challenge-response authentication

The system securely transmits medical images between a sender and multiple authorized receivers over TCP/IP networks with protection against both classical and quantum-level cryptographic attacks.

## System Flow

```
Sender → Select Image → Select Receiver → Authentication Challenge
           ↓
       Authentication Success?
           ├─ NO → Stop
           └─ YES ↓
       HQC Key Exchange → Establish Shared Secret
           ↓
       Derive ASCON Session Key
           ↓
       Encrypt Image with ASCON-128
           ↓
       TCP Transmission
           ↓
       Receiver: Authenticate & Decrypt
           ↓
       Medical Image Reconstructed
```

## Key Objectives

✅ Secure medical image transmission over TCP/IP  
✅ Receiver authentication before key exchange  
✅ Protection against unauthorized access  
✅ Post-quantum secure key establishment using HQC  
✅ Confidentiality & integrity via Ascon-128 AEAD  
✅ Challenge-response authentication with replay resistance  
✅ Performance measurement of cryptographic operations  
✅ Support for multiple receivers  
✅ Session key derivation without direct transmission  

---

## System Architecture

### Sender (TCP Client)

**Responsibilities:**
1. Load receiver information from `.env` file
2. Connect to selected receiver via TCP
3. Perform HMAC challenge-response authentication
4. Receive receiver's HQC public key
5. Perform HQC key encapsulation
6. Derive ASCON session key from shared secret
7. Encrypt medical image using Ascon-128 AEAD
8. Transmit encrypted image over TCP
9. Log performance metrics

### Receiver (TCP Server)

**Responsibilities:**
1. Listen for incoming TCP connections
2. Identify itself via receiver ID
3. Respond to authentication challenge
4. Generate HQC key pair upon successful authentication
5. Send HQC public key to sender
6. Perform HQC key decapsulation
7. Derive same ASCON session key
8. Receive and verify encrypted image
9. Decrypt and save medical image
10. Log performance metrics

---

## Security Protocol

### 1. Receiver Authentication (HMAC-SHA256)

The sender initiates authentication with a fresh random challenge:

```python
challenge = secrets.token_bytes(32)
```

The receiver calculates:
```
HMAC-SHA256(Kidentity, Challenge || Receiver_ID)
```

The sender verifies using constant-time comparison:
```python
hmac.compare_digest(received_hmac, expected_hmac)
```

**Authentication Result:**
- ✅ **Match** → Proceed to HQC key exchange
- ❌ **Mismatch** → Abort; do not send medical image

**Security Features:**
- Fresh random challenge for every session (prevents replay attacks)
- Pre-shared identity key between sender and receiver
- Constant-time comparison (prevents timing attacks)

### 2. HQC Key Encapsulation

After authentication succeeds:

1. **Receiver generates HQC key pair:**
   - Public key (sent to sender)
   - Private key (kept secret)

2. **Sender performs encapsulation:**
   ```
   Receiver's Public Key → HQC Encapsulation → {Ciphertext, Shared Secret}
   ```

3. **Receiver performs decapsulation:**
   ```
   HQC Ciphertext + Private Key → HQC Decapsulation → Shared Secret
   ```

Both parties obtain the same **shared secret** without transmitting it.

### 3. ASCON-128 Session Key Derivation

```
HQC Shared Secret → Key Derivation Function → ASCON-128 Session Key
```

- Session key is **never transmitted** over the network
- Derived independently by sender and receiver

### 4. Medical Image Encryption (Ascon-128 AEAD)

**Encryption inputs:**
```
Medical Image + ASCON Session Key + Nonce + AAD("medical-image")
    ↓
ASCON-128 AEAD Encryption
    ↓
Ciphertext + Authentication Tag
```

**Decryption verification:**
- Authentication tag allows receiver to detect tampering/corruption
- Ensures **confidentiality** and **integrity**

### 5. Secure Transmission Over TCP

**Transmitted packet structure:**
```
┌─────────────────────────────────────┐
│ Receiver ID                         │
│ Patient Information                 │
│ Image Filename                      │
│ Nonce (for Ascon-128)              │
│ Encrypted Image (Ciphertext)        │
│ Authentication Tag                  │
└─────────────────────────────────────┘

⚠️  ASCON Session Key is NOT included
```

---

## Project Structure

```
software-implementation/
├── sender/
│   ├── sender.py                 # Sender implementation
│   ├── .env                      # Configuration (DO NOT commit)
│   ├── img/                      # Medical images to transmit
│   │   ├── image1.jpg
│   │   ├── image2.png
│   │   └── ...
│   └── performance_log.csv       # Metrics (generated at runtime)
│
├── receiver/
│   ├── receiver.py               # Receiver implementation
│   ├── .env                      # Configuration (DO NOT commit)
│   ├── img/                      # Received/reconstructed images
│   │   ├── received_image1.jpg
│   │   └── ...
│   └── performance_log_receiver.csv  # Metrics (generated at runtime)
│
└── README.md                     # This file
```

---

## Requirements

### Software Requirements
- **Python 3.8+**
- **Linux/Ubuntu recommended** (or WSL on Windows)
- **TCP/IP network connectivity**
- Python virtual environment (recommended)

### Python Dependencies

```bash
pip install python-dotenv
```

**Cryptographic Libraries:**
- **Ascon-128** implementation (specify package)
- **liboqs-python** for HQC (Open Quantum Safe bindings)

Install all dependencies:
```bash
pip install -r requirements.txt
```

---

## Configuration

### Sender `.env` File

Store IP addresses and authentication secrets for authorized receivers:

```env
TCP_PORT=5000

RECEIVER1_IP=192.168.1.101
RECEIVER1_ID=receiver1
RECEIVER1_KEY=receiver1-secret-key-123456

RECEIVER2_IP=192.168.1.102
RECEIVER2_ID=receiver2
RECEIVER2_KEY=receiver2-secret-key-654321

RECEIVER3_IP=192.168.1.103
RECEIVER3_ID=receiver3
RECEIVER3_KEY=receiver3-secret-key-abcdef
```

### Receiver `.env` File

Each receiver stores its identity and shared authentication secret:

```env
RECEIVER_ID=receiver1
RECEIVER_SECRET=receiver1-secret-key-123456
TCP_PORT=5000
```

**Important:** The receiver secret **must match exactly** with the sender's corresponding key:
```
Sender:    RECEIVER1_KEY=receiver1-secret-key-123456
Receiver 1: RECEIVER_SECRET=receiver1-secret-key-123456
```

⚠️ **Security Note:** Never commit `.env` files to version control. Add to `.gitignore`:
```
.env
*.env
```

---

## Running the System

### Step 1: Start Receiver

On the receiver machine:

```bash
python3 receiver.py
```

Expected output:
```
Receiver ID: receiver1
TCP server listening on port 5000...
Waiting for sender connection...
```

### Step 2: Start Sender

On the sender machine:

```bash
python3 sender.py
```

**Select receiver:**
```
Available Receivers:
1. receiver1
2. receiver2
3. receiver3

Select receiver [1-3]: 1
```

**Select medical image:**
```
Available Medical Images:
1. patient1.jpg
2. patient2.png
3. patient3.jpg

Select image [1-3]: 1
```

---

## Execution Flow Logs

### Authentication Phase

```
Connecting to receiver1 at 192.168.1.101:5000...
✓ TCP connection established

Starting receiver authentication...
✓ Challenge generated (32 bytes)
✓ Waiting for HMAC response...
✓ Authentication successful
```

**If authentication fails:**
```
✗ Authentication failed
✗ HQC key exchange will NOT proceed
✗ Medical image will NOT be sent
```

### HQC Key Exchange

```
Receiver: Generating HQC key pair...
✓ HQC key pair generated
✓ Sending public key to sender...

Sender: Receiving HQC public key...
✓ Performing HQC encapsulation...
✓ HQC ciphertext generated
✓ Sending HQC ciphertext to receiver...

Receiver: Performing HQC decapsulation...
✓ Shared secret established
```

### Image Transmission

```
Encrypting medical image with Ascon-128...
✓ Encryption completed
✓ Sending encrypted image...
✓ Transmission completed (2.5 MB)

Receiver: Receiving encrypted image...
✓ Verifying Ascon authentication tag...
✓ Authentication tag valid
✓ Decrypting medical image...
✓ Medical image successfully reconstructed
✓ Saved to: receiver/img/received_patient1.jpg
```

---

## Performance Measurement

### Measured Parameters

| Parameter | Description | Unit |
|-----------|-------------|------|
| **HQC Key Generation Time** | Time to generate HQC key pair | ms |
| **HQC Encapsulation Time** | Sender-side HQC encapsulation | ms |
| **HQC Decapsulation Time** | Receiver-side HQC decapsulation | ms |
| **HMAC Authentication Time** | Receiver authentication duration | ms |
| **ASCON Encryption Time** | Image encryption time | ms |
| **ASCON Decryption Time** | Image decryption time | ms |
| **Transmission Time** | TCP transfer duration | ms |
| **Overall Delay** | Total end-to-end latency | ms |
| **Throughput** | Data transfer rate | MB/s |
| **Image Size** | Medical image file size | MB |

### Output Files

Performance metrics are automatically logged to CSV files:

**Sender:**
```
sender/performance_log.csv
```

**Receiver:**
```
receiver/performance_log_receiver.csv
```

Example CSV format:
```csv
timestamp,image_name,image_size_mb,hqc_keygen_ms,hqc_encap_ms,hmac_auth_ms,ascon_enc_ms,transmission_ms,overall_delay_ms
2024-01-15T10:30:45,patient1.jpg,2.5,125.3,45.2,8.1,102.5,320.1,601.2
```

---

## Security Features

| Feature | Mechanism | Purpose |
|---------|-----------|---------|
| **Confidentiality** | Ascon-128 encryption | Prevent unauthorized image access |
| **Integrity** | Ascon-128 authentication tag | Detect tampering/corruption |
| **Receiver Authentication** | HMAC-SHA256 challenge-response | Verify receiver identity |
| **Replay Resistance** | Fresh random challenge per session | Prevent attack replay |
| **Post-Quantum Security** | HQC key encapsulation | Quantum-safe key exchange |
| **Session Key Protection** | Derived (not transmitted) | Prevent key compromise |
| **Unauthorized Access Prevention** | Failed auth blocks transmission | Enforce access control |

---

## Communication Protocol Diagram

```
SENDER                          RECEIVER
  │                                │
  │──── TCP Connection ──────────>│
  │                                │
  │─ Receiver ID ────────────────>│
  │                                │
  │<─── Challenge Response ───────│ (HMAC-SHA256)
  │                                │
  │<─── HQC Public Key ───────────│
  │                                │
  │─── HQC Ciphertext ──────────>│
  │                                │
  │─── Encrypted Image (TCP) ───>│
  │     + Nonce + Auth Tag        │
  │                                │
  │<─── Acknowledgment ───────────│
  │                                │
```

---

## Limitations

This software implementation focuses on **cryptographic and network-security aspects**. The following are outside the scope:

- ❌ FPGA resource utilization analysis
- ❌ Hardware power consumption measurement
- ❌ Hardware clock frequency analysis
- ❌ FPGA throughput optimization

These can be evaluated when deploying to FPGA hardware.

---

## Future Enhancements

- 🔧 FPGA acceleration for HQC and Ascon
- 📊 Hardware resource utilization analysis
- ⚡ Power consumption measurement
- 🖼️ Support for additional medical image formats (JPEG-XR, WebP)
- 📦 Multi-image transmission in single session
- 🔐 Enhanced key management infrastructure (PKI)
- 📝 Secure logging and audit trails
- 🏥 DICOM medical image standard integration
- 🌐 Network optimization and compression
- 🔀 Comparison with classical cryptographic schemes (RSA, ECDH)

---

## Important Security Notes

⚠️ **Critical Reminders:**

1. **Never hard-code secrets** in source code
2. **Always use environment variables** via `.env` files
3. **Exclude `.env` files from version control** (add to `.gitignore`)
4. **Protect `.env` files** with appropriate file permissions (`chmod 600`)
5. **Do not transmit session keys** directly in network packets
6. **Use strong authentication secrets** (minimum 32 bytes of entropy)
7. **Rotate credentials periodically** in production systems
8. **Never disable authentication checks** for performance

---

## Disclaimer

⚖️ This implementation is for **academic and research purposes only**. It demonstrates a prototype secure medical-image transmission architecture and should **NOT** be deployed as a production medical data security system without:

- ✓ Professional security audit
- ✓ Compliance verification (HIPAA, GDPR, local regulations)
- ✓ Hardware security module integration
- ✓ Extended testing in target environment
- ✓ Legal and compliance review

---

## Author & Attribution

**Project:** Authenticated Secure Medical Image Transmission Using HQC and Ascon  
**Course:** Final Year Electronics and Communication Engineering Project  
**Institution:** GCE KANNUR
**Academic Year:** 2023-2027

---

## License

[Specify license: MIT, Apache 2.0, etc.]

---

## References

- HQC Key Encapsulation Mechanism: [Link to specification]
- Ascon-128 AEAD: [Link to specification]
- Open Quantum Safe (liboqs): https://github.com/open-quantum-safe/liboqs
- HMAC-SHA256: RFC 2104
- Python Cryptography: https://cryptography.io/

---

## Support & Questions

For questions or issues, please refer to the project repository or contact the project maintainers.
