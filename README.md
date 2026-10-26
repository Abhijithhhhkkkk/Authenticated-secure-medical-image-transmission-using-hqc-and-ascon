# Authenticated Secure Medical Image Transmission Using HQC and ASCON

A research-focused, post-quantum secure framework for transmitting medical images with confidentiality, integrity, and strong receiver authentication.

This project combines:

- HQC KEM for post-quantum session-key establishment
- ASCON-128 AEAD for authenticated image encryption
- HMAC-SHA256 for challenge-response receiver authentication
- TCP/IP communication for reliable secure transfer
- FPGA acceleration as a future hardware optimization path
- Software and hardware design comparison for performance evaluation

<p align="center">
  <img alt="Secure medical image transmission overview" src="https://img.shields.io/badge/Status-Research%20Prototype-blue" />
  <img alt="Security model" src="https://img.shields.io/badge/Focus-Post-Quantum%20Security-orange" />
  <img alt="Cryptography" src="https://img.shields.io/badge/Crypto-HQC%20%2B%20ASCON-purple" />
</p>

## Why this project matters

Medical images are highly sensitive and must remain protected from unauthorized access, tampering, replay, and impersonation. This project addresses those risks by combining:

- post-quantum key establishment
- authenticated encryption
- receiver identity checks before image release
- challenge-response authentication per session
- explicit validation of integrity before decryption

The design is meant to demonstrate a secure end-to-end medical image transmission workflow and to provide a path toward FPGA-accelerated cryptographic execution.

---

## System overview

The workflow begins with secure receiver authentication, then establishes a shared session key using HQC, encrypts the medical image using ASCON-128, and validates the packet before the image is released.

```mermaid
flowchart TD
    A([Medical Image<br/>Sender]) --> B[Receiver Authentication]
    B --> C[HQC Key Establishment]
    C --> D[Session Key K]
    D --> E[ASCON-128 AEAD<br/>Encryption]
    E --> F[Authentication Tag T]
    F --> G[HMAC-SHA256<br/>Identity Binding]
    G --> H[Construct Secure Packet]
    H --> I[TCP/IP Transmission]

    I --> J{Authorized Receiver?}
    J -- No --> X[Discard Packet]
    J -- Yes --> K[HMAC Verification]
    K --> L{Valid?}
    L -- No --> X
    L -- Yes --> M[ASCON-128<br/>Decrypt + Verify]
    M --> N{Tag Valid?}
    N -- No --> Y[Discard Image]
    N -- Yes --> O([Display / Save<br/>Medical Image])

    I -.-> R1[Receiver 1]
    I -.-> R2[Receiver 2]
    I -.-> RN[Receiver N]
    R1 -.-> J
    R2 -.-> J
    RN -.-> J
```

---

## Key security properties

| Security property | Mechanism | Purpose |
|---|---|---|
| Confidentiality | ASCON-128 encryption | Protects medical image contents |
| Integrity | ASCON authentication tag | Detects tampering or corruption |
| Authentication | HMAC-SHA256 challenge-response | Verifies receiver identity |
| Binding | Challenge + receiver ID | Prevents cross-session misuse |
| Replay resistance | Fresh challenge per session | Prevents reuse of stale authentication data |
| Post-quantum readiness | HQC KEM | Supports future-proof key establishment |

---

## Repository structure

```text
.
├── README.md
├── LICENSE
├── requirement.txt
├── project-plan/
│   └── README.md
├── software-implementation/
│   ├── README.md
│   ├── sender/
│   └── receiver/
└── ...
```

### Important directories

- `software-implementation/` — end-to-end software implementation of the secure communication pipeline
- `project-plan/` — roadmap and development milestones
- `sender/` — sender-side image selection, authentication, encryption, and packet transmission
- `receiver/` — receiver-side authentication, decapsulation, verification, and image reconstruction

---

## Software implementation

The software implementation demonstrates the complete secure medical image workflow, including:

- receiver authentication before transfer
- HQC-based shared session key establishment
- ASCON-128 encryption and decryption of medical images
- HMAC-bound identity validation
- TCP/IP communication with authorized receivers
- CSV-based performance logging

For implementation details, see:

- `software-implementation/README.md`

---

## Getting started

### Prerequisites

- Python 3.8+
- pip
- Linux environment recommended
- Access to required cryptographic libraries for HQC support

### Install dependencies

```bash
pip install -r requirement.txt
```

> Note: configuration values such as receiver IPs and secrets should be stored in environment variables or a `.env` file and should not be committed to the repository.

### Run the receiver

```bash
cd software-implementation/receiver
python receiver.py
```

### Run the sender

```bash
cd software-implementation/sender
python sender.py
```

---

## Example security flow

1. Sender connects to an authorized receiver
2. Receiver receives a fresh authentication challenge
3. Receiver computes a valid HMAC response
4. Sender verifies the challenge-response
5. Sender and receiver perform HQC encapsulation/decapsulation
6. Shared session key is established
7. Medical image is encrypted with ASCON-128
8. HMAC binds identity and packet authenticity
9. Encrypted packet is transmitted over TCP/IP
10. Receiver verifies HMAC before decryption
11. ASCON tag is checked during decryption
12. Image is saved only after successful verification

---

## Performance focus

This project is designed to support evaluation of:

- cryptographic execution time
- network transmission delay
- end-to-end latency
- throughput
- FPGA resource utilization
- hardware/software performance comparison

---

## Project plan

The project is organized into phases covering:

- requirement analysis
- authentication mechanisms
- HQC KEM implementation
- ASCON-based encryption
- secure communication
- FPGA acceleration
- complete framework integration
- performance evaluation
- documentation and reporting

See `project-plan/README.md` for the full roadmap and milestone status.

---

## Security considerations

This repository is intentionally research-oriented and is not a production medical-data deployment. Important guidelines include:

- never hard-code authentication secrets
- store configuration values in environment variables
- use strong random challenges
- verify HMAC using constant-time comparison
- reject packets before decryption when authentication fails
- never release plaintext if ASCON tag verification fails
- treat the software implementation as a prototype

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Contributing

Contributions are welcome for cryptographic improvements, security analysis, performance benchmarking, FPGA integration, and documentation improvements. If you are working on enhancements, please open an issue or submit a pull request with a clear description of the change.

---

## Summary

This project demonstrates a practical research-oriented model for secure medical image transmission using post-quantum key exchange and authenticated encryption. It balances cryptographic security, network reliability, and future hardware acceleration, making it a strong foundation for secure healthcare imaging research.
