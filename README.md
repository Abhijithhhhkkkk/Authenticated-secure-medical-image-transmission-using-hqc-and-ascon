# Post-Quantum Cryptographic Framework for Secure Medical Image Transmission

<p align="center">
  <b>Authentication • HQC KEM • ASCON • FPGA Acceleration • Secure Medical Imaging</b>
</p>

<p align="center">
  A hardware-accelerated post-quantum cryptographic framework for secure
  transmission of medical images between a sender and multiple authorized receivers.
</p>

---

## 📌 Overview

Medical images contain highly sensitive patient information and require strong
confidentiality, integrity, authentication, and secure key establishment.

This project develops a **Post-Quantum Cryptographic (PQC) framework** for
secure medical image transmission by integrating:

- User authentication
- Receiver authentication
- HQC-based Post-Quantum Key Encapsulation Mechanism (KEM)
- ASCON authenticated encryption
- TCP/IP secure communication
- Multi-receiver communication
- FPGA-based cryptographic acceleration
- Hardware/software co-design
- Performance evaluation

The project follows a **software-to-hardware implementation approach**, where
the cryptographic framework is first developed and validated in software and
then migrated to FPGA hardware for acceleration.

---

## 🎯 Objectives

1. Develop a secure authentication mechanism for authorized users and receivers.
2. Implement a Post-Quantum Key Encapsulation Mechanism (PQC KEM) for secure
   session-key establishment.
3. Implement ASCON authenticated encryption for protecting medical images.
4. Establish secure TCP/IP communication between a sender and multiple receivers.
5. Migrate cryptographic modules from software to FPGA hardware.
6. Compare software and hardware implementations based on:
   - Execution time
   - Latency
   - Throughput
   - FPGA resource utilization
   - Maximum operating frequency
   - Power consumption
   - Communication delay

---

## 🏗️ System Architecture

```mermaid
flowchart LR

    A[Medical Image] --> B[Sender]

    B --> C[User Authentication]
    C --> D[Receiver Authentication]

    D --> E[HQC KEM]

    E --> F[Session Key Establishment]

    F --> G[ASCON AEAD]

    G --> H[Encrypted Medical Image]

    H --> I[TCP/IP Communication]

    I --> J[Authorized Receiver 1]
    I --> K[Authorized Receiver 2]
    I --> L[Authorized Receiver N]

    J --> M[HQC Decapsulation]
    K --> M2[HQC Decapsulation]
    L --> M3[HQC Decapsulation]

    M --> N[Session Key]
    M2 --> N2[Session Key]
    M3 --> N3[Session Key]

    N --> O[ASCON Decryption]
    N2 --> O2[ASCON Decryption]
    N3 --> O3[ASCON Decryption]

    O --> P[Original Medical Image]
    O2 --> P2[Original Medical Image]
    O3 --> P3[Original Medical Image]
