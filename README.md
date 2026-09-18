# Authenticated Secure Medical Image Transmission Using HQC and Ascon

**Authentication • HQC KEM • ASCON-128 • HMAC-SHA256 • FPGA Acceleration • Secure Medical Imaging**

A hardware-accelerated post-quantum cryptographic framework for securely transmitting medical images from a sender to multiple authorized receivers.

---

##  Overview

Medical images contain sensitive patient information and require strong protection against unauthorized access, modification, impersonation, and replay attacks.

This project proposes a secure medical-image transmission framework that combines:

- **HQC Key Encapsulation Mechanism (KEM)** for post-quantum session-key establishment
- **ASCON-128 AEAD** for image confidentiality and integrity
- **HMAC-SHA256** for receiver identity binding and authentication
- **Challenge-response authentication** for authorized receivers
- **TCP/IP communication** for reliable image transmission
- **Multi-receiver support** for communication with multiple authorized devices
- **FPGA acceleration** for hardware implementation of cryptographic operations
- **Software/hardware co-design** for performance evaluation

The system follows a **software-to-hardware implementation approach**. The complete cryptographic protocol is first developed and tested in software and subsequently migrated to FPGA hardware for acceleration.

---

## Objectives

The main objectives of the project are:

1. Establish secure session keys using the **HQC post-quantum KEM**.
2. Protect medical images using **ASCON-128 authenticated encryption**.
3. Authenticate receivers using a **challenge-response mechanism with HMAC-SHA256**.
4. Bind the receiver identity to the authentication process.
5. Provide secure communication between a sender and multiple authorized receivers.
6. Prevent unauthorized receivers from accessing transmitted medical images.
7. Implement selected cryptographic modules on an **FPGA**.
8. Compare software and hardware implementations.
9. Evaluate cryptographic, communication, and hardware performance.

---

##  System Architecture

The proposed system consists of four major stages:


```mermaid
flowchart TD

    A([Medical Image<br/>Sender])
    B[HQC Key Establishment]
    C[Shared Session Key K]
    D[Generate Fresh Challenge<br/>+ Receiver Identity]
    E[ASCON-128 AEAD<br/>Image Encryption]
    F[Authentication Tag T]
    G[HMAC-SHA256<br/>Identity Binding]
    H[Build Secure Packet<br/>C + T + B + Receiver ID + Nonce]
    I[TCP/IP Transmission]

    J{Authorized<br/>Receiver?}
    K[HMAC Verification]
    L{HMAC Valid?}
    M[ASCON-128<br/>Decrypt + Verify]
    N{ASCON Tag Valid?}
    O([Display / Save<br/>Medical Image])

    X[Discard Packet]
    Y[Discard Image]

    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H
    H --> I

    I --> J

    J -- No --> X
    J -- Yes --> K

    K --> L
    L -- No --> X
    L -- Yes --> M

    M --> N
    N -- No --> Y
    N -- Yes --> O

    %% Multiple receivers
    I -.-> R1[Receiver 1]
    I -.-> R2[Receiver 2]
    I -.-> RN[Receiver N]

    R1 -.-> J
    R2 -.-> J
    RN -.-> J

    classDef start fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    classDef crypto fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef network fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef receiver fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px;
    classDef decision fill:#fffde7,stroke:#f9a825,stroke-width:2px;
    classDef error fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef success fill:#e0f2f1,stroke:#00695c,stroke-width:2px;

    class A,C start;
    class B,D,E,F,G,H crypto;
    class I network;
    class R1,R2,RN receiver;
    class J,L,N decision;
    class K,M receiver;
    class X,Y error;
    class O success;
