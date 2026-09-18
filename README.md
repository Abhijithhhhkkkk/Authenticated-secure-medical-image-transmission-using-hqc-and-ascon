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

```text
                    ┌──────────────────────┐
                    │   Medical Image      │
                    │      Sender          │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  HQC Key             │
                    │  Establishment       │
                    └──────────┬───────────┘
                               │
                       Shared Session Key K
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Challenge Generation │
                    │ + Receiver Identity  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    ASCON-128 AEAD    │
                    │ Image Encryption     │
                    │ + Integrity Tag T    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    HMAC-SHA256       │
                    │ Identity Binding     │
                    │      + Tag T         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      TCP/IP          │
                    │    Transmission      │
                    └──────────┬───────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
          ┌──────────┐   ┌──────────┐   ┌──────────┐
          │Receiver 1│   │Receiver 2│   │Receiver N│
          └────┬─────┘   └────┬─────┘   └────┬─────┘
               │              │              │
               └──────────────┼──────────────┘
                              ▼
                    ┌──────────────────────┐
                    │ HMAC Verification    │
                    └──────────┬───────────┘
                               │
                          Valid HMAC?
                         /           \
                       No             Yes
                       │               │
                    Discard            ▼
                              ┌──────────────────┐
                              │ ASCON-128        │
                              │ Decrypt + Verify │
                              └────────┬─────────┘
                                       │
                                  Valid Tag?
                                  /       \
                                No         Yes
                                │           │
                             Discard         ▼
                                      Display Image
