
# Project Plan

## Post-Quantum Cryptographic Framework for Secure Medical Image Transmission

This document defines the development roadmap for the project, covering
software implementation, secure communication, FPGA acceleration, hardware
integration, performance evaluation, and final documentation.

---

## Project Roadmap

| Phase | Module | Major Deliverables |
|---|---|---|
| 1 | Requirement Analysis | Literature survey and technology study |
| 2 | Authentication | User and receiver authentication |
| 3 | HQC KEM | Key generation, encapsulation, decapsulation |
| 4 | ASCON | Image encryption and decryption |
| 5 | Secure Communication | TCP/IP and multi-receiver transmission |
| 6 | FPGA Acceleration | FPGA symmetric-encryption implementation |
| 7 | HQC Hardware | FPGA-based HQC integration |
| 8 | Complete Framework | Hardware cryptographic framework |
| 9 | Performance Evaluation | Software vs hardware comparison |
| 10 | Documentation | Thesis and research publication |

---

## Phase 1 — Requirement Analysis

**Status:** Completed / Ongoing

### Activities
- Literature survey on medical image security
- Study of post-quantum cryptography
- Study of HQC KEM
- Study of ASCON
- Study of authentication techniques
- Study of TCP/IP-based secure communication

### Deliverable
Technical and literature review defining the system architecture and
cryptographic requirements.

---

## Phase 2 — Authentication Module

**Status:** In Progress

### Activities
- User registration
- User authentication
- Receiver authentication
- Session management

### Deliverable
Authenticated sender and authorized receiver management system.

---

## Phase 3 — Post-Quantum Key Establishment

**Status:** In Progress

### Activities
- Software implementation of HQC KEM
- Key generation
- Encapsulation
- Decapsulation
- Shared/session-key verification

### Deliverable
Software-based post-quantum session-key establishment.

---

## Phase 4 — Symmetric Encryption

**Status:** Planned

### Activities
- Software implementation of ASCON
- Medical image encryption
- Medical image decryption
- Verification using standard test images

### Deliverable
Validated ASCON-based authenticated medical-image encryption module.

---

## Phase 5 — Secure Communication Framework

**Status:** Planned

### Activities
- TCP/IP communication
- Single-sender communication
- Single-receiver communication
- Multiple-receiver communication
- Secure session establishment
- Medical image transmission

### Deliverable
Complete software-based secure medical-image transmission framework.

---

## Phase 6 — FPGA Acceleration

**Target:** 8th Semester

### Activities
- FPGA implementation of the symmetric-encryption module
- Hardware/software interfacing
- Functional verification

### Deliverable
FPGA-accelerated symmetric cryptographic module.

---

## Phase 7 — Hardware Post-Quantum Cryptography

### Activities
- FPGA implementation/integration of HQC KEM
- Hardware key generation
- Hardware encapsulation
- Hardware decapsulation
- Hardware session-key generation

> Initially, the available HQC hardware implementation may be integrated.
> Further optimization can be performed based on resource and performance
> requirements.

### Deliverable
Hardware-accelerated post-quantum key-establishment module.

---

## Phase 8 — Complete Hardware Cryptographic Framework

### Activities
- Integration of authentication, PQC and encryption
- Hardware-assisted secure medical-image transmission
- Complete system validation

### Deliverable
Integrated hardware/software post-quantum secure medical-image
transmission system.

---

## Phase 9 — Performance Evaluation

### Evaluation Metrics

| Metric | Description |
|---|---|
| Software Execution Time | Time required by software implementation |
| Hardware Execution Time | Time required by FPGA implementation |
| FPGA Resource Utilization | LUT, FF, BRAM and other resources |
| Maximum Operating Frequency | Maximum stable FPGA clock frequency |
| Throughput | Amount of data processed per unit time |
| Latency | End-to-end cryptographic/system delay |
| Power Consumption | Hardware power requirement |
| Communication Delay | Network transmission delay |
| Image Quality | PSNR/SSIM where applicable |

### Main Comparison

```text
Software Implementation
        │
        ├── Execution Time
        ├── Latency
        ├── Throughput
        └── Power
              │
              ▼
        Comparison
              ▲
              │
        FPGA Implementation
        ├── Execution Time
        ├── Latency
        ├── Throughput
        ├── Power
        ├── LUT / FF / BRAM
        └── Maximum Frequency
