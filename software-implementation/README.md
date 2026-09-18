# Authenticated Secure Medical Image Transmission Using HQC and Ascon

**Software Implementation | HQC KEM | ASCON-128 | HMAC-SHA256 | TCP/IP | Secure Medical Imaging**

## Overview

This software implementation demonstrates a post-quantum secure medical image transmission system that combines:

- HQC (Hamming Quasi-Cyclic) post-quantum Key Encapsulation Mechanism (KEM)
- ASCON-128 authenticated encryption with associated data (AEAD)
- HMAC-SHA256 challenge-response authentication
- Receiver identity binding
- TCP/IP communication
- Multiple authorized receivers
- Cryptographic and communication performance measurement

The system securely transmits medical images between a sender and multiple authorized receivers while providing confidentiality, integrity, receiver authentication, secure session-key establishment, and replay resistance.

The software implementation serves as the first stage of the project before migration of selected cryptographic components to FPGA hardware for acceleration.

---

## Key Features

- Post-quantum key establishment using HQC KEM
- ASCON-128 authenticated encryption
- HMAC-SHA256 receiver authentication
- Fresh random challenge for each authentication session
- Receiver identity binding
- Secure TCP/IP image transmission
- Support for multiple receivers
- No direct transmission of session keys
- Authentication before medical-image transfer
- HMAC verification before decryption
- ASCON authentication-tag verification
- Automatic performance logging
- Software performance evaluation

---

## Key Objectives

- Secure medical image transmission over TCP/IP
- Authenticate authorized receivers before image transmission
- Prevent unauthorized access to medical images
- Establish session keys using HQC KEM
- Provide confidentiality using ASCON-128
- Provide integrity using ASCON authentication tags
- Provide receiver authentication using HMAC-SHA256
- Provide replay resistance using fresh random challenges
- Support communication with multiple authorized receivers
- Measure cryptographic execution time and network performance
- Prepare the cryptographic modules for future FPGA acceleration

---

## System Architecture

The software system consists of two primary components:

### Sender

The sender operates as a TCP client and is responsible for:

1. Loading receiver configuration from the `.env` file
2. Selecting the medical image
3. Connecting to the selected receiver
4. Performing receiver authentication
5. Receiving the receiver's HQC public key
6. Performing HQC encapsulation
7. Establishing the shared session key
8. Generating a fresh authentication challenge
9. Binding the challenge to the receiver identity
10. Encrypting the medical image using ASCON-128 AEAD
11. Generating the identity-binding HMAC
12. Constructing the secure packet
13. Transmitting the encrypted image over TCP
14. Recording performance measurements

### Receiver

The receiver operates as a TCP server and is responsible for:

1. Listening for incoming TCP connections
2. Identifying itself using the receiver ID
3. Responding to the authentication challenge
4. Generating an HQC key pair after successful authentication
5. Sending the HQC public key to the sender
6. Performing HQC decapsulation
7. Recovering the shared session key
8. Receiving the encrypted image packet
9. Verifying the HMAC
10. Performing ASCON-128 authenticated decryption
11. Verifying the ASCON authentication tag
12. Reconstructing and saving the medical image
13. Recording performance measurements

---

## Project Structure

    software-implementation/
    │
    ├── sender/
    │   ├── sender.py
    │   ├── img/
    │   │   ├── image1.jpg
    │   │   ├── image2.png
    │   │   └── ...
    │   └── performance_log.csv
    │
    ├── receiver/
    │   ├── receiver.py
    │   ├── img/
    │   │   ├── received_image1.jpg
    │   │   ├── received_image2.png
    │   │   └── ...
    │   └── performance_log_receiver.csv
    │
    └── README.md

---

## System Flow

    Sender
       │
       ▼
    Select Medical Image
       │
       ▼
    Select Authorized Receiver
       │
       ▼
    Establish TCP Connection
       │
       ▼
    Generate Authentication Challenge
       │
       ▼
    Receiver Authentication
       │
       ├── Authentication Failed ──► Abort
       │
       ▼
    HQC Key Establishment
       │
       ▼
    Shared Session Key Established
       │
       ▼
    Construct Associated Data
       │
       ▼
    ASCON-128 Encryption
       │
       ├── Encrypted Image C
       └── Authentication Tag T
       │
       ▼
    HMAC-SHA256 Generation
       │
       ▼
    Construct Secure Packet
       │
       ▼
    TCP Transmission
       │
       ▼
    Receiver
       │
       ▼
    Receive Complete Packet
       │
       ▼
    HMAC Verification
       │
       ├── Invalid ──► Discard Packet
       │
       ▼
    ASCON-128 Decryption
       │
       ▼
    ASCON Tag Verification
       │
       ├── Invalid ──► Discard Packet
       │
       ▼
    Medical Image Reconstructed
       │
       ▼
    Save Image

---

# Security Protocol

## 1. TCP Connection

The sender establishes a TCP connection with the selected authorized receiver.

    Sender ───────────── TCP Connection ─────────────► Receiver

TCP is used as the transport protocol because it provides reliable and ordered delivery of the encrypted image data.

---

## 2. Receiver Authentication

Before HQC key establishment and medical-image transmission, the receiver is authenticated.

The sender generates a fresh random challenge:

    Challenge = secrets.token_bytes(32)

The challenge is associated with the receiver identity.

The receiver computes an authentication response using its identity secret:

    HMAC-SHA256(K_identity, Challenge || Receiver_ID)

where:

- `K_identity` is the shared receiver authentication secret
- `Challenge` is the fresh random challenge
- `Receiver_ID` is the identity of the receiver
- `||` represents concatenation

The sender verifies the received authentication value using a constant-time comparison.

    hmac.compare_digest(received_hmac, expected_hmac)

If authentication succeeds:

    Authentication Successful
             │
             ▼
    Proceed to HQC Key Establishment

If authentication fails:

    Authentication Failed
             │
             ▼
    Abort Communication
             │
             ▼
    Do Not Transmit Medical Image

---

## 3. HQC Key Establishment

After successful receiver authentication, the receiver generates or provides its HQC public key.

The sender performs HQC encapsulation using the receiver's public key.

    Receiver HQC Public Key
             │
             ▼
      HQC Encapsulation
             │
          ┌──┴──┐
          ▼     ▼
       Key K  Ciphertext
                │
                ▼
        Send HQC Ciphertext
                │
                ▼
             Receiver
                │
                ▼
       HQC Decapsulation
                │
                ▼
          Shared Key K

Both sender and receiver obtain the same shared secret.

The session key is not transmitted directly over the network.

---

## 4. Challenge and Receiver Identity Binding

A fresh challenge is generated for the current authentication session.

The challenge is combined with the receiver identity:

    A = Challenge || Receiver_ID

The value `A` binds the authentication operation to:

- The current session challenge
- The intended receiver

This value is used as associated data during the authenticated encryption process and as part of the HMAC calculation.

---

## 5. ASCON-128 Authenticated Encryption

The selected medical image is loaded from:

    sender/img/

Supported image formats include:

- `.jpg`
- `.jpeg`
- `.png`

The image is encrypted using ASCON-128 AEAD.

Conceptually:

    (C, T) = ASCON_Encrypt(K, N_A, A, P)

where:

- `K` = shared ASCON session key
- `N_A` = ASCON nonce
- `A` = associated authenticated data
- `P` = original medical image
- `C` = encrypted medical image
- `T` = ASCON authentication tag

ASCON provides confidentiality and authenticated integrity protection for the medical image.

---

## 6. Identity-Binding HMAC

After ASCON encryption, the sender computes an HMAC using the receiver's identity secret.

    B = HMAC-SHA256(K_identity, A || T)

where:

- `K_identity` = receiver authentication secret
- `A` = `Challenge || Receiver_ID`
- `T` = ASCON authentication tag
- `B` = HMAC authentication value

The ASCON authentication tag is included in the HMAC input so that the authentication value is bound to the protected image data.

---

## 7. Secure Packet Construction

The sender constructs a packet containing the information required by the receiver.

    {
        C,
        T,
        B,
        Receiver_ID,
        N_A
    }

where:

- `C` = encrypted medical image
- `T` = ASCON authentication tag
- `B` = HMAC-SHA256 authentication value
- `Receiver_ID` = intended receiver identity
- `N_A` = ASCON nonce

The authentication challenge was already exchanged during the authentication stage.

---

## 8. Secure Transmission

The complete encrypted packet is transmitted over TCP/IP.

    Sender
       │
       │ {C, T, B, Receiver_ID, N_A}
       │
       ▼
    TCP/IP
       │
       ▼
    Receiver

The medical image is never transmitted as plaintext.

---

# Receiver Verification

The receiver performs verification before releasing the medical image.

## Step 1: Receive Complete Packet

The receiver obtains:

    {C, T, B, Receiver_ID, N_A}

---

## Step 2: Reconstruct Authentication Data

The receiver reconstructs:

    A = Challenge || Receiver_ID

---

## Step 3: Recompute HMAC

The receiver calculates:

    B' = HMAC-SHA256(K_identity, A || T)

The calculated HMAC `B'` is compared with the received HMAC `B`.

    B' == B

The comparison should be performed using a constant-time comparison.

    hmac.compare_digest(received_hmac, calculated_hmac)

---

## HMAC Verification Failure

If the HMAC verification fails:

    Received Packet
          │
          ▼
    HMAC Verification
          │
          ▼
       Invalid
          │
          ▼
    Discard Packet
          │
          ▼
    Do Not Decrypt Image

The receiver must not decrypt or release the medical image when authentication fails.

---

## HMAC Verification Success

If the HMAC is valid:

    Received Packet
          │
          ▼
    HMAC Verification
          │
          ▼
        Valid
          │
          ▼
    Proceed to ASCON Decryption

---

# ASCON Decryption and Verification

After successful HMAC verification, the receiver performs ASCON-128 authenticated decryption.

Conceptually:

    P = ASCON_Decrypt(K, N_A, A, C, T)

ASCON verifies the authentication tag during the decryption process.

---

## Invalid ASCON Authentication Tag

If the ASCON authentication tag is invalid:

    HMAC Valid
        │
        ▼
    ASCON Decryption
        │
        ▼
    Tag Invalid
        │
        ▼
    Discard Result
        │
        ▼
    Do Not Release Image

This protects against modified or corrupted encrypted image data.

---

## Valid ASCON Authentication Tag

If the ASCON authentication tag is valid:

    HMAC Valid
        │
        ▼
    ASCON Decryption
        │
        ▼
    Tag Valid
        │
        ▼
    Medical Image Reconstructed
        │
        ▼
    Save Image

The reconstructed medical image is stored in:

    receiver/img/

---

# ##  Communication Protocol Sequence

```mermaid
sequenceDiagram
    autonumber

    participant S as Sender
    participant R as Authorized Receiver

    S->>R: TCP Connection
    S->>R: Receiver ID
    S->>R: Fresh Random Challenge

    R->>S: HMAC-SHA256 Challenge Response

    S->>S: Verify Receiver Authentication

    alt Authentication Failed
        S-->>R: Abort Communication
    else Authentication Successful
        R->>S: HQC Public Key
        S->>S: HQC Encapsulation
        S->>R: HQC Ciphertext
        R->>R: HQC Decapsulation
        Note over S,R: Shared Session Key K Established

        S->>S: A = Challenge || Receiver_ID
        S->>S: ASCON-128 Encryption
        Note over S: C = Ciphertext<br/>T = ASCON Authentication Tag

        S->>S: B = HMAC-SHA256(K_identity, A || T)

        S->>R: {C, T, B, Receiver_ID, N_A}

        R->>R: Reconstruct A
        R->>R: Verify HMAC

        alt HMAC Invalid
            R-->>S: Authentication Failed
            R->>R: Discard Packet
        else HMAC Valid
            R->>R: ASCON-128 Decrypt + Verify Tag

            alt ASCON Tag Invalid
                R-->>S: Integrity Verification Failed
                R->>R: Discard Image
            else ASCON Tag Valid
                R->>R: Reconstruct Medical Image
                R->>R: Display / Save Image
                R-->>S: ACK
            end
        end
    end
# Multiple Receiver Support

The sender can communicate with multiple authorized receivers.

Each receiver can have its own:

- Receiver ID
- IP address
- Authentication secret
- HQC key pair
- Session key

Conceptually:

                            Sender
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
        Receiver 1    Receiver 2    Receiver N
             │             │             │
             ▼             ▼             ▼
          HQC KEM       HQC KEM       HQC KEM
             │             │             │
             ▼             ▼             ▼
        Session K1    Session K2    Session KN
             │             │             │
             ▼             ▼             ▼
           ASCON         ASCON         ASCON
             │             │             │
             ▼             ▼             ▼
           HMAC          HMAC          HMAC
             │             │             │
             ▼             ▼             ▼
        Secure Image  Secure Image  Secure Image

Authentication is performed independently for each authorized receiver.

---

# Configuration

Sensitive configuration information should be stored in a `.env` file.

Example configuration:

    RECEIVER1_IP=<receiver-ip-address>
    RECEIVER1_KEY=<receiver-authentication-secret>

    RECEIVER2_IP=<receiver-ip-address>
    RECEIVER2_KEY=<receiver-authentication-secret>

    TCP_PORT=5000

Do not commit the actual `.env` file to the repository.

Use a `.env.example` file to document the required configuration variables without exposing real credentials.

---

# Running the Software

## 1. Start the Receiver

Navigate to the receiver directory:

    cd receiver

Start the receiver:

    python receiver.py

The receiver starts the TCP server and waits for incoming connections.

Example:

    Receiver started
    Waiting for incoming connection...

---

## 2. Start the Sender

Open another terminal and navigate to the sender directory:

    cd sender

Start the sender:

    python sender.py

The sender then:

1. Loads receiver configuration
2. Selects the receiver
3. Establishes a TCP connection
4. Performs receiver authentication
5. Performs HQC key establishment
6. Generates the session key
7. Encrypts the medical image using ASCON-128
8. Generates the HMAC
9. Sends the encrypted packet
10. Records performance measurements

---

# Image Input and Output

## Input

Medical images to be transmitted should be placed in:

    sender/img/

Example:

    sender/img/
    ├── patient1.jpg
    ├── patient2.png
    └── patient3.jpeg

## Output

Successfully authenticated and verified images are reconstructed and saved in:

    receiver/img/

Example:

    receiver/img/
    ├── patient1.jpg
    ├── patient2.png
    └── patient3.jpeg

The medical image is released only after successful authentication and ASCON verification.

---

# Performance Evaluation

The software implementation measures the execution time of major cryptographic and communication operations.

## Performance Metrics

| Metric | Description | Unit |
|---|---|---|
| HQC Key Generation | Time required to generate the HQC key pair | ms |
| HQC Encapsulation | Time required for HQC encapsulation | ms |
| HQC Decapsulation | Time required for HQC decapsulation | ms |
| HMAC Authentication | HMAC computation/verification time | ms |
| ASCON Encryption | Medical-image encryption time | ms |
| ASCON Decryption | Medical-image decryption time | ms |
| Transmission Time | TCP transfer duration | ms |
| Overall Delay | Total end-to-end latency | ms |
| Throughput | Data transfer rate | MB/s |
| Image Size | Medical image file size | MB |

---

# Performance Logs

Performance measurements are automatically stored in CSV files.

## Sender Log

    sender/performance_log.csv

## Receiver Log

    receiver/performance_log_receiver.csv

Example CSV format:

    timestamp,image_name,image_size_mb,hqc_keygen_ms,hqc_encap_ms,hmac_auth_ms,ascon_enc_ms,transmission_ms,overall_delay_ms
    2026-09-18T10:30:45,patient1.jpg,2.5,125.3,45.2,8.1,102.5,320.1,601.2

The logs can be used to analyze:

- HQC key-generation overhead
- HQC encapsulation and decapsulation time
- HMAC processing time
- ASCON encryption and decryption time
- TCP transmission time
- End-to-end latency
- Throughput
- Effect of medical-image size on performance

---

# Security Features

| Security Feature | Mechanism | Purpose |
|---|---|---|
| Confidentiality | ASCON-128 encryption | Protect medical-image contents |
| Integrity | ASCON authentication tag | Detect modification or corruption |
| Receiver Authentication | HMAC-SHA256 challenge-response | Verify receiver identity |
| Identity Binding | Challenge + Receiver ID | Bind authentication to the intended receiver |
| Replay Resistance | Fresh random challenge | Prevent reuse of previous authentication data |
| Post-Quantum Key Establishment | HQC KEM | Establish shared secrets using a post-quantum KEM |
| Session Key Protection | HQC-derived shared secret | Avoid direct transmission of the session key |
| Unauthorized Access Prevention | Authentication failure blocks transfer | Prevent unauthorized image access |
| Secure Transport | TCP/IP | Reliable and ordered encrypted-data transmission |

---

# Security Testing

The implementation can be tested using different security scenarios.

## Valid Receiver

    Valid Authentication
            │
            ▼
    HQC Key Establishment
            │
            ▼
    ASCON Encryption
            │
            ▼
    HMAC Verification
            │
            ▼
    ASCON Verification
            │
            ▼
    Image Reconstructed

## Invalid Authentication Secret

    Authentication Attempt
            │
            ▼
    HMAC Verification
            │
            ▼
       Authentication
          Failed
            │
            ▼
       Abort Transfer
            │
            ▼
    Image Not Transmitted

## Modified HMAC

    Packet Received
          │
          ▼
    HMAC Verification
          │
          ▼
       Mismatch
          │
          ▼
    Packet Discarded
          │
          ▼
    Image Not Decrypted

## Modified Ciphertext

    Packet Received
          │
          ▼
    HMAC Verification
          │
          ▼
       Valid
          │
          ▼
    ASCON Verification
          │
          ▼
    Integrity Failure
          │
          ▼
    Packet Discarded

## Modified ASCON Tag

    Packet Received
          │
          ▼
    HMAC Verification
          │
          ▼
       Valid
          │
          ▼
    ASCON Tag Verification
          │
          ▼
       Invalid Tag
          │
          ▼
    Image Not Released

## Replay Attempt

    Previously Used Authentication Data
                  │
                  ▼
          Fresh Challenge Required
                  │
                  ▼
           Authentication Check
                  │
                  ▼
              Rejected

---

# Important Security Notes

- Never hard-code authentication secrets in source code.
- Store sensitive configuration values in environment variables.
- Add `.env` to `.gitignore`.
- Never commit `.env` files containing real credentials.
- Protect `.env` files with appropriate file permissions.
- Use strong random challenges for authentication.
- Use sufficiently strong authentication secrets.
- Do not transmit session keys directly through the network.
- Use constant-time comparison for HMAC verification.
- Perform authentication before medical-image transfer.
- Do not decrypt the image when HMAC verification fails.
- Do not release plaintext when the ASCON authentication tag is invalid.
- Do not disable authentication checks for performance testing.

---

# Software Requirements

The implementation requires a Python environment and the cryptographic/networking dependencies specified by the project.

Install the Python dependencies using:

    pip install -r requirements.txt

The project may require Open Quantum Safe libraries for HQC support.

The software environment can be configured on a Linux system such as Fedora or another compatible Linux distribution.

---

# Technologies Used

## Programming

- Python

## Cryptography

- HQC KEM
- ASCON-128 AEAD
- HMAC-SHA256

## Networking

- TCP/IP
- Python socket programming

## Post-Quantum Cryptography

- Open Quantum Safe (liboqs)
- liboqs-python

## Data

- JPEG
- PNG
- Medical image files

## Performance Analysis

- Python timing functions
- CSV logging
- Cryptographic execution-time measurement
- Network latency measurement
- Throughput measurement

---

# Limitations

This directory focuses on the software implementation of the proposed secure medical-image transmission framework.

The following hardware-specific analysis is outside the scope of this software implementation:

- FPGA resource utilization
- FPGA power consumption
- FPGA maximum operating frequency
- Hardware timing analysis
- FPGA throughput optimization
- Hardware implementation efficiency

These parameters are evaluated separately during the FPGA implementation phase.

The current software implementation is a research prototype and does not represent a complete production medical-data security system.

---

# Future Enhancements

Future development may include:

- FPGA acceleration of HQC
- FPGA acceleration of ASCON-128
- FPGA implementation of HMAC-SHA256
- FPGA resource utilization analysis
- FPGA power-consumption analysis
- Maximum operating-frequency analysis
- Hardware/software performance comparison
- Additional medical-image formats
- Multi-image transmission within a single session
- Improved key-management infrastructure
- Secure audit logging
- DICOM medical-image integration
- Network optimization
- Image compression
- Comparison with classical key-establishment approaches such as RSA and ECDH

---

# Project Development Approach

The project follows a software-to-hardware development workflow:

    Protocol Design
          │
          ▼
    Software Implementation
          │
          ▼
    Functional Testing
          │
          ▼
    Security Testing
          │
          ▼
    Performance Evaluation
          │
          ▼
    FPGA Cryptographic Implementation
          │
          ▼
    Hardware Acceleration
          │
          ▼
    Software vs Hardware Comparison

The software implementation provides the functional reference for the subsequent FPGA implementation.

---

# License

This project is licensed under the MIT License.

You are free to use, modify, and distribute the software in accordance with the terms of the license.

---

# References

## HQC

Hamming Quasi-Cyclic (HQC) Key Encapsulation Mechanism:

https://www.pqc-hqc.org/doc/hqc-specification_2020-05-29.pdf

## NIST Post-Quantum Cryptography

NIST Post-Quantum Cryptography Project:

https://csrc.nist.gov/projects/post-quantum-cryptography

## ASCON

Ascon Authenticated Encryption:

https://ascon.iaik.tugraz.at/

## Open Quantum Safe

Open Quantum Safe (liboqs):

https://github.com/open-quantum-safe/liboqs

## liboqs-python

Python bindings for Open Quantum Safe:

https://github.com/open-quantum-safe/liboqs-python

## HMAC-SHA256

RFC 2104 — HMAC: Keyed-Hashing for Message Authentication:

https://www.rfc-editor.org/rfc/rfc2104.html

---

# Disclaimer

This implementation is intended for academic and research purposes.

It demonstrates a prototype architecture for secure medical-image transmission and should not be deployed as a production medical-data security system without appropriate security evaluation, regulatory compliance, key-management infrastructure, and testing in the target environment.

---

# Author & Attribution

**Project:** Authenticated Secure Medical Image Transmission Using HQC and Ascon

**Component:** Software Implementation

**Course:** Final Year Electronics and Communication Engineering Project

**Institution:** Government College of Engineering Kannur (GCE Kannur)

**Academic Year:** 2023–2027

## Project Team

- Abhijith K
- Arya
- Jithin
- Gokul

## Maintainer

**Abhijith K**

**Email:** abhijithk20052@gmail.com
