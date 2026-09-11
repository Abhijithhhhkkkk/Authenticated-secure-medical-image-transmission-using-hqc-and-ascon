Authenticated Secure Medical Image Transmission Using HQC and Ascon

Overview

This software implementation demonstrates a secure medical image transmission system that combines HQC post-quantum key encapsulation with Ascon-128 authenticated encryption and HMAC-SHA256-based receiver authentication.

The system is designed to securely transmit medical images between a sender and one of multiple authorized receivers over a TCP/IP network.

The implementation follows the security sequence:

Sender
   │
   ▼
Select Medical Image
   │
   ▼
Select Receiver
   │
   ▼
HMAC Challenge–Response Authentication
   │
   ├── Authentication Failed ──► Stop
   │
   ▼
HQC Key Encapsulation
   │
   ▼
Shared Secret Established
   │
   ▼
Derive ASCON-128 Session Key
   │
   ▼
ASCON-128 Image Encryption
   │
   ▼
TCP Transmission
   │
   ▼
ASCON-128 Authentication & Decryption
   │
   ▼
Medical Image Reconstructed

---

Objectives

The software implementation aims to provide:

- Secure medical image transmission over TCP/IP.
- Authentication of the intended receiver before key exchange.
- Protection against unauthorized receivers.
- Post-quantum secure key establishment using HQC KEM.
- Confidentiality and integrity using Ascon-128 AEAD.
- HMAC-SHA256 challenge-response authentication.
- Performance measurement of cryptographic and communication operations.
- Support for multiple receivers.
- Secure session-key generation without transmitting the ASCON key directly.

---

System Architecture

The implementation consists of two main components:

Sender

The sender acts as a TCP client.

Responsibilities:

1. Load receiver information from the ".env" file.
2. Select the required receiver.
3. Select the medical image.
4. Establish a TCP connection with the selected receiver.
5. Perform HMAC challenge-response authentication.
6. Continue only if authentication succeeds.
7. Receive the receiver's HQC public key.
8. Perform HQC encapsulation.
9. Send the HQC ciphertext to the receiver.
10. Derive the ASCON session key from the HQC shared secret.
11. Encrypt the medical image using Ascon-128.
12. Transmit the encrypted image.
13. Record performance parameters.

Receiver

The receiver acts as a TCP server.

Responsibilities:

1. Listen for incoming TCP connections.
2. Identify itself using its configured receiver ID.
3. Respond to the sender's authentication challenge.
4. Stop the session if authentication fails.
5. Generate an HQC key pair after successful authentication.
6. Send the HQC public key to the sender.
7. Receive the HQC ciphertext.
8. Perform HQC decapsulation.
9. Derive the same ASCON session key.
10. Receive the encrypted medical image.
11. Verify the Ascon-128 authentication tag.
12. Decrypt the image.
13. Save the reconstructed medical image.
14. Record performance parameters.

---

Security Protocol

1. Receiver Authentication

The sender generates a fresh random challenge:

challenge = secrets.token_bytes(32)

The receiver calculates:

HMAC-SHA256(Kidentity, Challenge || Receiver_ID)

The sender independently calculates the expected HMAC and compares the values using a secure comparison.

hmac.compare_digest(received_hmac, expected_hmac)

If the values match:

Authentication Successful
        ↓
HQC Key Exchange Allowed

If the values do not match:

Authentication Failed
        ↓
HQC Key Exchange NOT Performed
        ↓
Medical Image NOT Sent

The challenge is freshly generated for every authentication session to prevent replay of previously captured authentication responses.

---

2. HQC Key Encapsulation

After successful authentication, the receiver generates an HQC key pair:

HQC Key Generation
      │
      ├── Public Key
      └── Private Key

The receiver sends its public key to the sender.

The sender performs encapsulation:

Receiver Public Key
        │
        ▼
HQC Encapsulation
        │
        ├── Ciphertext
        └── Shared Secret

The ciphertext is sent to the receiver.

The receiver uses its private key to perform decapsulation:

HQC Ciphertext + Private Key
              │
              ▼
        Shared Secret

Both sides therefore obtain the same shared secret without transmitting the secret itself.

---

3. ASCON-128 Session Key

The HQC shared secret is used as the basis for deriving the symmetric session key.

Conceptually:

HQC Shared Secret
       │
       ▼
 Key Derivation
       │
       ▼
ASCON-128 Session Key

The ASCON session key is not transmitted directly over the network.

---

4. Medical Image Encryption

The selected medical image is encrypted using Ascon-128 authenticated encryption.

The encryption process produces:

Medical Image
     +
ASCON Session Key
     +
Nonce
     +
AAD
     │
     ▼
ASCON-128 AEAD
     │
     ▼
Ciphertext + Authentication Tag

The implementation uses:

AAD = "medical-image"

The authentication tag allows the receiver to detect modification or corruption of the encrypted image.

---

5. Secure Transmission

The encrypted image and required metadata are transmitted using TCP.

The ASCON session key itself is not included in the transmission packet.

Conceptually:

Secure Packet
├── Receiver ID
├── Patient Information
├── Image Filename
├── Nonce
├── Encrypted Image
└── Authentication Tag

---

Project Structure

A recommended software implementation structure is:

software-implementation/
│
├── sender/
│   ├── sender.py
│   ├── .env
│   ├── img/
│   │   ├── image1.jpg
│   │   ├── image2.png
│   │   └── ...
│   └── performance_log.csv
│
├── receiver/
│   ├── receiver.py
│   ├── .env
│   ├── img/
│   │   ├── received_image1.jpg
│   │   └── ...
│   └── performance_log_receiver.csv
│
└── README.md

---

Requirements

Software Requirements

- Python 3.x
- TCP/IP network
- Linux/Ubuntu recommended
- Python virtual environment recommended

Python Libraries

Install the required packages using:

pip install python-dotenv

Install the required ASCON implementation used by the project.

For an HQC implementation based on "liboqs-python", install/configure the corresponding Open Quantum Safe libraries and Python bindings.

---

Environment Configuration

Sender ".env"

The sender stores the IP addresses and authentication secrets of the available receivers.

Example:

TCP_PORT=5000

RECEIVER1_IP=192.168.1.101
RECEIVER1_KEY=receiver1-secret-key-123456

RECEIVER2_IP=192.168.1.102
RECEIVER2_KEY=receiver2-secret-key-654321

RECEIVER3_IP=192.168.1.103
RECEIVER3_KEY=receiver3-secret-key-abcdef

The sender uses these values to identify and connect to the selected receiver.

---

Receiver ".env"

Each receiver stores its own identity and corresponding authentication secret.

Example:

RECEIVER_ID=receiver1
RECEIVER_SECRET=receiver1-secret-key-123456
TCP_PORT=5000

The receiver secret must match the corresponding key configured on the sender.

For example:

Sender:
RECEIVER1_KEY=receiver1-secret-key-123456

Receiver 1:
RECEIVER_SECRET=receiver1-secret-key-123456

The ".env" files should not be uploaded to GitHub because they contain secret authentication keys.

---

Running the Software

Step 1 — Start the Receiver

On the receiver machine:

python3 receiver.py

The receiver starts the TCP server and waits for an incoming connection.

Example:

Receiver ID: receiver1
TCP server listening on port 5000...
Waiting for sender connection...

---

Step 2 — Start the Sender

On the sender machine:

python3 sender.py

The sender displays the available receivers:

Available Receivers:

1. receiver1
2. receiver2
3. receiver3

Select receiver:

The sender then displays the available medical images:

Available Medical Images:

1. patient1.jpg
2. patient2.png
3. patient3.jpg

Select image:

---

Authentication Process

After the TCP connection is established:

Connecting to receiver1...
TCP connection established.

Starting receiver authentication...
Challenge generated.

Waiting for HMAC response...

If authentication succeeds:

Authentication successful.
Starting HQC key exchange...

If authentication fails:

Authentication failed.
HQC key exchange will NOT start.
Medical image will NOT be sent.

This conditional behaviour is an important security requirement of the implementation.

---

HQC Key Exchange

After successful authentication:

Receiver:
Generating HQC key pair...

Sender:
Receiving HQC public key...
Performing HQC encapsulation...

Sender:
Sending HQC ciphertext...

Receiver:
Performing HQC decapsulation...

HQC shared secret established.

The resulting shared secret is used to derive the ASCON session key.

---

Medical Image Transmission

The sender encrypts the selected medical image:

Encrypting medical image...
ASCON-128 encryption completed.

Sending encrypted medical image...
Transmission completed.

The receiver then performs:

Receiving encrypted image...
Verifying ASCON authentication tag...
Authentication tag valid.

Decrypting medical image...
Medical image successfully reconstructed.

The decrypted image is stored in:

receiver/img/

---

Performance Measurement

The implementation can record the following parameters:

Parameter| Description
HQC Key Generation Time| Time required to generate the HQC key pair
HQC Encapsulation Time| Time required for sender-side encapsulation
HQC Decapsulation Time| Time required for receiver-side decapsulation
HMAC Authentication Time| Time required for receiver authentication
ASCON Encryption Time| Time required to encrypt the image
ASCON Decryption Time| Time required to decrypt the image
Transmission Time| Time required to transfer the encrypted image
Overall Delay| Total processing and communication delay
Throughput| Amount of image data transferred per second
Image Size| Size of the medical image
Latency| Communication delay between sender and receiver

Performance results can be stored in CSV files:

performance_log.csv
performance_log_receiver.csv

---

Security Features

Confidentiality

Ascon-128 encrypts the medical image so that unauthorized parties cannot obtain the original image from intercepted ciphertext.

Integrity

The ASCON authentication tag allows the receiver to detect modification of the encrypted image.

Receiver Authentication

HMAC-SHA256 challenge-response verifies that the selected receiver possesses the correct pre-shared authentication secret.

Replay Resistance

A fresh random challenge is generated for every authentication session.

Post-Quantum Key Establishment

HQC KEM is used to establish the shared secret used for the symmetric encryption session.

Session Key Protection

The ASCON session key is derived from the HQC shared secret rather than being transmitted directly over the network.

Unauthorized Receiver Protection

An unauthenticated receiver does not proceed to HQC key exchange or medical-image transmission.

---

Communication Flow

                    SENDER
                      │
                      │ TCP Connection
                      ▼
                 RECEIVER
                      │
                      │ Receiver ID
                      ▼
                 Authentication
                      │
             HMAC Challenge/Response
                      │
             ┌────────┴────────┐
             │                 │
          FAILED             SUCCESS
             │                 │
             ▼                 ▼
           STOP          HQC Key Exchange
                               │
                               ▼
                       Shared Secret
                               │
                               ▼
                       ASCON Session Key
                               │
                               ▼
                       Image Encryption
                               │
                               ▼
                       TCP Transmission
                               │
                               ▼
                       Image Decryption
                               │
                               ▼
                     Medical Image Output

---

Important Security Note

The authentication secret and other sensitive configuration values must not be hard-coded into the source code in the final implementation.

Use environment variables:

.env

and exclude them from version control:

.env

The ASCON session key should also never be transmitted directly as part of the image packet. It should be derived independently by the sender and receiver from the established HQC shared secret.

---

Limitations

This software implementation primarily demonstrates the cryptographic and network-security aspects of medical image transmission.

The following hardware-level measurements are outside the basic Python software implementation:

- FPGA resource utilization
- FPGA power consumption
- Hardware clock-frequency analysis
- Hardware throughput optimization

These parameters can be evaluated separately when the cryptographic components are implemented on FPGA hardware.

---

Future Enhancements

Possible future improvements include:

- FPGA acceleration of HQC and Ascon.
- Hardware resource utilization analysis.
- Power-consumption measurement.
- Support for additional medical image formats.
- Multi-image transmission.
- Improved key-management infrastructure.
- Secure logging and audit trails.
- Integration with medical-image standards such as DICOM.
- Network performance optimization.
- Comparison with classical cryptographic key-exchange mechanisms.

---

Disclaimer

This implementation is intended for academic and research purposes. It demonstrates a prototype secure medical-image transmission architecture and should not be considered a production medical-data security system without further security auditing, testing, and compliance validation.

---

Author

Final Year Electronics and Communication Engineering Project

Project: Authenticated Secure Medical Image Transmission Using HQC and Ascon
