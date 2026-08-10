# Secure Medical Image Transmission Workflow

## Post-Quantum Cryptographic Framework

This workflow describes the complete secure medical image transmission
process using **HQC KEM, ASCON-128 AEAD, receiver authentication, TCP/IP
communication, and FPGA acceleration**.

---

## System Workflow

```text
START
  │
  ▼
Sender Selects Medical Image
  │
  ▼
Load Receiver Information / Public Keys
  │
  ▼
┌──────────────────────────────────────────────┐
│ For Each Receiver (Receiver 1 ... Receiver N)│
└──────────────────────────────────────────────┘
  │
  ▼
Receiver Sends HQC Public Key
  │
  ▼
Sender Performs HQC Encapsulation
  │
  ▼
Generate Shared Session Key + HQC Ciphertext
  │
  ▼
Send HQC Ciphertext to Corresponding Receiver
  │
  ▼
Receiver Performs HQC Decapsulation
  │
  ▼
Shared Session Key Established
  │
  ▼
────────────────────────────────────────────────
  │
  ▼
Sender Generates Authentication Challenge (Nonce)
  │
  ▼
Encrypt Challenge Using ASCON Session Key (Optional)
  │
  ▼
Send Challenge to All Established Receivers
  │
  ▼
Receiver Computes
HMAC(K_identity, Challenge || Receiver_ID)
  │
  ▼
Receiver Sends HMAC Response to Sender
  │
  ▼
Sender Verifies HMAC Response
  │
  ▼
           All Receivers Verified?
              /          \
            No            Yes
            │              │
            ▼              ▼
   Reject Unauthorized   Create Authorized
       Receiver          Receiver List
                            │
                            ▼
                Encrypt Medical Image
                     using ASCON-128 AEAD
                            │
                            ▼
              Create Secure Transmission Packet
          {Encrypted Image + Tag + Receiver ID}
                            │
                            ▼
                  TCP/IP Communication
                            │
                            ▼
              Authorized Receiver Receives Packet
                            │
                            ▼
              Verify ASCON Authentication Tag
                            │
                            ▼
                 Authentication Tag Valid?
                    /                \
                  No                  Yes
                  │                    │
                  ▼                    ▼
            Discard Packet      Decrypt Medical Image
                                       │
                                       ▼
                              Display Medical Image
                                       │
                                       ▼
                         Record Performance Metrics
                                       │
                                       ▼
                           FPGA Hardware Acceleration
                              ┌───────────────┐
                              │     ASCON     │
                              │      +        │
                              │      HQC      │
                              └───────────────┘
                                       │
                                       ▼
                                      END
