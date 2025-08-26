[![release](https://github.com/affinidi/recrypt-dart/actions/workflows/release.yaml/badge.svg)](https://github.com/affinidi/recrypt-dart/actions/workflows/release.yaml)
[![publish](https://github.com/affinidi/recrypt-dart/actions/workflows/publish.yaml/badge.svg)](https://github.com/affinidi/recrypt-dart/actions/workflows/publish.yaml)
[![check](https://github.com/affinidi/recrypt-dart/actions/workflows/check.yaml/badge.svg)](https://github.com/affinidi/recrypt-dart/actions/workflows/check.yaml)

# recrypt

Proxy Re-Encryption (PRE) utilities for Dart enabling secure, server-mediated sharing of encrypted data without exposing plaintext.
This library lets a data owner encrypt content once, then delegate decryption rights to other parties via transformation (re-encryption) keys—without sharing private keys or re-encrypting the original data.

## Use cases:

- End-to-end encrypted group or multi-recipient messaging
- Zero-knowledge relay / brokered data exchange
- Secure access delegation and revocation
  Core concepts:
- Owner encrypts a symmetric content key under their public key
- A transformation key (owner private key + recipient public key) lets an untrusted server convert the encrypted key for a recipient
- Recipient uses their private key to recover the symmetric key and decrypt the content
- Server never learns the plaintext or symmetric key

## Benefits:

- Least-privilege server role
- Scales better than encrypting separately for every recipient
- Cryptographic separation of duties (encryption, transformation, decryption)
- Ideal when you need brokered delivery (e.g. group chat) where the transport service must route but not read messages.
