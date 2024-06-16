# Threshold Encryption Service

## About

This Rust project implements a threshold encryption service using the Rocket framework and the `threshold_crypto` crate. The service allows clients to encrypt and decrypt messages using a threshold cryptography scheme.

## Approach Used to implement the service

The service uses a threshold cryptography scheme provided by the threshold_crypto crate. This involves the following key concepts:

### Key generation and storage

- Key shares are generated during service setup and shares are stored in shared state using structs, service uses `RwLock` to handle concurrent access to shared state for various encrypt and decrypt operaitons.

### Secret Sharing:

- The secret key is divided into multiple shares using Shamir's Secret Sharing scheme.
Each share is distributed to a different entity.

### Threshold:

- Define a threshold t such that any t or more shares can reconstruct the original secret.
This ensures that the secret can still be recovered even if some shares are lost or compromised, but fewer than t shares reveal nothing about the secret.

### Public and Secret Keys:

- Generate a public key set and a corresponding set of secret key shares.
The public key set is used for encryption, while the secret key shares are used to create decryption shares during the decryption process.

### Decryption Shares:

- Each holder of a secret key share can produce a decryption share for a given ciphertext.
Combining the decryption shares from at least t different shares will reconstruct the original plaintext.

## Limitations

- Using `RwLock` is for managing access to shared state is efficient as it will have performance issues for high concurrency systems.

- The key shares are not persistent and a new key pair is generated every time the serice starts

- The current implementation stores all key shares in shared storage which can result in single point of failure

## Improvements for real world applications

This service is just a basic demonstration of threshold cryptography and it needs following improvements to adapt to real world applications:

- Distributed Share Storage: Store key shares in different  servers to enhance security. Using distributed databases or blockchain could be beneficial.

- User Authentication: Currently there is no authentication to use service, ideally there should be some authentication to give access to authorized users only.

- Error handling: Error handling can be improved to handle more edge cases and provide better messages.

- Logging : Add logging to detect issues and monitor performance.

- HTTPS implementation: Communication between client and service should be HTTPS.

- Configuration Management: The service url, threshold and other settings for service should be configurable in config file.

## Features

- **Public Key Retrieval**: Clients can retrieve the public key set used for encryption.
- **Encryption**: Clients can encrypt plaintext messages using the public key set.
- **Decryption**: Clients can decrypt ciphertext messages using the secret key shares.

## Prerequisites

- Rust and Cargo installed.
- Rocket framework.
- Dependencies specified in `Cargo.toml`.

## Getting Started

### Install Dependencies

```sh
cargo build
```

### Running the Service

```sh
cargo run
```
The service will start on http://localhost:8000.

### Endpoints

#### Get Public Key

- URL: /public_key
- Method: GET
- Response:
200 OK with JSON body containing the public key set.

#### Encrypt

- URL: /encrypt
- Method: POST
- Request Body:
```json
{
  "plaintext": "Your message here"
}
```
- Response:
200 OK with JSON body containing the ciphertext.

#### Decrypt

- URL: /decrypt
- Method: POST
- Request Body:
```json
{
  "ciphertext": "Ciphertext here"
}
```
- Response:
200 OK with JSON body containing the decryption shares.

### Error Handling

The service functions return descriptive error messages in case of failures, such as invalid input or failed encryption/decryption processes.

### Testing

Unit tests are provided in the tests directory. To run the tests:
```sh
cargo test
```
