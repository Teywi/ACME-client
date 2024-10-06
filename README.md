# ACME Client Implementation

## Overview
This project is a solo implementation of an **ACME client** following the specifications from **RFC 8555**. The ACME client is designed to automate the process of obtaining certificates through domain validation. In addition to the client, this project includes implementations of a DNS and HTTP server to handle the challenges as specified by the protocol.

The project follows the guidelines provided in the RFC but was developed entirely based on personal understanding and research, without detailed implementation instructions.

## Technical Highlights
- **ACME Client**: Implements the core functionality of an ACME client, including:
  - Registration and account management with the ACME server.
  - Ordering certificates for domains.
  - Handling challenges (DNS-01, HTTP-01) for domain validation.
  - Requesting certificates and handling responses from the ACME server.
- **DNS and HTTP Servers**: Includes servers to handle the ACME challenges:
  - **DNS-01 Challenge**: A custom DNS server that handles TXT record challenges.
  - **HTTP-01 Challenge**: A lightweight HTTP server to serve validation files.
- **Protocol Compliance**: Strictly adheres to **RFC 8555** guidelines to ensure compliance with the ACME protocol.

## Features
- Automatic certificate issuance and renewal for domains via the ACME protocol.
- Built-in DNS and HTTP servers for handling domain validation challenges.
- Full handling of ACME challenges, including DNS-01 and HTTP-01.
- Use of custom cryptographic material for SSL/TLS operations.

## Contributing
This project was developed as a solo effort as part of an ETH Zurich project. Special thanks to **ETH Zurich** for the project guidelines and the learning opportunity provided by the ACME protocol and **RFC 8555**.

