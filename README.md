# CACC-Secure: A Lightweight, Secure Context-Aware Collaborative Caching Protocol for Named Data Networking

This repository contains the official `ndnSIM` implementation of **CACC-Secure**, a lightweight, secure, non-AI caching protocol designed for Named Data Networking (NDN). The architecture embeds a 6-byte data-plane header containing a Popularity Hint (PH), Origin Hop-Count (OHC), Sequence Number (SEQ), and a truncated HMAC to deliver defense-in-depth against metadata manipulation and cache pollution attacks without incurring control-plane signaling overhead.

## Repository Architecture

* `src/cacc-secure/` - Module models (HMAC, sequence tracking, rate limiting, trust metrics, caching engine) and helpers.
* `scenarios/` - Network simulation layout scripts (GEANT backbone and IoT Mesh topologies).
* `scripts/` - Output logs extraction tools and performance rendering scripts.

## Prerequisites & Installation

CACC-Secure requires an operational installation of `ns-3` coupled with `ndnSIM` (v2.8 or newer) and the OpenSSL developer library for native packet hashing.

```bash
# Install cryptographic dependencies (Ubuntu example)
sudo apt-get install libssl-dev basic-build-tools

# Clone this extension directly into your ns-3 src directory
cd ns-3/src/
git clone [https://github.com/Kezrane/CACC.git](https://github.com/Kezrane/CACC.git) cacc-secure
cd ..