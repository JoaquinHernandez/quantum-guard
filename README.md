# quantum-guard

# 🛡️ quantum-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![NIST PQC](https://img.shields.io/badge/NIST%20PQC-ML--KEM--768-purple.svg)](https://csrc.nist.gov/)

**quantum-guard** is an open-source cybersecurity CLI and auditor built to test web endpoints for **Post-Quantum Cryptography (PQC)** readiness and external perimeter exposure.

It defends against **"Harvest Now, Decrypt Later" (HNDL)** threats by verifying hybrid quantum-resilient key exchanges (`X25519MLKEM768`, `Kyber768`), modern TLS 1.3 implementation, HTTP security headers, and open sensitive ports.

---

## ⚡ Features

- ⚛️ **PQC Key Exchange Detection:** Probes endpoints using custom TLS 1.3 `ClientHello` extensions for NIST-standardized `X25519MLKEM768` (0x11EC).
- 🔒 **TLS & Transport Security:** Audits TLS version enforcement and validates modern cryptographic standards.
- 🛡️ **Defensive Header Analysis:** Evaluates `Strict-Transport-Security` (HSTS) and `Content-Security-Policy` (CSP).
- 📡 **Concurrent Attack Surface Scan:** Asynchronously audits high-risk ports (`21`, `22`, `3389`, `6379`, `27017`).
- 📊 **Risk Scoring Matrix:** Computes a 0–100 posture score and assigns a clear readiness grade ($A^+$ to $F$).

---

## 🚀 Installation & Usage

### 1. Clone & Install
```bash
git clone [https://github.com/yourusername/quantum-guard.git](https://github.com/yourusername/quantum-guard.git)
cd quantum-guard
pip install -e .


Run and scan
quantum-guard cloudflare.com
