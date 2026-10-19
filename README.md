<div align="center">

# 🛡️ CyberShield
### Next-Gen Cyber Crime Case Management & Evidence Integrity System

*A lightweight, secure, single-file FastAPI application designed for police cyber cells and law enforcement agencies.*

</div>

---

## 🚀 Overview

**CyberShield** is a comprehensive, production-grade cyber-crime case management system built to streamline investigations. Packed with advanced features like automated Indicators of Compromise (IOC) extraction, gang/linked-case detection, cryptographic evidence integrity checks, and a hash-chained audit ledger, it ensures total accountability and modern digital forensics workflow management.

---

## ✨ Core Features

* **🔐 Secure Authentication & RBAC**: Robust JWT-based authentication coupled with strict Role-Based Access Control (`admin`, `investigator`, `officer`, `viewer`)[span_0](start_span)[span_0](end_span).
* **🤖 Automated IOC Extraction**: Automatically parses complaint descriptions to extract and de-duplicate URLs, domains, UPI IDs, emails, IP addresses, and phone numbers[span_1](start_span)[span_1](end_span).
* **🔗 Linked-Case / Gang Detection**: Automatically correlates shared IOCs across distinct cases to flag potential coordinated cyber-crime campaigns or single gangs[span_2](start_span)[span_2](end_span).
* **📊 Explainable Risk Scoring**: Dynamically calculates a 0-100 risk score and severity level (`critical`, `high`, `medium`, `low`) based on financial loss, category weight, IOC density, and campaign links[span_3](start_span)[span_3](end_span).
* **📁 SHA-256 Evidence Integrity**: Secures digital evidence with cryptographic fingerprinting, full chain of custody logging, and immediate tamper-detection verification[span_4](start_span)[span_4](end_span).
* **⛓️ Tamper-Evident Audit Ledger**: Implements a secure, hash-chained audit log (`prev_hash` + current hash) to prevent and expose any history tampering[span_5](start_span)[span_5](end_span).
* **🖥️ Built-in Single-Page Dashboard**: A lightning-fast, responsive dashboard served directly out-of-the-box at `/` with zero complex frontend build steps required[span_6](start_span)[span_6](end_span).

---

## 🛠️ Tech Stack

* **Backend**: Python, FastAPI, Uvicorn, Pydantic[span_7](start_span)[span_7](end_span)
* **Database**: SQLite with foreign key enforcement and optimized indexing[span_8](start_span)[span_8](end_span)
* **Security**: PyJWT, HMAC-SHA256, PBKDF2 password hashing[span_9](start_span)[span_9](end_span)
* **Frontend**: Modern HTML5, Vanilla JavaScript, CSS Grid/Flexbox[span_10](start_span)[span_10](end_span)

---

## 📦 Quick Start Guide

### Prerequisites
Make sure you have **Python 3.8+** installed on your system.

### 1. Installation
Clone the repository and install the required dependencies:
```bash
pip install fastapi uvicorn pyjwt
