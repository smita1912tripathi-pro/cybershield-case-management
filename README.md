# CyberShield 🛡️
> **Next-Gen Cyber Crime Case Management & Evidence Integrity System for Police & Cyber Cells**

CyberShield ek powerful aur lightweight single-file FastAPI application hai jo cyber cells aur law enforcement agencies ke liye design kiya gaya hai. Isme advanced case tracking, automated Indicators of Compromise (IOC) extraction, gang/linked-case detection, aur SHA-256 tamper-evident chain of custody jaise features shamil hain.

---

## ✨ Features (Vividh Visheshatayen)

* 🔐 **Secure Authentication & RBAC**: JWT-based authentication aur Role-Based Access Control (`admin`, `investigator`, `officer`, `viewer`).
* 🤖 **Auto IOC Extraction**: Complaint descriptions se automatically URLs, domains, UPI IDs, emails, IP addresses, aur phone numbers detect kar leta hai.
* 🔗 **Linked-Case / Gang Detection**: Shared IOCs ke zariye alag-alag cases ke beech connection dhundh kar ek hi cyber gang ka pata lagata hai.
* 📊 **Explainable Risk Scoring**: Loss amount, category weight, aur IOCs ke adhar par dynamic 0-100 risk score aur severity (`critical`, `high`, `medium`, `low`) calculate hoti hai.
* 📁 **SHA-256 Evidence Integrity & Custody**: Evidence files ka cryptographic fingerprint track hota hai, jisse tamper hone par turant pata chal jata hai.
* ⛓️ **Tamper-Evident Audit Ledger**: Hash-chained audit log jo ensure karta hai ki system ki history ke sath koi chhedchhad na ho sake.
* 🖥️ **Built-in Dashboard**: Ek khoobsurat, modern, responsive Single-Page Dashboard jo bina kisi extra setup ke direct `/` par available hai.

---

## 🚀 Quick Start (Kaise Chalayein)

### Prerequisites
* Python 3.8+ installed hona chahiye.

### 1. Installation
Terminal ya command prompt mein yeh commands run karein:
```bash
pip install fastapi uvicorn pyjwt
