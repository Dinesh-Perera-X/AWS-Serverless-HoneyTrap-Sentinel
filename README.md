# AWS Serverless HoneyTrap Sentinel 🍯⚡

An active defense and deception engine for AWS cloud environments. Generates, arms, and monitors synthetic IAM access keys (honeytokens) and decoy S3 bait buckets. When an attacker trips a canary credential, the sentinel tracks the event in CloudTrail, profiles the adversary, and generates automated containment rules.

---

## 🎯 5-Day Development Roadmap

- [x] **Day 1: HoneyToken Registry & Synthetic IAM/S3 Decoy Generator**
- [ ] **Day 2: CloudTrail Ingestion & Canary Trip-Wire Detection Engine**
- [ ] **Day 3: Adversary Profiling, Geolocation & MITRE ATT&CK Attribution**
- [ ] **Day 4: Automated Active Defense & Access Key Quarantine Engine**
- [ ] **Day 5: Real-Time Terminal Feed, SIEM Alert Forwarder & Forensic Dossier**

---

## 📦 Installation & Setup

```bash
git clone [https://github.com/Dinesh-Perera-X/AWS-Serverless-HoneyTrap-Sentinel.git](https://github.com/Dinesh-Perera-X/AWS-Serverless-HoneyTrap-Sentinel.git)
cd AWS-Serverless-HoneyTrap-Sentinel
pip3 install -r requirements.txt --break-system-packages
