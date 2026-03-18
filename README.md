# 🛡️ Project GWall-of-China: Hardened Infrastructure Automation
**Course:** Cyber Defense - Assignment 1  
**Target Domain:** `gwallofchina.yulcyberhub.click`

## 📖 Overview
This repository contains a suite of automation scripts designed to provision, harden, and manage a secure web and mail infrastructure on AWS. This repo aims to automate most of the manual task for optimizing SSL Certificates for a webserver (Apache / Nginx) and mail server (Postfix).

---

## 🛠️ Technical Stack
* **Cloud Provider:** AWS (Route 53, EC2)
* **Operating System:** Debian / Kali Linux
* **Automation:** Bash (AWS CLI v2)
* **Security Layer:** DNSSEC, IMDSv2, SPF, DKIM, DMARC, MTA-STS

---

## 🚀 Automation Scripts

### 1. DNS Hardening Script (`hardened-dns-setup.sh`)
Automates the deployment of 16+ DNS records to Route 53.
* **Features:** Implements strict `p=reject` DMARC policies, SPF hard fails, and automated MTA-STS ID generation.
* **Usage:**
  ```bash
  chmod +x hardened-dns-setup.sh
  ./hardened-dns-setup.sh <HOSTED_ZONE_ID>
