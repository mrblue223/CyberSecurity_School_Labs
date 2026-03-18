![Course: Cyber_Defense](https://img.shields.io/badge/Course-Cyber_Defense-red?style=for-the-badge)
![Status: In-Progress](https://img.shields.io/badge/Status-In--Progress-yellow?style=for-the-badge)

![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Bash](https://img.shields.io/badge/bash-%234EAA25.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

# 🛡️ Optimizing SSL Certificates for webserver (Apache / Nginx and mail server (Postfix)
**Course:** Cyber Defense - Assignment 1  
**Target Domain:** `gwallofchina.yulcyberhub.click`

## 📖 Overview
This repository contains a suite of automation scripts designed to provision, harden, and manage a secure web and mail infrastructure on AWS. These instances will be running Apcache or Nginx, and a mail server (Postfix). And hopefully when the lab is finished the full assignment with step by step instructions on how to recreate the environment.

---

## 🛠️ Technical Stack
* **Cloud Provider:** AWS (Route 53, EC2)
* **Operating System:** Debian / Kali Linux
* **Automation:** Bash (AWS CLI v2)
* **Security Layer:** DNSSEC, IMDSv2, SPF, DKIM, DMARC, MTA-STS

---

## 🚀 Automation Scripts

### 1. DNS record Script (`dns-record-setup.sh`)
Automates the deployment of 16+ DNS records to Route 53.
* **Features:** Implements strict `p=reject` DMARC policies, SPF hard fails, and automated MTA-STS ID generation.
* **Usage:**
  ```bash
  chmod +x hardened-dns-setup.sh
  ./hardened-dns-setup.sh <HOSTED_ZONE_ID>
