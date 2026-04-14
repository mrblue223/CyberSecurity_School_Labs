# 🛡️ G-Wall SOC Toolkit & Threat Intelligence Resources

A curated collection of essential tools and resources for the modern SOC Analyst, specifically focused on defensive infrastructure, incident response, and threat hunting.

## 🔎 Threat Intelligence & Reputation
*Identify the "Who" and "Why" behind the IP address.*

| Tool | Purpose |
| :--- | :--- |
| **[AbuseIPDB](https://www.abuseipdb.com/)** | Check if an IP address has been reported for malicious activity (brute-forcing, spam, etc.). |
| **[VirusTotal](https://www.virustotal.com/)** | Analyze URLs, IPs, and files against 70+ antivirus scanners and blacklist services. |
| **[GreyNoise](https://www.greynoise.io/)** | Filter out "internet background noise" to focus on targeted attacks versus generic bot scans. |
| **[AlienVault OTX](https://otx.alienvault.com/)** | An open community for sharing "pulses" (IOCs) regarding active global threats. |
| **[Cisco Talos](https://talosintelligence.com/)** | Comprehensive IP and domain reputation lookups maintained by one of the world's largest security teams. |

## 🌐 OSINT & Reconnaissance
*Map the infrastructure and digital footprint of an attacker.*

| Tool | Purpose |
| :--- | :--- |
| **[Shodan](https://www.shodan.io/)** | Search engine for internet-connected devices; identify open ports and services on an attacker's server. |
| **[Censys](https://censys.io/)** | Search engine for hosts and networks; excellent for certificate transparency and service mapping. |
| **[URLScan.io](https://urlscan.io/)** | A sandbox that captures a screenshot and behavior profile of a website without you visiting it. |
| **[CentralOps](https://centralops.net/co/)** | A suite of online network tools including Domain Dossier, Traceroute, and WHOIS lookups. |
| **[IntelTechniques](https://inteltechniques.com/tools/index.html)** | Extensive collection of specialized OSINT search tools for deep investigations. |

## 🛠️ Analysis & Forensics
*Decode payloads and investigate the "How" of an exploit.*

| Tool | Purpose |
| :--- | :--- |
| **[CyberChef](https://gchq.github.io/CyberChef/)** | The "Cyber Swiss Army Knife" for encoding, decoding, hashing, and data manipulation. |
| **[Any.Run](https://any.run/)** | An interactive online malware sandbox to watch how a file or URL behaves in a live Windows environment. |
| **[Joe Sandbox](https://www.joesandbox.com/)** | Deep malware analysis that generates detailed reports on behavior and MITRE ATT&CK mapping. |
| **[Wireshark](https://www.wireshark.org/)** | The world's foremost network protocol analyzer for deep packet inspection (DPI). |
| **[Brim (Zui)](https://www.brimdata.io/)** | A desktop app to search and visualize large packet captures and structured logs (Zeek/Suricata). |

## 📚 Frameworks & News
*Stay updated on the latest vulnerabilities and industry standards.*

| Tool | Purpose |
| :--- | :--- |
| **[MITRE ATT&CK](https://attack.mitre.org/)** | A globally accessible knowledge base of adversary tactics and techniques based on real-world observations. |
| **[CVE Mitre](https://cve.mitre.org/)** | The master list of Common Vulnerabilities and Exposures (publicly disclosed security flaws). |
| **[Exploit-DB](https://www.exploit-db.com/)** | An archive of exploits and vulnerable software for penetration testing research. |
| **[BleepingComputer](https://www.bleepingcomputer.com/)** | Real-time news on data breaches, ransomware, and technical security trends. |
| **[Cyberwire Daily](https://thecyberwire.com/podcasts/daily-podcast)** | A concise daily podcast briefing for cybersecurity professionals. |

---

## 🚀 Pro SOC Workflow
1. **Detect**: Alert fires in **Wazuh** (e.g., Rule 100700 - Brute Force).
2. **Contextualize**: Paste IP into **AbuseIPDB** and **GreyNoise** to check reputation.
3. **Investigate**: Use **Shodan** to see if the attacker is a known bot or a compromised VPS.
4. **Analyze**: If a payload was sent, use **CyberChef** to decode the script.
5. **Respond**: Update **Wazuh Active Response** or block the ASN at the firewall level.
