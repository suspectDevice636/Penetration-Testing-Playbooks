# Penetration Testing Playbooks

A comprehensive collection of practical penetration testing methodologies, tools, commands, and payloads for security professionals.

**Table of Contents**
- [Quick Start](#quick-start)
- [Playbook Index](#playbook-index)
- [Category Overview](#category-overview)
- [How to Use](#how-to-use)
- [Key Resources](#key-resources)

---

## Quick Start

Each playbook follows a consistent structure:
1. **Testing Categories** — Organized by attack surface
2. **Tools & Commands** — Ready-to-use commands with examples
3. **Payloads** — Working exploits and injection vectors
4. **Expected Results** — What successful exploitation looks like
5. **Remediation** — How to fix the vulnerability

**Pro Tip:** Use `Ctrl+F` to search within playbooks. All are markdown-formatted for easy grepping.

---

## Playbook Index

### 🌐 Web Applications
- **[WSTG Playbook (Expanded)](01-Web-Applications/WSTG-Playbook-Expanded.md)** — OWASP Web Security Testing Guide with 102 practical test procedures across 12 categories
- **[Web App Penetration Testing](01-Web-Applications/webapp-pentesting-playbook.md)** — Complete web application testing methodology (authentication, authorization, injection, XSS, CSRF, etc.)
- **[Web App Quick Reference](01-Web-Applications/webapp-pentesting-quick-reference.md)** — Condensed cheat sheet for quick lookups during engagements
- **[Chatbot & Prompt Injection](01-Web-Applications/Chatbot-Prompt-Injection-Playbook.md)** — AI/LLM security testing (prompt injection, model extraction, jailbreaks, etc.)

### 🔌 APIs
- **[API Security Testing](02-APIs/api-pentesting-playbook.md)** — REST/GraphQL API enumeration, authentication bypass, rate limiting, injection attacks, IDOR

### 🌍 Network & Infrastructure
- **[Network Pentesting](03-Network-Infrastructure/network-infrastructure-pentesting-playbook.md)** — Nmap scanning, service enumeration, exploitation, lateral movement, privilege escalation

### ☁️ Cloud
- **[AWS Security Testing](04-Cloud/cloud-aws-pentesting-playbook.md)** — AWS IAM misconfigurations, S3 bucket enumeration, EC2/RDS exploitation, cloud-specific auth bypass

### 📱 Mobile Applications
- **[Mobile App Security](05-Mobile/mobile-app-security-playbook.md)** — iOS/Android insecure storage, injection attacks, authentication bypass, reverse engineering

### 🔧 IoT & Embedded
- **[IoT/Embedded Security](06-IoT-Embedded/iot-embedded-security-playbook.md)** — Firmware analysis, hardware hacking, protocol exploitation, firmware extraction

### 🕵️ OSINT & Attribution
- **[OSINT & Attribution](07-OSINT/osint-attribution-playbook.md)** — Open-source intelligence gathering, target reconnaissance, footprinting, identity correlation

### 📋 Compliance & Standards
- **[PCI-DSS Testing](08-Compliance/pci-dss-pentesting-playbook.md)** — PCI-DSS compliance assessment, cardholder data protection, payment system security
- **[PCI-DSS Web App Quick Reference](08-Compliance/pci-webapp-pentesting-playbook.md)** — Focused quick-reference for web app & API pentesting with PCI compliance (commands + expected outputs)

---

## Category Overview

| Category | Focus | Best For |
|----------|-------|----------|
| Web Applications | OWASP Top 10, injection, XSS, CSRF, auth bypass | Web app security assessments |
| APIs | REST/GraphQL endpoints, rate limiting, IDOR | API penetration testing |
| Network | Scanning, enumeration, exploitation, lateral movement | Infrastructure security |
| Cloud | AWS/Azure/GCP misconfigurations, IAM, data exposure | Cloud security audits |
| Mobile | App-level vulnerabilities, reverse engineering | Mobile app assessments |
| IoT/Embedded | Hardware, firmware, protocols | Device security testing |
| OSINT | Information gathering, reconnaissance | Passive reconnaissance phase |
| Compliance | PCI-DSS, HIPAA alignment, audit readiness | Compliance-driven testing |

---

## How to Use

### During Active Engagement

1. **Identify the target type** (web app, API, network, etc.)
2. **Open the corresponding playbook**
3. **Follow the testing categories in order**
4. **Copy commands/payloads and adapt to your target**
5. **Document results with evidence**

### As a Reference

- **Web app quick ref?** → Open [webapp-pentesting-quick-reference.md](01-Web-Applications/webapp-pentesting-quick-reference.md)
- **What payload works for XSS?** → Search in [WSTG-Playbook-Expanded.md](01-Web-Applications/WSTG-Playbook-Expanded.md) for "XSS"
- **API IDOR patterns?** → See [api-pentesting-playbook.md](02-APIs/api-pentesting-playbook.md#idor)
- **AWS bucket enumeration?** → See [cloud-aws-pentesting-playbook.md](04-Cloud/cloud-aws-pentesting-playbook.md)

### Search Across All Playbooks

```bash
# Find all mentions of "SQL injection"
grep -r "SQL injection" .

# Find all payloads matching a pattern
grep -r "payload" . | grep -i xss

# List all testing categories
grep "^## " *.md
```

---

## Key Resources

### Tools (Pre-configured)
- **[recon.sh](tools/recon.sh)** — Automated reconnaissance script (Nmap, Shodan, OSINT queries)

### External References (Embedded in Playbooks)
- OWASP Testing Guide (WSTG)
- NIST Cybersecurity Framework
- CWE/CVSS scoring
- Tool-specific documentation (Burp Suite, OWASP ZAP, etc.)

### When You Need More
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **NIST SP 800-115:** Technical Security Testing
- **PTES:** Penetration Testing Execution Standard
- **HackTricks:** https://book.hacktricks.xyz/

---

## Methodology

All playbooks follow the **OWASP Web Security Testing Guide (WSTG)** structure:
1. **Reconnaissance** — Target identification and footprinting
2. **Scanning & Enumeration** — Service/vulnerability discovery
3. **Vulnerability Analysis** — Classification and severity assessment
4. **Exploitation** — Proof-of-concept attacks
5. **Post-Exploitation** — Persistence, privilege escalation, data exfiltration
6. **Reporting** — Findings with remediation guidance

---

## Coverage

**Total Test Cases:** 200+ practical procedures across all playbooks

- ✅ Authentication & Authorization
- ✅ Input Validation & Injection
- ✅ Cross-Site Scripting (XSS) & CSRF
- ✅ Broken Access Control (IDOR)
- ✅ Sensitive Data Exposure
- ✅ Rate Limiting & DoS
- ✅ API Security
- ✅ Cloud Misconfigurations
- ✅ Mobile-Specific Vulnerabilities
- ✅ Hardware & Firmware Exploitation
- ✅ Network Reconnaissance & Lateral Movement
- ✅ Privilege Escalation

---

## Legal Disclaimer

⚠️ **These playbooks are for authorized security testing only.** Unauthorized access to computer systems is illegal. Always obtain written authorization before conducting penetration tests.

---

## Version

**Last Updated:** March 14, 2026  
**Playbooks:** 12 comprehensive guides  
**Testing Categories:** 80+

---

## Contributing

Found a better payload? Discovered a new testing technique? Feel free to submit updates.

---

**Ready to test?** Pick a playbook and dive in. 🔓
