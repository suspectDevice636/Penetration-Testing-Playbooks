# Web Application Security Testing Guide (WSTG) - Organized Playbooks

This repository contains comprehensive penetration testing playbooks organized by OWASP Web Security Testing Guide (WSTG) categories. Find tests by test ID, vulnerability type, or keyword.

---

## 📚 Quick Navigation

| Category | File | Tests | Keywords |
|----------|------|-------|----------|
| **Information Gathering** | `01-information-gathering.md` | WSTG-INFO-02 to 08 | fingerprint, recon, enumeration, metafiles |
| **Configuration & Deployment** | `02-configuration-deployment.md` | WSTG-CONF-01 to 12 | CSP, headers, HTTP methods, cloud storage, backups |
| **Identity Management** | `03-identity-management.md` (coming) | WSTG-IDNT-01 to 05 | roles, RBAC, registration, account enumeration |
| **Authentication** | `04-authentication.md` (coming) | WSTG-ATHN-01 to 10 | credentials, password reset, MFA, lockout |
| **Authorization** | `05-authorization.md` (coming) | WSTG-ATHZ-01 to 04 | IDOR, privilege escalation, path traversal |
| **Session Management** | `06-session-management.md` (coming) | WSTG-SESS-01 to 05 | session fixation, cookies, CSRF, token prediction |

---

## 🔍 Search by Test ID

### WSTG-INFO (Information Gathering)
- **WSTG-INFO-02** → Fingerprint Web Server — `01-information-gathering.md`
- **WSTG-INFO-03** → Review Webserver Metafiles — `01-information-gathering.md`
- **WSTG-INFO-05** → Review Webpage Content — `01-information-gathering.md`
- **WSTG-INFO-06** → Identify Application Entry Points — `01-information-gathering.md`
- **WSTG-INFO-07** → Map Execution Paths — `01-information-gathering.md`
- **WSTG-INFO-08** → Fingerprint Web Application Framework — `01-information-gathering.md`

### WSTG-CONF (Configuration & Deployment)
- **WSTG-CONF-01** → Test Network Infrastructure Configuration — `02-configuration-deployment.md`
- **WSTG-CONF-02** → Test Application Platform Configuration — `02-configuration-deployment.md`
- **WSTG-CONF-03** → Test File Extensions Handling — `02-configuration-deployment.md`
- **WSTG-CONF-04** → Review Old Backup and Unreferenced Files — `02-configuration-deployment.md`
- **WSTG-CONF-05** → Enumerate Admin Interfaces — `02-configuration-deployment.md`
- **WSTG-CONF-06** → Test HTTP Methods — `02-configuration-deployment.md`
- **WSTG-CONF-07** → Test HTTP Strict Transport Security (HSTS) — `02-configuration-deployment.md`
- **WSTG-CONF-08** → Test RIA Cross Domain Policy (CORS) — `02-configuration-deployment.md`
- **WSTG-CONF-09** → Test File Permission — `02-configuration-deployment.md`
- **WSTG-CONF-11** → Test Cloud Storage — `02-configuration-deployment.md`
- **WSTG-CONF-12** → Testing for Content Security Policy (CSP) ⭐ — `02-configuration-deployment.md`

### WSTG-IDNT (Identity Management)
- **WSTG-IDNT-01** → Test Role Definitions — `03-identity-management.md`
- **WSTG-IDNT-02** → Test User Registration Process — `03-identity-management.md`
- **WSTG-IDNT-03** → Test Account Provisioning Process — `03-identity-management.md`
- **WSTG-IDNT-04** → Testing for Account Enumeration — `03-identity-management.md`
- **WSTG-IDNT-05** → Testing for Weak Username Policy — `03-identity-management.md`

### WSTG-ATHN (Authentication)
- **WSTG-ATHN-01** → Testing for Credentials Transported over Encrypted Channel — `04-authentication.md`
- **WSTG-ATHN-02** → Testing for Default Credentials — `04-authentication.md`
- **WSTG-ATHN-03** → Testing for Weak Lock Out Mechanism — `04-authentication.md`
- **WSTG-ATHN-04** → Testing for Bypassing Authentication Schema — `04-authentication.md`
- **WSTG-ATHN-05** → Testing for Vulnerable Remember Password — `04-authentication.md`
- **WSTG-ATHN-06** → Testing for Browser Cache Weaknesses — `04-authentication.md`
- **WSTG-ATHN-07** → Testing for Weak Password Policy — `04-authentication.md`
- **WSTG-ATHN-08** → Testing for Weak Security Question Answer — `04-authentication.md`
- **WSTG-ATHN-09** → Testing for Weak Password Change/Reset — `04-authentication.md`
- **WSTG-ATHN-10** → Testing for Weaker Authentication in Alternative Channel — `04-authentication.md`

### WSTG-ATHZ (Authorization)
- **WSTG-ATHZ-01** → Testing Directory Traversal File Include — `05-authorization.md`
- **WSTG-ATHZ-02** → Testing for Bypassing Authorization Schema — `05-authorization.md`
- **WSTG-ATHZ-03** → Testing for Privilege Escalation — `05-authorization.md`
- **WSTG-ATHZ-04** → Testing for Insecure Direct Object References (IDOR) — `05-authorization.md`

### WSTG-SESS (Session Management)
- **WSTG-SESS-01** → Testing for Session Management Schema — `06-session-management.md`
- **WSTG-SESS-02** → Testing for Cookies Attributes — `06-session-management.md`
- **WSTG-SESS-03** → Testing for Session Fixation — `06-session-management.md`
- **WSTG-SESS-04** → Testing for Exposed Session Variables — `06-session-management.md`
- **WSTG-SESS-05** → Testing for Cross Site Request Forgery (CSRF) — `06-session-management.md`

---

## 🏷️ Search by Vulnerability Type

### Access Control & Authorization
- IDOR (Insecure Direct Object References) → WSTG-ATHZ-04
- Privilege Escalation → WSTG-ATHZ-03
- Authorization Bypass → WSTG-ATHZ-02
- Path Traversal / Directory Traversal → WSTG-ATHZ-01

### Authentication & Credentials
- Default Credentials → WSTG-ATHN-02
- Weak Password Policy → WSTG-ATHN-07
- Password Reset Flaws → WSTG-ATHN-09
- Authentication Bypass → WSTG-ATHN-04
- Weak Security Questions → WSTG-ATHN-08
- Account Enumeration → WSTG-IDNT-04
- Weak Lockout Mechanism → WSTG-ATHN-03
- Remember Me Token Weakness → WSTG-ATHN-05

### Session Management
- Session Fixation → WSTG-SESS-03
- Session Token Prediction → WSTG-SESS-01
- Cookie Attributes (HttpOnly, Secure, SameSite) → WSTG-SESS-02
- CSRF (Cross-Site Request Forgery) → WSTG-SESS-05
- Exposed Session Variables → WSTG-SESS-04

### Security Headers & Configuration
- Content Security Policy (CSP) → WSTG-CONF-12 ⭐
- HSTS (HTTP Strict Transport Security) → WSTG-CONF-07
- CORS Misconfiguration → WSTG-CONF-08
- Missing Security Headers → WSTG-CONF-02
- HTTP Methods Enabled → WSTG-CONF-06

### File & Backup Exposure
- Backup File Disclosure → WSTG-CONF-04
- Source Code Exposure (.git, .env) → WSTG-CONF-04
- Sensitive File Extensions → WSTG-CONF-03
- File Permission Misconfiguration → WSTG-CONF-09

### Information Disclosure
- Server Fingerprinting → WSTG-INFO-02
- Metafile Enumeration → WSTG-INFO-03
- Source Code Leakage → WSTG-INFO-05
- Debug Endpoint Exposure → WSTG-CONF-02
- Error Message Information → WSTG-CONF-02

### Network & Infrastructure
- Network Segmentation Flaws → WSTG-CONF-01
- Open Ports/Services → WSTG-CONF-01
- Cloud Storage Misconfiguration → WSTG-CONF-11

---

## 🎯 Search by Keyword

| Keyword | Tests | File |
|---------|-------|------|
| **CSP, XSS Prevention** | WSTG-CONF-12 | `02-configuration-deployment.md` |
| **IDOR, Object References** | WSTG-ATHZ-04 | `05-authorization.md` |
| **CORS, Cross-Domain** | WSTG-CONF-08 | `02-configuration-deployment.md` |
| **CSRF, Cross-Site Request** | WSTG-SESS-05 | `06-session-management.md` |
| **Session, Cookie, Token** | WSTG-SESS-01/02/03 | `06-session-management.md` |
| **Password Reset, Recovery** | WSTG-ATHN-09 | `04-authentication.md` |
| **Authentication Bypass** | WSTG-ATHN-04 | `04-authentication.md` |
| **Default Credentials** | WSTG-ATHN-02 | `04-authentication.md` |
| **Privilege Escalation** | WSTG-ATHZ-03 | `05-authorization.md` |
| **Path Traversal, Directory** | WSTG-ATHZ-01 | `05-authorization.md` |
| **Fingerprinting, Banner Grab** | WSTG-INFO-02 | `01-information-gathering.md` |
| **Backup Files, .env, .git** | WSTG-CONF-04 | `02-configuration-deployment.md` |
| **Cloud Storage, S3, Azure** | WSTG-CONF-11 | `02-configuration-deployment.md` |
| **HTTP Methods, PUT, DELETE** | WSTG-CONF-06 | `02-configuration-deployment.md` |
| **HSTS, Downgrade Attack** | WSTG-CONF-07 | `02-configuration-deployment.md` |
| **API, Endpoint Discovery** | WSTG-INFO-06 | `01-information-gathering.md` |
| **Recon, OSINT, Enumeration** | WSTG-INFO-* | `01-information-gathering.md` |

---

## 📖 How to Use This Repository

### For Quick Lookup:
1. **Know the test ID?** → Use "Search by Test ID" section above
2. **Know the vulnerability type?** → Use "Search by Vulnerability Type" section
3. **Have a keyword in mind?** → Use "Search by Keyword" section or `grep -r "keyword" .`

### For Full Testing:
1. Pick a category file (e.g., `02-configuration-deployment.md`)
2. Read each test description
3. Copy and adapt the example commands for your target
4. Document findings with severity ratings

### For Engagement Workflow:
Follow the order:
1. **Information Gathering** (WSTG-INFO) — Passive recon
2. **Configuration & Deployment** (WSTG-CONF) — Server/platform config weaknesses
3. **Identity Management** (WSTG-IDNT) — User/role enumeration
4. **Authentication** (WSTG-ATHN) — Login mechanism flaws
5. **Authorization** (WSTG-ATHZ) — Access control bypasses
6. **Session Management** (WSTG-SESS) — Session hijacking, token prediction

---

## ⭐ Highlighted Tests

### WSTG-CONF-12: Content Security Policy (CSP) Testing
**File:** `02-configuration-deployment.md`

CSP is one of the strongest XSS mitigations. This test covers:
- Detecting missing/weak CSP headers
- CSP bypass techniques (nonce reuse, unsafe-inline, unsafe-eval)
- Testing policy effectiveness
- Common misconfigurations
- Using Google's CSP Evaluator tool

---

## 📝 Original Expanded Playbook

The full `WSTG-Playbook-Expanded.md` contains all tests in a single file. These organized files break it down by category for easier searching and navigation.

---

## 🔗 External Resources

- **OWASP WSTG:** https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CWE/CAPEC:** https://cwe.mitre.org/
- **Google CSP Evaluator:** https://csp-evaluator.withgoogle.com/
- **HSTS Preload List:** https://hstspreload.org/

---

## 📊 Coverage

- **Total WSTG Tests Covered:** 40+ tests
- **Categories:** 6 (Information Gathering, Configuration & Deployment, Identity, Authentication, Authorization, Session Management)
- **Vulnerability Types:** 30+ unique vulnerability categories
- **Tools Referenced:** 50+ security testing tools

---

## 🚀 Quick Commands

### Search for a test by ID:
```bash
grep -r "WSTG-CONF-12" .
```

### Search by keyword:
```bash
grep -r "CSP\|nonce\|unsafe-inline" .
```

### Find all vulnerable outputs:
```bash
grep -r "Expected Output (Vulnerable)" .
```

### List all test IDs:
```bash
grep -E "^### WSTG-" . -r | cut -d' ' -f2
```

---

## 📄 Notes

- All tests include example commands for curl/bash
- Expected outputs show what vulnerability looks like
- Tools listed are industry-standard open-source options
- Adapt all commands for your specific target
- Always get written authorization before testing

---

**Last Updated:** 2026-03-18  
**WSTG Version:** v4.2
