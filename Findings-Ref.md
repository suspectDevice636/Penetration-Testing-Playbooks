# Findings Reference - Vulnerability Library

Reference library of common web application, network, and infrastructure vulnerabilities discovered during pentesting engagements. Use this as a template for reporting findings.

## Severity Reference
- **0-4 = Low**
- **5-7 = Medium**
- **8+ = High/Critical**

---

## Web Application Findings

### Clickjacking / UI Redress Attack (Medium)
**DREAD Score:** 6  
**CWE:** CWE-693

**Description:**
The application does not implement clickjacking protection headers (X-Frame-Options), allowing the application to be framed within a malicious webpage. An attacker can overlay legitimate application elements with hidden iframes to trick authenticated users into performing unintended actions.

**Impact:**
- Unauthorized action execution on behalf of authenticated users
- Credential theft via fake login overlays
- Transaction manipulation (payments, transfers, etc.)
- Privilege escalation through admin action abuse

**Proof of Concept:**
```javascript
var iframe = document.createElement('iframe');
iframe.src = 'https://target.com/admin-page';
iframe.style.opacity = '0.8';
iframe.style.position = 'fixed';
iframe.style.top = '0';
iframe.style.left = '0';
iframe.style.width = '100%';
iframe.style.height = '100%';
iframe.style.zIndex = '9999';
iframe.style.border = '3px solid red';
document.body.appendChild(iframe);
```

**Remediation:**
Set X-Frame-Options header to DENY or SAMEORIGIN:
```
X-Frame-Options: DENY
# or
X-Frame-Options: SAMEORIGIN
```

Also implement Content-Security-Policy:
```
Content-Security-Policy: frame-ancestors 'none';
```

**References:**
- [OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)
- [CWE-693](https://cwe.mitre.org/data/definitions/693.html)

---

### HTTP TRACE Method Enabled (Medium)
**DREAD Score:** 5  
**CWE:** CWE-200

**Description:**
The HTTP TRACE method is enabled on the web server, allowing attackers to use HTTP request echoing to inspect request headers and body content. This can expose authentication tokens and sensitive data.

**Impact:**
- Session token/cookie exposure
- HTTP header inspection by attackers
- Potential XSS via reflected headers

**Remediation:**
Disable TRACE method at web server configuration level.

---

### Insecure SSL/TLS Configurations (Low)
**DREAD Score:** 3  
**CWE:** CWE-327

**Description:**
Outdated TLS versions or weak cipher suites are supported. Current best practice requires TLS 1.2 minimum (TLS 1.3 preferred).

**Remediation:**
- Enforce TLS 1.2 or higher
- Disable SSLv3, TLSv1.0, TLSv1.1
- Remove weak ciphers (RC4, DES, MD5)

---

### Information Disclosure - Verbose Error Messages (Low)
**DREAD Score:** 2  
**CWE:** CWE-209

**Description:**
The application returns detailed error messages exposing internal architecture, database queries, file paths, and framework versions.

**Impact:**
- Information gathering for targeted attacks
- Technology stack disclosure

**Remediation:**
Implement generic error messages in production. Log detailed errors server-side only.

---

### Missing HSTS Header (Low)
**DREAD Score:** 3  
**CWE:** CWE-319

**Description:**
HTTP Strict-Transport-Security (HSTS) header is not set, allowing potential downgrade attacks to HTTP.

**Remediation:**
Add HSTS header:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

### Content Security Policy - Insecure Configuration (Medium)
**DREAD Score:** 5  
**CWE:** CWE-693

**Description:**
CSP header is missing or misconfigured with unsafe directives (unsafe-inline, unsafe-eval), reducing XSS protection effectiveness.

**Remediation:**
Implement strict CSP:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';
```

---

## Network/Infrastructure Findings

### SSH Terrapin Vulnerability CVE-2023-48795 (Medium)
**DREAD Score:** 5  
**CWE:** CWE-347

**Description:**
SSH protocol vulnerability allowing prefix truncation attacks. Attackers can remove extension negotiation from the SSH handshake without detection.

**Impact:**
- Disabling security extensions
- Rollback attacks on SSH protocol

**Remediation:**
Update OpenSSH to version 9.6 or later.

---

**Last Updated:** 2026-03-16
