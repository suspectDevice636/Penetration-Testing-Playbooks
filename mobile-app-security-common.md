# Mobile App Security Penetration Testing - Common & Shared
**Shared Methodology, Tools & Reporting** | Last Updated: 2026-03-20

---

## Overview

This document covers shared methodology, prerequisites, tools, and reporting for iOS and Android penetration testing. 

**Platform-specific guides:**
- **[Android](mobile-app-security-android.md)** - APK decompilation, static/dynamic analysis, Android-specific vulns
- **[iOS](mobile-app-security-ios.md)** - Binary analysis, class-dump, iOS-specific vulns

**Key Focus Areas (Both Platforms):**
1. App Installation & Collection
2. Network Traffic Interception
3. Authentication & Session Management
4. Cryptography & Encryption
5. Data Exfiltration & Forensics

**Testing Phases:**
1. Reconnaissance & App Collection
2. Network Traffic Analysis (Burp)
3. Storage & Credential Assessment
4. Authentication Testing
5. Cryptography Assessment
6. Exploitation & Data Exfiltration
7. Reporting

---

## Phase 0: Prerequisites & Setup

### 0.1 Testing Environment - General Tools
**Objective:** Configure shared tools and test devices

**Cross-Platform Tools:**
- Frida (instrumentation)
- Burp Suite (proxy/interception)
- MobSF (vulnerability scanning)
- Wireshark (packet analysis)
- Python 3 (scripting)

**Installation:**
```bash
# General tools
pip install frida-tools
pip install mobsf
pip install requests paramiko

# Burp Suite
# Download from: https://portswigger.net/burp/communitydownload
# Or: brew install burp-suite-community (macOS)
```

### 0.2 Authorization & Scope
**Critical Checklist:**
- [ ] Written authorization to test app
- [ ] Scope defined (features, accounts to test)
- [ ] API endpoints in scope identified
- [ ] Third-party services identified
- [ ] Rules of engagement agreed
- [ ] Data handling procedures documented
- [ ] Test device considerations noted
- [ ] Escalation contacts identified
- [ ] Testing environment is isolated

**Rules:**
- Only test on devices/accounts you control or have written permission for
- Do not access production user data outside scope
- Do not share findings with unauthorized parties
- Document all testing activities
- Follow responsible disclosure timeline

---

## Phase 1: App Collection & Initial Assessment

### 1.1 App Acquisition
**Objective:** Obtain app binary for analysis

**Android:**
```bash
# Extract from device
adb shell pm list packages | grep -i target
adb shell pm path com.example.app
adb pull /data/app/com.example.app

# Or download from Play Store (if authorized)
python3 -m pip install gplaydl
gplaydl com.example.app
```

**iOS:**
```bash
# Extract from device (requires jailbreak)
ssh root@device
find /var/containers/Bundle/Application -name "*.app"
tar -czf app.tar.gz /path/to/app
```

See **[Android](mobile-app-security-android.md)** or **[iOS](mobile-app-security-ios.md)** guides for full decompilation steps.

---

## Phase 4: Network Traffic Analysis

### 4.1 Burp Suite Proxy Setup
**Objective:** Intercept and analyze app traffic

This works on both Android and iOS. Follow your platform's specific setup:
- **[Android - Burp Setup](mobile-app-security-android.md#41-burp-suite-proxy-setup)**
- **[iOS - Burp Setup](mobile-app-security-ios.md#41-burp-suite-proxy-setup)**

### 4.2 Analyzing API Requests
**Objective:** Identify API endpoints and test for vulnerabilities

**Checklist:**
- [ ] Map all API endpoints
- [ ] Identify authentication mechanisms
- [ ] Review request/response format (JSON, XML)
- [ ] Check for sensitive data transmission
- [ ] Verify TLS/HTTPS usage
- [ ] Test parameter tampering
- [ ] Check for weak authentication
- [ ] Identify API version
- [ ] Test rate limiting
- [ ] Check CORS headers

**Testing:**
```
GET /api/v1/user/profile
Request Headers:
  Authorization: Bearer <token>
  X-Custom-Header: value

Response:
  {
    "id": 123,
    "username": "user",
    "email": "user@example.com",
    "phone": "555-1234"
  }

Testing:
- Modify Authorization token
- Remove Authorization header
- Change user ID to other user
- Inject SQL in parameters
- Try XXE in XML requests
- Check for XXE, CSRF, etc.
```

### 4.3 Certificate Pinning Bypass
**Objective:** Bypass certificate pinning to intercept HTTPS

See your platform guide:
- **[Android - Certificate Pinning Bypass](mobile-app-security-android.md#43-certificate-pinning-bypass)**
- **[iOS - Certificate Pinning Bypass](mobile-app-security-ios.md#43-certificate-pinning-bypass)**

---

## Phase 6: Authentication & Session Management

### 6.1 Authentication Mechanism Analysis
**Objective:** Test authentication strength (applies to both platforms)

**Checklist:**
- [ ] How credentials transmitted (HTTPS)
- [ ] How credentials stored (encrypted?)
- [ ] Weak password policy
- [ ] Biometric authentication security
- [ ] Multi-factor authentication
- [ ] Account enumeration possible
- [ ] Brute force protection
- [ ] Session timeout
- [ ] Logout effectiveness

**Testing:**
```bash
# Intercept login request in Burp
POST /api/login
{
  "username": "user",
  "password": "pass123"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}

# Test weak credentials
# Test account enumeration
# Test brute force
# Analyze token format (JWT?)
# Check token expiration
```

### 6.2 JWT Token Analysis
**Objective:** Analyze JSON Web Tokens for weaknesses (applies to both platforms)

```bash
# Decode JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | cut -d. -f1-2 | base64 -d

# Results in:
# {"alg":"HS256","typ":"JWT"}
# {"sub":"user123","exp":1234567890}

# Common JWT weaknesses:
# 1. None algorithm (no signature verification)
# 2. Weak secret (brute forceable)
# 3. Hardcoded secret in code
# 4. Missing exp claim
# 5. Signed with HS256 instead of RS256

# Test JWT manipulation
# Modify payload, remove signature
```

### 6.3 Session Management Testing
**Objective:** Test session handling

**Checklist:**
- [ ] Session tokens/cookies generated securely
- [ ] Tokens have sufficient entropy
- [ ] Session fixation protection
- [ ] Concurrent session handling
- [ ] Cross-site request forgery (CSRF) protection
- [ ] Secure flag on cookies
- [ ] HttpOnly flag on cookies
- [ ] SameSite attribute set
- [ ] Logout invalidates session
- [ ] Timeout implemented
- [ ] Device binding

---

## Phase 7: Cryptography Assessment

### 7.1 Cryptographic Implementation Review
**Objective:** Identify weak cryptography (applies to both platforms)

**General Vulnerabilities:**
```
1. Weak algorithms (DES, MD5, SHA1, RC4)
2. ECB mode (deterministic)
3. Hardcoded keys
4. Weak random number generation
5. No authentication (bare encryption)
```

See your platform guide for platform-specific search patterns:
- **[Android - Crypto Review](mobile-app-security-android.md#71-cryptographic-implementation-review)**
- **[iOS - Crypto Review](mobile-app-security-ios.md#71-cryptographic-implementation-review)**

### 7.2 Key Management Testing
**Objective:** Verify secure key storage

**Checklist:**
- [ ] Keys not hardcoded
- [ ] Keys encrypted with KMS/Keystore
- [ ] Key rotation implemented
- [ ] Key access restricted
- [ ] No key leakage in logs
- [ ] Key destroyed on logout/uninstall

---

## Phase 9: Data Exfiltration & Forensics

### 9.1 Data Extraction
**Objective:** Extract and analyze app data

See your platform guide:
- **[Android - Data Extraction](mobile-app-security-android.md#91-data-extraction)**
- **[iOS - Data Extraction](mobile-app-security-ios.md#91-data-extraction)**

### 9.2 Memory Forensics
**Objective:** Extract sensitive data from memory

See your platform guide:
- **[Android - Memory Forensics](mobile-app-security-android.md#92-memory-forensics)**
- **[iOS - Memory Forensics](mobile-app-security-ios.md#92-memory-forensics)**

### 9.3 Log Analysis
**Objective:** Extract sensitive data from logs

See your platform guide:
- **[Android - Logcat Analysis](mobile-app-security-android.md#93-log-analysis)**
- **[iOS - Console Analysis](mobile-app-security-ios.md#93-log-analysis)**

---

## Phase 11: Reporting

### Vulnerability Classification
```
CRITICAL:
- SQL injection with data access
- Authentication bypass
- RCE via deserialization
- Arbitrary file write/read
- Credential theft
- Root/Jailbreak bypass

HIGH:
- Hardcoded credentials
- Insecure storage (passwords)
- Weak encryption
- SSRF via API
- Privilege escalation

MEDIUM:
- Insecure logging
- Weak session management
- Missing CSRF protection
- Path traversal

LOW:
- Information disclosure
- Weak password policy
- Missing security headers
```

### Report Template
```
# Mobile App Security Assessment Report

## Executive Summary
[Overview of findings and risk]

## Scope
- App: [Name] [Version]
- Platform: Android / iOS
- Testing Type: Black box / White box
- Dates: [Date range]

## Key Findings

### Critical Findings
1. [Finding]
   - Impact: [Consequence]
   - PoC: [Reproduction steps]
   - Fix: [Remediation]

### High Findings
[Same format]

### Medium Findings
[Same format]

### Low Findings
[Same format]

## Detailed Analysis

### 1. Storage Security
- Shared Storage: [Status]
- Database Security: [Status]
- Credential Storage: [Status]
- File Permissions: [Status]

### 2. Network Security
- HTTPS enforcement: [Status]
- Certificate pinning: [Status]
- API authentication: [Status]

### 3. Cryptography
- Algorithms: [Assessment]
- Key management: [Assessment]

### 4. Authentication
- Mechanism: [Type]
- Strength: [Assessment]
- MFA: [Present/Absent]

### 5. Data Exfiltration Risk
- Sensitive data exposure: [Risk level]
- Credential theft: [Risk level]

## Recommendations
[Priority-ordered fixes]

## Appendix
- Tools used
- Testing methodology
- Evidence (screenshots)
```

---

## Tools Arsenal

### Decompilation & Analysis
- APKTool (Android)
- dex2jar (Android)
- CFR (Android/Java)
- class-dump (iOS)
- Hopper Disassembler (iOS)
- Frida (Both)
- MobSF (Both)

### Interception & Debugging
- Burp Suite (Both)
- Wireshark (Both)
- Fiddler (Both)
- LLDB (iOS)
- Android Studio Debugger (Android)

### Exploitation
- Metasploit (Android modules)
- Custom Python scripts

### Utilities
- Android SDK & adb
- Xcode
- ssh
- sqlite3
- strings / nm
- Python 3

---

**Last Updated:** 2026-03-20
**Version:** 2.0 (split into common + platform-specific)
