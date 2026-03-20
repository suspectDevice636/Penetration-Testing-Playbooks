# MobSF Quick Reference - Static Analysis Guide
**Fast triage for Android & iOS apps** | Last Updated: 2026-03-20

---

## What is MobSF?

Free, open-source static analyzer. Automatically scans APK/IPA for:
- Hardcoded secrets (API keys, passwords)
- Dangerous permissions
- Weak crypto
- Insecure storage
- Exported components (Android)
- Network security issues

**Docker (recommended):**
```bash
docker run -it -p 8000:8000 -v $(pwd):/home/mobsf/uploads opensecurity/mobile-security-framework
# Then navigate to http://localhost:8000
```

---

## Quick Triage (Time-Constrained)

**Goal:** Find high-value findings in 5-10 minutes.

### 1. Upload & Scan (Auto)
Upload APK or IPA → MobSF scans automatically (2-5 min)

### 2. Check Dashboard Summary
After scan completes, you'll see:
- **Risk: Critical/High/Medium/Low**
- **Key findings count**
- **Permission summary**

### 3. Navigate to Key Sections (In Order)

**Priority 1 - Hardcoded Secrets (2 min) ⭐⭐⭐**
```
Android:
  Click: "Manifest Analysis" → Scroll to "Hardcoded Secrets"
  Or: "Code Analysis" → Search for "secrets"
  
iOS:
  Click: "Binary Analysis" → Look for "Hardcoded Strings"
  Or: "Code Analysis" → Search for API keys/passwords

Search for:
  - api_key, apikey, API_KEY
  - password, passwd, pwd
  - bearer, token, auth_token
  - secret, private_key
  - firebase, aws_access, sk_test_, AKIA
```
**Action:** If found, test immediately (API endpoints, auth)

---

**Priority 2 - Dangerous Permissions (1 min) ⭐⭐**

**Android - Click "Manifest Analysis"**
```
Look for these flags:
✓ READ_CONTACTS - Can access all contacts
✓ READ_CALENDAR - Can access calendar
✓ RECORD_AUDIO - Can record conversations
✓ CAMERA - Can record video
✓ ACCESS_FINE_LOCATION - Real-time location tracking
✓ SEND_SMS - Can send SMS
✓ READ_SMS - Can intercept SMS codes (2FA bypass)
✓ WRITE_EXTERNAL_STORAGE - Can write files to device
```

**iOS - Click "Info.plist Analysis"**
```
Look for these keys:
✓ NSHealthShareUsageDescription - Health data access
✓ NSContactsUsageDescription - Contacts access
✓ NSCameraUsageDescription - Camera access
✓ NSLocationWhenInUseUsageDescription - Location
✓ NSMicrophoneUsageDescription - Microphone
✓ NSPhotoLibraryUsageDescription - Photos
```
**Action:** These tell you what data to hunt for in storage/network.

---

**Priority 3 - Network & Certificate Security (2 min) ⭐⭐**

**Android - Click "Manifest Analysis"**
```
Look for:
✓ android:usesCleartextTraffic="true" - HTTP allowed
✓ Network Security Config issues
```

**iOS - Click "Info.plist Analysis"**
```
Look for:
✓ NSAppTransportSecurity
✓ NSAllowsArbitraryLoads - HTTP allowed
✓ NSAllowsArbitraryLoadsInWebContent - Browser HTTP allowed
```

**Both - Click "Certificate Analysis"**
```
Look for:
✓ No certificate pinning
✓ Weak TLS versions
✓ Self-signed certificates
```
**Action:** If cleartext HTTP or no pinning → Set up Burp proxy.

---

**Priority 4 - Exported Components (1 min) - Android Only ⭐**

**Click "Manifest Analysis"**
```
Look for:
✓ Exported Activities (exported="true")
✓ Exported Services (exported="true")
✓ Exported Broadcast Receivers (exported="true")

Especially flag if no <permission> or <permission-group> tag
```
**Action:** Test exploitation with:
```bash
adb shell am start -a [ACTION] -n com.example.app/.ActivityName
```

---

**Priority 5 - Weak Crypto (Skim - 1 min)**

**Click "Code Analysis" or "Security Issues"**
```
Flag any use of:
✓ DES, 3DES, RC4 - Too weak
✓ MD5, SHA1 - Collision vuln
✓ ECB mode - Deterministic
✓ Hardcoded encryption keys
✓ Random() instead of SecureRandom
```
**Action:** Note for reporting, usually not immediately exploitable.

---

## GUI Navigation (Both Platforms)

**Main Tabs/Sections:**
```
Report (Overview/Summary)
  ├── Manifest Analysis (Android)
  ├── Info.plist Analysis (iOS)
  ├── Code Analysis
  ├── Binary Analysis
  ├── Security Issues
  ├── Certificate Analysis
  └── Strings/Hardcoded Data
```

**If You're Lost:**
1. Use browser Find (Ctrl+F) on the report page
2. Search for: "secret", "api", "key", "password", "bearer"
3. Search for: "hardcoded", "exported", "cleartext"
4. Search for: "DES", "MD5", "ECB"

---

## Typical Findings Explained

### Hardcoded API Key Found
```
Finding: "API key detected: sk_live_123456abcdef"
Action:
  1. Test if valid (try API calls)
  2. Check scope (what can it access?)
  3. Report as Critical if valid + high-privileged endpoint
```

### App Allows Cleartext Traffic (HTTP)
```
Finding: "android:usesCleartextTraffic="true""
Action:
  1. Set up Burp proxy on device
  2. Intercept HTTP traffic
  3. Look for sensitive data in plaintext
  4. Report as High
```

### Exported Unprotected Activity
```
Finding: "Activity AdminPanel exported without permission"
Action:
  1. Test: adb shell am start -a com.example.ADMIN
  2. If it launches without auth → Critical (auth bypass)
  3. Report as Critical/High
```

### Dangerous Permission Requested
```
Finding: "READ_CONTACTS permission requested"
Action:
  1. Check if app actually needs it
  2. Test if data is encrypted in storage
  3. Determine if it's properly gated (permission checks)
  4. Report as Medium/Low depending on sensitivity + implementation
```

### Weak Crypto Detected
```
Finding: "DES encryption used in com.example.Crypto"
Action:
  1. Note for reporting
  2. Check if it's actually used for sensitive data
  3. If hardcoded key found → High
  4. If just weak algorithm → Medium
```

---

## Time-Boxed Approach (30 min Pentest)

**5 min:** Upload to MobSF, start scan (while waiting, read the overview)

**5 min:** Triage findings
- Hardcoded secrets? → YES: Test now
- Cleartext HTTP? → YES: Set up Burp now
- Dangerous perms? → Note for later
- Exported components? → Test with adb

**10 min:** Quick validation tests
- Test hardcoded credentials
- Test exported components
- Set up Burp if needed

**10 min:** Manual analysis
- Focus on what MobSF didn't catch (logic flaws, API logic)
- Use Burp to test APIs
- Check storage for sensitive data

**Remaining time:** Deeper analysis or reporting

---

## What MobSF Misses

**MobSF is good at:**
- ✓ Finding hardcoded secrets
- ✓ Detecting obvious code patterns
- ✓ Checking manifest/plist
- ✓ Flagging weak crypto

**MobSF misses:**
- ❌ Logic flaws (e.g., improper session validation)
- ❌ API endpoint vulnerabilities
- ❌ Runtime behavior (e.g., what happens when you trigger functions)
- ❌ Authentication bypass flows
- ❌ Race conditions
- ❌ Complex data exfiltration paths

**Always follow up with:**
- Manual code review (focus on what MobSF flagged + logic)
- Frida hooking (runtime behavior)
- Burp proxy (API testing)
- Storage extraction (actual data)

---

## Real Example: iOS App

```
MobSF Scan Results:

1. Hardcoded Secrets Found:
   - "api_key": "sk_test_abc123"
   - "firebase_url": "https://myapp.firebaseio.com"

2. NSAppTransportSecurity Analysis:
   - NSAllowsArbitraryLoads: true
   - Allows cleartext HTTP

3. Entitlements:
   - NSLocationWhenInUseUsageDescription: YES
   - NSCameraUsageDescription: YES

4. Crypto Issues:
   - MD5 usage detected in UserValidator.h
   - No AES encryption found

TRIAGE PLAN:
  Priority 1: Test API key (sk_test_abc123)
    → Check what Firebase endpoints it accesses
    → See if it has write permissions (data exfil)
  
  Priority 2: Set up Burp
    → App allows HTTP, intercept cleartext traffic
  
  Priority 3: Extract location data
    → App has fine location permission
    → Check if stored locally or uploaded
  
  Priority 4: Test MD5 usage
    → Usually not exploitable, but note for reporting
```

---

## Checklist for Report

After MobSF triage, confirm:
- [ ] All hardcoded secrets found and tested
- [ ] All dangerous permissions noted
- [ ] Network security (cleartext, pinning) documented
- [ ] Exported components tested (Android)
- [ ] Weak crypto flagged for reporting
- [ ] Manual code review of flagged sections
- [ ] Burp proxy results compiled
- [ ] Storage analysis completed
- [ ] Findings deduplicated and prioritized

---

## Tools & Related Guides

**In This Folder:**
- [./mobile-app-security-playbook.md](./mobile-app-security-playbook.md) - Full methodology
- [./mobile-app-security-android.md](./mobile-app-security-android.md) - Deep Android testing
- [./mobile-app-security-ios.md](./mobile-app-security-ios.md) - Deep iOS testing
- [./mobile-app-security-common.md](./mobile-app-security-common.md) - Burp, auth testing, reporting

**Next Steps After MobSF:**
1. **Frida** - Runtime hooking & bypass (in platform guides)
2. **Burp Suite** - API & network testing
3. **Manual storage extraction** - Pull actual data
4. **Code review** - Deep dive flagged sections

---

**Version:** 1.0
**Last Updated:** 2026-03-20
