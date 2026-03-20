# Mobile App Security Penetration Testing
**Index & Navigation** | Last Updated: 2026-03-20

---

## 📑 Quick Navigation

This playbook has been restructured into three focused guides for clarity and speed during engagements.

### 🚀 Tools Quick Start

**[MobSF Quick Reference](./mobsf-quick-reference.md)** - Fast static analysis triage
- Automated scanning for hardcoded secrets, permissions, weak crypto
- GUI navigation guide (Android & iOS)
- Time-boxed approach for quick findings
- Start here before manual testing

### Choose Your Path:

**🔧 [Common & Shared](./mobile-app-security-common.md)**
- Prerequisites & environment setup
- Network traffic interception (Burp)
- Authentication & session management
- Cryptography assessment
- Reporting templates & vulnerability classification

**🤖 [Android-Specific](./mobile-app-security-android.md)**
- APK decompilation (APKTool, dex2jar, CFR)
- AndroidManifest.xml analysis
- Static code analysis (smali, Java decompilation)
- Frida instrumentation & hooking
- SQLite & SharedPreferences extraction
- Android-specific vulnerabilities (Intent injection, Content Provider abuse)
- Root detection bypass

**🍎 [iOS-Specific](./mobile-app-security-ios.md)**
- IPA extraction & binary analysis
- Hopper disassembly & strings extraction
- class-dump for header extraction
- Frida hooking on jailbroken devices
- Keychain & NSUserDefaults analysis
- iOS-specific vulnerabilities (URL schemes, pasteboard monitoring)
- Jailbreak detection bypass

---

## 🚀 Quick Start (by OS)

### Testing Android App?
1. Read **[Common](mobile-app-security-common.md)** — Phase 0 (Prerequisites)
2. Use **[Android](mobile-app-security-android.md)** — Full workflow
3. Reference **[Common](mobile-app-security-common.md)** for Burp setup, auth testing, reporting

### Testing iOS App?
1. Read **[Common](mobile-app-security-common.md)** — Phase 0 (Prerequisites)
2. Use **[iOS](mobile-app-security-ios.md)** — Full workflow
3. Reference **[Common](mobile-app-security-common.md)** for Burp setup, auth testing, reporting

### Testing Both?
- Start with **[Common](mobile-app-security-common.md)** once
- Then follow **[Android](mobile-app-security-android.md)** and **[iOS](mobile-app-security-ios.md)** separately

---

## 📊 Coverage

| Area | Common | Android | iOS |
|------|--------|---------|-----|
| **Setup & Tools** | ✓ | ✓ | ✓ |
| **App Collection** | — | ✓ | ✓ |
| **Static Analysis** | — | ✓ (APK/smali) | ✓ (binary/class-dump) |
| **Dynamic Analysis** | — | ✓ (Frida) | ✓ (Frida) |
| **Network (Burp)** | ✓ | — | — |
| **Storage Security** | — | ✓ (SharedPrefs/SQLite) | ✓ (Keychain/NSUserDefaults) |
| **Authentication** | ✓ | — | — |
| **Cryptography** | ✓ | ✓ (weak algorithms) | ✓ (weak algorithms) |
| **Platform Vulns** | — | ✓ (Intent, Content Provider) | ✓ (URL schemes, ATS) |
| **Exploitation** | — | ✓ (priv esc) | ✓ (jailbreak bypass) |
| **Reporting** | ✓ | — | — |

---

## 🛠 Tools Quick Reference

**Cross-Platform:**
- Frida (runtime instrumentation)
- Burp Suite (proxy)
- MobSF (scanning)

**Android:**
- APKTool, dex2jar, CFR (decompilation)
- adb (device interaction)
- Android Studio (debugging)

**iOS:**
- Hopper Disassembler (binary analysis)
- class-dump (headers)
- Xcode (debugging)
- LLDB (command-line debugger)

---

## 📋 Typical Engagement Flow

```
1. Authorization & Scope (All: Common → Phase 0)
2. App Collection (Android or iOS specific)
3. Static Analysis (Android or iOS specific)
4. Network Setup (Common)
5. Burp Interception (Common)
6. Dynamic Analysis (Android or iOS specific)
7. Storage/Crypto Testing (Android or iOS specific)
8. Platform-Specific Vulns (Android or iOS specific)
9. Exploitation & Escalation (Android or iOS specific)
10. Reporting (Common)
```

---

## 📚 Files in This Directory

- **mobile-app-security-common.md** — Shared methodology & tools
- **mobile-app-security-android.md** — Android pentesting guide
- **mobile-app-security-ios.md** — iOS pentesting guide
- **mobile-app-security-playbook.md** — This file (navigation index)

---

**Version:** 2.0 (Split structure for clarity)
**Last Updated:** 2026-03-20

For specific sections, use `grep` or `Ctrl+F` within each file:
```bash
grep -i "burp\|ssl\|frida" mobile-app-security-common.md
grep -i "decompilation\|apktool" mobile-app-security-android.md
grep -i "hopper\|class-dump" mobile-app-security-ios.md
```
