# Mobile App Security Penetration Testing Playbook
**iOS & Android Security Assessment Methodology** | Last Updated: 2026-03-08

---

## Overview

This playbook provides comprehensive methodology for penetration testing iOS and Android mobile applications. It covers static analysis, dynamic analysis, network testing, platform-specific vulnerabilities, and data exfiltration techniques.

**Key Focus Areas:**
1. App Installation & Decompilation
2. Static Code Analysis
3. Dynamic Analysis & Runtime Testing
4. Network Traffic Interception
5. Storage Security (Local, Shared)
6. Authentication & Session Management
7. Cryptography & Encryption
8. Platform-Specific Vulnerabilities
9. Jailbreak/Root Detection Bypass
10. Data Exfiltration & Forensics

**Testing Phases:**
1. Reconnaissance & App Collection
2. Static Analysis
3. Dynamic Analysis Setup
4. Network Traffic Analysis
5. Storage & Credential Assessment
6. Authentication Testing
7. Cryptography Assessment
8. Platform-Specific Testing
9. Exploitation & Data Exfiltration
10. Reporting

---

## Phase 0: Prerequisites & Setup

### 0.1 Testing Environment Setup
**Objective:** Configure tools and test devices

**Tools Needed:**

**Android:**
- Android Studio (emulator)
- Android SDK & Platform Tools
- APKTool
- dex2jar
- CFR (Java decompiler)
- Frida
- Burp Suite
- MobSF (Mobile Security Framework)
- Logcat analyzer
- ADB (Android Debug Bridge)
- RootCloak (if testing on rooted device)
- Xposed Framework (if testing on rooted device)

**iOS:**
- Xcode (simulator)
- iOS Device (jailbroken recommended for testing)
- Frida
- Burp Suite
- MobSF
- Hopper Disassembler
- Needle
- Cycript
- Console app
- Class-dump
- Strings utility

**Installation:**
```bash
# Android tools
brew install android-platform-tools
pip install frida-tools
pip install mobsf

# iOS tools (macOS only)
# Xcode from App Store
pip install frida-tools
pip install needle

# General tools
pip install requests paramiko
```

### 0.2 Emulator/Device Configuration
**Objective:** Set up test environment with disabled protections

**Android Emulator:**
```bash
# Create emulator
android create avd --name test-avd --target android-30

# Launch with specific options
emulator -avd test-avd -no-snapshot -noaudio -no-window
```

**Android Physical Device:**
- Enable USB Debugging (Developer Options)
- Install test app via APK
- Root device (optional but helpful)
- Disable app signature verification (if possible)

**iOS Simulator:**
```bash
# List available simulators
xcrun simctl list

# Launch simulator
xcrun simctl boot "iPhone 13"

# Install IPA
xcrun simctl install booted app.ipa
```

**iOS Physical Device:**
- Jailbreak (Checkra1n, unc0ver, etc.)
- Install Cydia and useful tools
- Disable code signature verification
- Install debugging tools

### 0.3 Authorization & Scope
**Checklist:**
- [ ] Written authorization to test app
- [ ] Scope defined (features, accounts to test)
- [ ] API endpoints in scope identified
- [ ] Third-party services identified
- [ ] Rules of engagement agreed
- [ ] Data handling procedures documented
- [ ] Test device considerations noted
- [ ] Escalation contacts identified

---

## Phase 1: App Collection & Initial Assessment

### 1.1 App Acquisition
**Objective:** Obtain app binary for analysis

**Android:**
```bash
# Download from Google Play (if authorized)
# Use APK downloader tools or Google Play direct download

# Extract from device
adb shell pm list packages | grep -i target
adb shell pm path com.example.app
adb pull /data/app/com.example.app

# Or using:
python3 -m pip install gplaydl
gplaydl com.example.app
```

**iOS:**
```bash
# Extract from device (requires jailbreak)
ssh root@device
find /var/containers/Bundle/Application -name "*.app"
tar -czf app.tar.gz /path/to/app

# Or use Frida to dump
frida-ps -U
frida-server (run on device)
```

### 1.2 App Information Gathering
**Objective:** Extract metadata from app

**Android:**
```bash
# Extract AndroidManifest.xml
unzip app.apk AndroidManifest.xml

# Parse manifest
aapt dump badging app.apk

# Extract app name, version, permissions
aapt dump permissions app.apk
aapt dump uses-permission app.apk

# Get certificate info
keytool -printcert -jarfile app.apk
```

**iOS:**
```bash
# Extract Info.plist
unzip -p app.ipa Payload/App.app/Info.plist | plutil -convert xml1 -

# Extract bundle identifier
mdls app.ipa | grep com.example

# Check entitlements
ldid -e app.ipa
```

### 1.3 Vulnerability Scanning (Automated)
**Objective:** Quick automated vulnerability detection

**Using MobSF:**
```bash
# Run MobSF on APK
mobsf --file app.apk --scan

# Run MobSF on IPA
mobsf --file app.ipa --scan

# Extract report
# Open MobSF web UI for detailed report
```

---

## Phase 2: Static Code Analysis

### 2.1 Android Decompilation
**Objective:** Convert APK to readable source code

**APK Decompilation:**
```bash
# Extract APK
unzip app.apk -d app-extracted

# Convert DEX to JAR
d2j-dex2jar app-extracted/classes.dex -o classes.jar

# Decompile to Java
cfr classes.jar --outputdir src/

# Or use APKTool for resources
apktool d app.apk -o app-decompiled

# View decompiled code
ls -la app-decompiled/
cat app-decompiled/AndroidManifest.xml
```

**APKTool Analysis:**
```bash
# Decompile with APKTool
apktool d app.apk

# Analyze manifest
cat app/AndroidManifest.xml

# View resources
ls -la app/res/

# Analyze smali code
cat app/smali/com/example/MainActivity.smali
```

### 2.2 iOS Decompilation
**Objective:** Extract and disassemble iOS binary

**Binary Extraction:**
```bash
# Extract Mach-O binary from IPA
unzip -l app.ipa  # List contents
unzip app.ipa -d app-extracted
cp app-extracted/Payload/App.app/App ./app-binary

# Get binary information
file app-binary
otool -L app-binary  # Dependencies
```

**Binary Analysis:**
```bash
# Disassemble using Hopper
# Open app-binary in Hopper Disassembler

# Use strings to find hardcoded values
strings app-binary | grep -i "password\|api\|secret"

# Check imports
nm app-binary | grep -i "security\|crypto"

# Use objc-dump to get Objective-C classes
class-dump -H app-binary -o headers/

# View headers
cat headers/ViewController.h
```

### 2.3 Permission & Capability Analysis
**Objective:** Identify sensitive permissions requested

**Android Permissions:**
```bash
# Extract permissions from manifest
aapt dump permissions app.apk

# Dangerous permissions to look for:
# - android.permission.WRITE_EXTERNAL_STORAGE
# - android.permission.READ_PHONE_STATE
# - android.permission.ACCESS_FINE_LOCATION
# - android.permission.CAMERA
# - android.permission.RECORD_AUDIO
# - android.permission.READ_CONTACTS
# - android.permission.READ_CALL_LOG

# Check if permissions are properly gated
apktool d app.apk
grep -r "permission" app/AndroidManifest.xml
grep -r "READ_EXTERNAL_STORAGE\|CAMERA\|LOCATION" app/smali/
```

**iOS Capabilities & Entitlements:**
```bash
# Extract entitlements
ldid -e app-binary | plutil -convert xml1 -

# Common dangerous entitlements:
# - com.apple.security.get-task-allow (debugging)
# - com.apple.security.files.user-selected.read-write
# - com.apple.keychain-access-groups
# - com.apple.application-identifier

# Check Info.plist for permissions
cat headers/Info.plist | grep -i "camera\|location\|microphone\|contacts"
```

### 2.4 Hardcoded Secrets & API Keys
**Objective:** Search for exposed credentials

```bash
# Android
apktool d app.apk
grep -r "AKIA\|api_key\|secret\|password" app/smali/
grep -r "http://" app/smali/ | grep -v "https://"

strings app-extracted/classes.dex | grep -i "api\|key\|secret"

# iOS
strings app-binary | grep -i "api\|key\|secret\|password"
grep -r "NSString" headers/*.h | grep -i "api\|key"

# Search in resources
find app-extracted/res -type f -exec grep -l "api\|secret\|key" {} \;
```

### 2.5 Insecure Coding Patterns
**Objective:** Identify common vulnerabilities in code

**Android Vulnerabilities:**
```
1. SQL Injection
   - db.rawQuery(String)  (use parameterized queries)
   - ContentProvider without proper access control
   
2. Path Traversal
   - File("/sdcard/" + userInput)
   - openFileInput(userInput)
   
3. Command Injection
   - Runtime.getRuntime().exec()
   - ProcessBuilder with unsanitized input
   
4. Hardcoded Secrets
   - API keys in source
   - Passwords in smali
   
5. Logging Sensitive Data
   - Log.d/e/i with passwords
   - Toast with sensitive data
   
6. Insecure Deserialization
   - ObjectInputStream.readObject()
   - Parcelable without signature validation
```

**Search for Patterns:**
```bash
# SQL Injection
apktool d app.apk
grep -r "rawQuery\|execSQL" app/smali/

# Command Injection
grep -r "Runtime.getRuntime\|ProcessBuilder" app/smali/

# Logging
grep -r "Log\.d\|Log\.e" app/smali/ | grep -v "//"

# Hardcoded strings
strings app-extracted/classes.dex | grep -E "password|key|secret|bearer|auth" | head -20
```

**iOS Vulnerabilities:**
```
1. Insecure Network (HTTP)
   - [NSURL URLWithString:@"http://..."]
   
2. Insecure Logging
   - NSLog()@"%@", password
   
3. Hardcoded Secrets
   - NSString literals with keys
   
4. Broken Cryptography
   - DES, MD5, SHA1 (weak)
   
5. Unsafe Deserialization
   - NSKeyedUnarchiver without validation
   
6. Weak Random
   - rand() instead of SecRandomCopyBytes()
```

---

## Phase 3: Dynamic Analysis & Runtime Testing

### 3.1 Frida Instrumentation Setup
**Objective:** Hook and modify app at runtime

**Frida Installation:**
```bash
# Install Frida server on device
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify
frida-ps -U
```

**iOS Frida Setup:**
```bash
# Install on jailbroken device
ssh root@device
apt-get install frida  # Via Cydia

# Or compile and install manually
frida-server (start on device)
```

### 3.2 Frida Hooking & Method Interception
**Objective:** Intercept and modify function calls

**Example Hooks:**

```javascript
// Android - Hook SharedPreferences (credential storage)
Java.perform(function() {
  var SharedPreferences = Java.use("android.content.SharedPreferences");
  var getString = SharedPreferences.getString.overload("java.lang.String", "java.lang.String");
  
  getString.implementation = function(key, defaultValue) {
    var result = this.getString(key, defaultValue);
    console.log("[SharedPreferences] " + key + " = " + result);
    return result;
  };
});

// Android - Hook SQLite queries
Java.perform(function() {
  var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
  SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava/lang/String;").implementation = function(sql, args) {
    console.log("[SQL] " + sql);
    return this.rawQuery(sql, args);
  };
});

// Android - Hook HttpURLConnection
Java.perform(function() {
  var HttpURLConnection = Java.use("java.net.HttpURLConnection");
  HttpURLConnection.setRequestProperty.overload("java.lang.String", "java.lang.String").implementation = function(key, value) {
    console.log("[Header] " + key + ": " + value);
    return this.setRequestProperty(key, value);
  };
});

// iOS - Hook HTTP requests
Interceptor.attach(Module.findExportByName(null, "CFHTTPMessageCopySerializedMessage"), {
  onEnter: function(args) {
    console.log("[HTTPMessage] Creating request");
  },
  onLeave: function(retval) {
    console.log("[HTTPMessage] " + Memory.readCString(retval));
  }
});
```

**Running Hooks:**
```bash
# Save hook to hook.js
# Run against app
frida -U -f com.example.app -l hook.js --no-pause

# Or attach to running app
frida -U com.example.app -l hook.js
```

### 3.3 Bypassing Jailbreak/Root Detection
**Objective:** Disable anti-tampering mechanisms

**Android Root Detection Bypass:**
```javascript
// Method 1: Hook detection class
Java.perform(function() {
  var RootDetection = Java.use("com.example.security.RootDetection");
  RootDetection.isDeviceRooted.implementation = function() {
    console.log("[+] isDeviceRooted called - returning false");
    return false;
  };
});

// Method 2: Hook Runtime.exec
Java.perform(function() {
  var Runtime = Java.use("java.lang.Runtime");
  Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
    if (cmd.includes("su")) {
      console.log("[+] Blocking su execution");
      throw new Error("Command blocked");
    }
    return this.exec(cmd);
  };
});

// Method 3: Hook Build properties
Java.perform(function() {
  var Build = Java.use("android.os.Build");
  var BuildVersion = Java.use("android.os.Build$VERSION");
  
  // Mock build properties
  Build.TAGS.value = "release-keys";  // Instead of "test-keys"
  Build.DEVICE.value = "generic";
});
```

**iOS Jailbreak Detection Bypass:**
```javascript
// Hook jailbreak detection function
Interceptor.attach(Module.findExportByName(null, "access"), {
  onEnter: function(args) {
    var path = Memory.readCString(args[0]);
    if (path.includes("Cydia") || path.includes("ssh") || path.includes("su")) {
      console.log("[+] Blocking jailbreak detection path: " + path);
      args[0] = ptr("0");  // Block access
    }
  }
});

// Hook stat
Interceptor.attach(Module.findExportByName(null, "stat"), {
  onEnter: function(args) {
    var path = Memory.readCString(args[0]);
    console.log("[stat] " + path);
  }
});
```

### 3.4 Debugger Attachment & Code Execution
**Objective:** Attach debugger for step-by-step analysis

**Android Debugging:**
```bash
# Enable debugging on app (AndroidManifest.xml)
# android:debuggable="true"

# Use Android Studio debugger
adb forward tcp:5005 tcp:5005
# Connect debugger to localhost:5005

# Or use jdwp-shellifier for RCE
python jdwp-shellifier.py --host localhost --port 5005 --cmd "shell command"
```

**iOS Debugging:**
```bash
# Xcode debugging
xcode-select --install
open Xcode project
# Build & Run with debugger attached

# LLDB (command line)
lldb -n AppName
(lldb) continue
(lldb) breakpoint set -f ViewController.m -l 10
(lldb) po (method call)  # Print object
```

---

## Phase 4: Network Traffic Analysis

### 4.1 Burp Suite Proxy Setup
**Objective:** Intercept and analyze app traffic

**Android Configuration:**
```bash
# Install Burp CA certificate
# 1. Export from Burp Suite
# 2. Install to device: Settings → Security → Install Certificate

# Configure proxy
adb shell settings put global http_proxy <burp-ip>:<port>

# Or use iptables
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <burp-ip>:8080

# Verify traffic in Burp
# Intercept requests, analyze, modify, forward
```

**iOS Configuration (Stock & Jailbroken):**

*Works on both stock iOS and jailbroken devices*

**Step 1: Install Burp CA Certificate**
```bash
# On iPhone, open Safari
# Navigate to: http://<burp-ip>:8080/
# Download the Burp CA certificate
# Install when prompted (will redirect to profiles/device management)

# Then verify/trust the certificate:
# 
# iOS 18.x (18.3.2+):
#   Settings → General → VPN & Device Management
#   Find "PortSwigger" certificate
#   Tap it and verify it shows as "Trusted"
#
# iOS 17.x and earlier:
#   Settings → General → About → Certificate Trust Settings
#   Find "PortSwigger CA" and toggle trust ON
```

**Step 2: Configure WiFi Proxy (Manual)**
```bash
# On iPhone:
# Settings → WiFi → [Select Your Network]
# Tap the (i) icon next to network name
# Scroll down to "HTTP Proxy"
# Select "Manual"
# Enter:
#   Server: <burp-ip>  (e.g., 192.168.1.100 if Burp on Kali)
#   Port: 8080
# Tap "Save"

# Verify: Traffic should now appear in Burp
```

**Network Setup Example (Kali VM + iPhone):**
```
Kali VM IP: 192.168.1.50
iPhone WiFi: Connected to same network (192.168.1.x)
iPhone Proxy Setting: 192.168.1.50:8080
```

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

**Android Bypass:**
```javascript
// Hook certificate validation
Java.perform(function() {
  var SSLContext = Java.use("javax.net.ssl.SSLContext");
  var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  
  var insecureTrustManager = Java.use("java.lang.Object");
  insecureTrustManager.$new = function() {
    return Java.use("javax.net.ssl.X509TrustManager").$new(
      function checkClientTrusted() {},
      function checkServerTrusted() {},
      function getAcceptedIssuers() { return null; }
    );
  };
  
  SSLContext.getInstance.overload("java.lang.String").implementation = function(provider) {
    var sslContext = this.getInstance(provider);
    try {
      sslContext.init(null, [insecureTrustManager.$new()], null);
    } catch(e) {}
    return sslContext;
  };
});
```

**iOS Bypass:**
```javascript
// Hook SSL validation
var ssl_verify = Module.findExportByName(null, "SSL_CTX_set_verify");
Interceptor.replace(ssl_verify, new NativeCallback(function(ctx, mode) {
  console.log("[+] SSL_CTX_set_verify called - bypassing");
  return 0;  // SSL_VERIFY_NONE
}, 'int', ['pointer', 'int']));
```

---

## Phase 5: Storage Security

### 5.1 Android Local Storage Assessment
**Objective:** Identify insecure data storage

**SharedPreferences:**
```bash
# Locate SharedPreferences
adb shell find /data/data/com.example.app -name "*.xml"

# Pull files
adb pull /data/data/com.example.app/shared_prefs/

# Analyze
cat shared_prefs/preferences.xml
```

**SQLite Databases:**
```bash
# Locate databases
adb shell find /data/data/com.example.app -name "*.db"

# Pull database
adb pull /data/data/com.example.app/databases/app.db

# Query database
sqlite3 app.db
sqlite> .tables
sqlite> SELECT * FROM users;
```

**File Storage:**
```bash
# Check app directory
adb shell ls -la /data/data/com.example.app/

# Check external storage
adb shell ls -la /sdcard/Android/data/com.example.app/

# Pull all files
adb pull /data/data/com.example.app/ ./app-data/

# Analyze
find app-data -type f -exec file {} \;
strings app-data/files/* | grep -i password
```

### 5.2 iOS Local Storage Assessment
**Objective:** Identify insecure data storage on iOS

**File System:**
```bash
# SSH into jailbroken device
ssh root@device

# App bundle location
ls /var/containers/Bundle/Application/*/

# App data directory
ls /var/mobile/Containers/Data/Application/*/

# Documents, Library, Caches
ls -la /var/mobile/Containers/Data/Application/[UUID]/Documents/
ls -la /var/mobile/Containers/Data/Application/[UUID]/Library/
ls -la /var/mobile/Containers/Data/Application/[UUID]/tmp/
```

**Keychain (Credential Storage):**
```bash
# Pull keychain data
security dump-keychain -a
security find-generic-password -a

# Or use Frida to hook keychain
// Hook keychain access
Interceptor.attach(Module.findExportByName(null, "SecItemCopyMatching"), {
  onEnter: function(args) {
    console.log("[Keychain] Item requested");
  }
});
```

**SQLite Databases:**
```bash
# Locate databases
find /var/mobile/Containers/Data/Application/ -name "*.db" -o -name "*.sqlite"

# Copy for analysis
cp /var/mobile/Containers/Data/Application/[UUID]/Library/database.db ./

# Query
sqlite3 database.db
sqlite> SELECT * FROM users;
```

### 5.3 Sensitive Data Exposure
**Objective:** Identify unencrypted sensitive data

**Checklist:**
- [ ] Plaintext passwords in storage
- [ ] Unencrypted auth tokens
- [ ] Unencrypted PII
- [ ] Unencrypted financial data
- [ ] Unencrypted health data
- [ ] Logs containing sensitive info
- [ ] Cache files with sensitive data
- [ ] Backup files accessible

**Testing:**
```bash
# Search for sensitive patterns
find app-data -type f -exec strings {} \; | grep -E "password|credit_card|ssn|bearer|token"

# Check file permissions
ls -la app-data/shared_prefs/
# Look for world-readable files (644 or 666)

# Check encryption
strings app-data/databases/app.db | grep -E "CREATE TABLE|password"
```

---

## Phase 6: Authentication & Session Management

### 6.1 Authentication Mechanism Analysis
**Objective:** Test authentication strength

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
**Objective:** Analyze JSON Web Tokens for weaknesses

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

**Testing:**
```javascript
// Hook session creation
Java.perform(function() {
  var SessionManager = Java.use("com.example.SessionManager");
  SessionManager.createSession.implementation = function() {
    var session = this.createSession();
    console.log("[Session] Created: " + session);
    return session;
  };
});

// Monitor session usage
Java.perform(function() {
  var SessionManager = Java.use("com.example.SessionManager");
  SessionManager.getSession.implementation = function() {
    var session = this.getSession();
    console.log("[Session] Accessed: " + session);
    return session;
  };
});
```

---

## Phase 7: Cryptography Assessment

### 7.1 Cryptographic Implementation Review
**Objective:** Identify weak cryptography

**Android Vulnerabilities:**
```
1. Weak algorithms (DES, MD5, SHA1, RC4)
2. ECB mode (deterministic)
3. Hardcoded keys
4. Weak random number generation (Random instead of SecureRandom)
5. No authentication (bare encryption)
```

**Search for Issues:**
```bash
apktool d app.apk
grep -r "DES\|MD5\|SHA1\|RC4\|ECB\|Random(" app/smali/ | grep -v SecureRandom

strings app-extracted/classes.dex | grep -i "cipher\|key\|encrypt"
```

**iOS Vulnerabilities:**
```
1. CCCrypt with weak algorithms
2. CommonCrypto with MD5/SHA1
3. Hardcoded encryption keys
4. Weak random (arc4random instead of arc4random_buf)
```

### 7.2 Key Management Testing
**Objective:** Verify secure key storage

**Checklist:**
- [ ] Keys not hardcoded
- [ ] Keys encrypted with KMS/Keystore
- [ ] Key rotation implemented
- [ ] Key access restricted
- [ ] No key leakage in logs
- [ ] Key destroyed on logout/uninstall

**Android Keystore Testing:**
```bash
# Check if using Android Keystore
apktool d app.apk
grep -r "KeyStore\|KeyProperties\|KeyGenerator" app/smali/

# Hook KeyStore access
adb shell cat /proc/[pid]/maps | grep keystore
```

**iOS Keychain Testing:**
```bash
# Check keychain usage
strings app-binary | grep -i "keychain\|security"

# Hook Keychain
security find-generic-password -a | grep app_name
```

---

## Phase 8: Platform-Specific Vulnerabilities

### 8.1 Android-Specific Issues
**Objective:** Test Android-specific attack vectors

**Intent Injection:**
```bash
# Detect exported components
apktool d app.apk
grep -r "exported\|intent-filter" app/AndroidManifest.xml

# Exploit via adb
adb shell am start -a com.example.LAUNCH_UNPROTECTED
adb shell am broadcast -a com.example.MALICIOUS_ACTION
adb shell am service com.example/.UnprotectedService
```

**Content Provider Exploitation:**
```bash
# Enumerate content providers
apktool d app.apk
grep -r "ContentProvider\|content://" app/AndroidManifest.xml

# Query content provider
adb shell content query --uri content://com.example.app.provider/users

# Exploit path traversal
adb shell content query --uri "content://com.example.app.provider/../../etc/passwd"
```

**Broadcast Receiver Abuse:**
```bash
# Identify receivers
apktool d app.apk
grep -r "BroadcastReceiver" app/AndroidManifest.xml

# Send broadcast
adb shell am broadcast -a com.example.SENSITIVE_ACTION --es data "malicious"
```

### 8.2 iOS-Specific Issues
**Objective:** Test iOS-specific vulnerabilities

**URL Scheme Exploitation:**
```bash
# Extract URL schemes from Info.plist
strings app-binary | grep "://"

# Invoke schemes
xcrun simctl openurl booted "com.example.app://user/123"

# Hook URL handling
Interceptor.attach(Module.findExportByName(null, "application:openURL:"), {
  onEnter: function(args) {
    console.log("[URL] " + Memory.readCString(args[1]));
  }
});
```

**Pasteboard (Clipboard) Access:**
```bash
# Monitor clipboard
// Hook UIPasteboard
var UIPasteboard = ObjC.classes.UIPasteboard;
var generalPasteboard = UIPasteboard.generalPasteboard();
console.log("[Pasteboard] " + generalPasteboard.$ownMembers());

// Hook clipboard change
Interceptor.attach(Module.findExportByName(null, "UIPasteboardChangedNotification"), {
  onEnter: function() {
    console.log("[Clipboard] Changed");
  }
});
```

**App Transport Security (ATS) Bypass:**
```bash
# Check ATS configuration in Info.plist
strings app-binary | grep -i "transport\|security"

# Hook SSL
Interceptor.attach(Module.findExportByName(null, "SSL_CTX_set_verify"), {
  onEnter: function(args) {
    args[1] = ptr(0);  // Disable verification
  }
});
```

---

## Phase 9: Data Exfiltration & Forensics

### 9.1 Data Extraction
**Objective:** Extract and analyze app data

**Android Data Pull:**
```bash
# Full app data
adb pull /data/data/com.example.app/ ./extracted-data/

# Database dump
adb shell sqlite3 /data/data/com.example.app/databases/app.db ".dump" > database.sql

# Preferences dump
adb shell cat /data/data/com.example.app/shared_prefs/preferences.xml > prefs.xml

# Logcat logs
adb logcat > app.log

# Pull uploaded files
adb pull /sdcard/DCIM/ ./camera-data/
```

**iOS Data Pull:**
```bash
# SSH to device
ssh root@device

# Pull app data
scp -r root@device:/var/mobile/Containers/Data/Application/[UUID] ./ios-data/

# Dump databases
scp root@device:/var/mobile/Containers/Data/Application/[UUID]/Library/database.db ./

# Pull logs
scp root@device:/var/log/system.log ./
```

### 9.2 Memory Forensics
**Objective:** Extract sensitive data from memory

**Android Memory Analysis:**
```bash
# Dump memory
adb shell dumpsys meminfo > meminfo.txt

# Capture heap dump
adb shell am dumpheap com.example.app /data/local/tmp/heap.dump

# Analyze with HPROF
hprof-conv heap.dump heap.hprof
jhat -J-Xmx2g heap.hprof

# Search for credentials in memory
strings /proc/[pid]/cmdline
cat /proc/[pid]/maps  # Memory layout
```

**iOS Memory Analysis:**
```bash
# Dump memory with LLDB
lldb -n AppName
(lldb) memory read 0x1000 0x2000

# Or use Frida to search memory
Interceptor.attach(Module.findExportByName(null, "malloc"), {
  onEnter: function(args) {
    console.log("[malloc] " + args[0]);
  }
});
```

### 9.3 Log Analysis
**Objective:** Extract sensitive data from logs

**Android Logcat:**
```bash
# View logs
adb logcat

# Filter by app
adb logcat com.example.app:*

# Search for sensitive data
adb logcat | grep -i "password\|token\|credit\|secret"

# Save for analysis
adb logcat > logcat.log

# Analyze
grep -E "password|credential|secret|key" logcat.log
```

**iOS Console:**
```bash
# View console
deviceconsole  # Using device-console tool

# Or via Xcode
Xcode → Window → Devices → Select Device → View Device Logs

# Search logs
scp root@device:/var/log/* ./logs/
grep -r "password\|token" ./logs/
```

---

## Phase 10: Exploitation & Privilege Escalation

### 10.1 Android Privilege Escalation
**Objective:** Escalate privileges

**Dangerous Permissions:**
```
WRITE_EXTERNAL_STORAGE → Write any file
READ_CONTACTS → Steal contacts
READ_CALENDAR → Steal calendar data
RECORD_AUDIO → Monitor conversations
ACCESS_FINE_LOCATION → Track user
CAMERA → Record video
SEND_SMS → Send messages
```

**Exploitation Example (Write Arbitrary File):**
```java
// If app has WRITE_EXTERNAL_STORAGE
// Can write to /sdcard/ or app-specific directory

// Create backdoor APK
// Drop to /sdcard/
// Trick user into installing

// Or use:
adb push backdoor.apk /sdcard/
adb shell pm install /sdcard/backdoor.apk
```

### 10.2 iOS Privilege Escalation
**Objective:** Escalate privileges on jailbroken device

**Available Exploits (if unpatched):**
```
- kernel_task port leak → Full kernel control
- CVE exploitation via Frida
- App sandbox breakout
- System app modification
```

**Testing:**
```javascript
// Attempt to gain kernel port
// (requires specific vulnerability)
var task_for_pid = Module.findExportByName(null, "task_for_pid");
Interceptor.attach(task_for_pid, {
  onEnter: function(args) {
    console.log("[task_for_pid] PID: " + args[1]);
    args[1] = 0;  // kernel_task
  }
});
```

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
- SharedPreferences: [Status]
- SQLite: [Status]
- Keychain: [Status]
- Files: [Status]

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
- APKTool
- dex2jar
- CFR
- class-dump
- Hopper Disassembler
- Frida
- MobSF

### Interception & Debugging
- Burp Suite
- Wireshark
- Fiddler
- LLDB
- Android Studio Debugger

### Exploitation
- Metasploit (Android modules)
- Custom Python scripts

### Utilities
- Android SDK
- Xcode
- adb
- ssh
- sqlite3
- strings
- nm

---

**Last Updated:** 2026-03-08
**Version:** 1.0
