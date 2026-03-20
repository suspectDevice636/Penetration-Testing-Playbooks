# Mobile App Security Penetration Testing - iOS
**iOS-Specific Assessment & Exploitation** | Last Updated: 2026-03-20

---

## Overview

This guide covers iOS-specific pentesting methodology. For shared setup, tools, and reporting, see **[Common Guide](./mobile-app-security-common.md)**.

**Quick Links:**
- Storage Security (Section 5.2)
- Static Analysis (Section 2.2)
- Dynamic Analysis (Section 3)
- iOS-Specific Vulns (Section 8.2)
- Exploitation (Section 10.2)

---

## Phase 0: iOS Prerequisites & Setup

### 0.1 iOS Testing Tools
**Objective:** Configure iOS-specific tools (macOS required)

**iOS Tools:**
- Xcode (IDE + simulator)
- iOS Device (jailbroken recommended)
- Frida (instrumentation)
- Hopper Disassembler (binary analysis)
- class-dump (extract headers)
- Needle (iOS testing framework)
- MobSF (vulnerability scanning)
- LLDB (debugger)
- Cycript (JavaScript REPL)
- ldid (entitlement editing)

**Installation:**
```bash
# Xcode (from App Store or CLI)
xcode-select --install

# Homebrew tools
brew install frida
brew install hopper
brew install ldid
brew install cycript
brew install lldb  # Usually included with Xcode

# Python tools
pip install frida-tools
pip install mobsf
pip install requests

# From source
# Hopper: https://www.hopperapp.com/download.html
# Needle: https://github.com/mwrlabs/needle
```

### 0.2 iOS Simulator & Device Configuration
**Objective:** Set up test environment

**iOS Simulator Setup:**
```bash
# List available simulators
xcrun simctl list

# Create simulator
xcrun simctl create "Test Device" com.apple.CoreSimulator.SimDeviceType.iPhone-14 com.apple.CoreSimulator.SimRuntime.iOS-16-2

# Boot simulator
xcrun simctl boot "Test Device"

# Install IPA
xcrun simctl install booted app.ipa

# Open app
xcrun simctl openurl booted "com.example.app://"
```

**iOS Physical Device (Jailbroken):**

*Jailbreaking enables unrestricted testing:*
- Checkra1n (most reliable)
- unc0ver (alternative)
- Palera1n (newer devices)

**After Jailbreaking:**
```bash
# SSH into device
ssh root@<device-ip>
# Default password: alpine

# Install useful tools via Cydia
# - Frida
# - OpenSSH (if not installed)
# - Class Dump
# - Cycript
# - MobileSubstrate (Substrate framework for hooking)

# Install specific tools
apt-get update
apt-get install frida openssh
```

**Enable SSH Access:**
```bash
# On device:
# Settings → Wi-Fi → Network details → Note IP
# Or use:
idevice_id -l  # List connected devices
ideviceinfo -k WiFiAddress  # Get IP

# SSH from computer
ssh root@<ip>  # Password: alpine (default)
```

---

## Phase 1: iOS App Collection

### 1.1 iOS App Acquisition
**Objective:** Obtain app binary for analysis

**From Device (Jailbroken):**
```bash
ssh root@device

# Find app bundle
find /var/containers/Bundle/Application -name "*.app" -type d

# Or
find /Applications -name "*.app" -type d

# Locate app directory
ls -la /var/containers/Bundle/Application/*/Payload/

# Copy binary
APPID="com.example.app"
APPPATH=$(find /var/containers -name "$APPID.app" -type d)
cp -r "$APPPATH" /tmp/
tar -czf app.tar.gz /tmp/$APPID.app

# Transfer to computer
scp -r root@device:/var/containers/.../app.ipa ./
```

**From Simulator:**
```bash
# Find simulator app
xcrun simctl get_app_container booted com.example.app

# Or locate in:
~/Library/Developer/CoreSimulator/Devices/[UUID]/data/Containers/Bundle/Application/

# Copy IPA
cp -r app.app ./
zip -r app.ipa Payload/
```

---

## Phase 2: iOS Static Code Analysis

### 2.1 iOS Binary Extraction & Analysis
**Objective:** Extract and disassemble iOS binary

**IPA Structure:**
```
app.ipa (just a ZIP)
├── Payload/
│   └── App.app/
│       ├── App (main binary - Mach-O)
│       ├── Info.plist (app configuration)
│       ├── _CodeSignature/ (code signature)
│       ├── Frameworks/ (embedded frameworks)
│       ├── Assets.car (resources)
│       └── ...
└── SwiftSupport/ (Swift libraries)
```

**Extract Binary:**
```bash
# IPA is a ZIP file
unzip app.ipa

# Find main binary
ls -la Payload/App.app/

# Main binary is usually named same as app
# e.g., App, MyApp, instagram, etc.

# Copy binary
cp Payload/App.app/App ./app-binary
```

**Binary Information:**
```bash
# Identify binary type
file app-binary
# Output: Mach-O 64-bit executable arm64

# Get architecture
lipo -info app-binary

# Strip for size (not needed for analysis)
# strip app-binary
```

### 2.2 iOS Binary Disassembly
**Objective:** Reverse engineer iOS binary

**Using Hopper Disassembler (GUI):**
```bash
# Open in Hopper
open -a Hopper\ Disassembler app-binary

# In Hopper:
1. Click "Strings" tab to find hardcoded values
2. Click "Disassemble" to view assembly
3. Search for function names or strings
4. Cross-reference call chains
```

**Using strings (CLI):**
```bash
# Extract all strings from binary
strings app-binary | less

# Search for interesting strings
strings app-binary | grep -i "password\|api\|secret\|endpoint"
strings app-binary | grep "https://"
strings app-binary | grep "Bearer\|Authorization"

# Search for hardcoded IPs
strings app-binary | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

**Using nm (symbol table):**
```bash
# List all exported symbols
nm -gm app-binary | head -20

# Search for sensitive functions
nm -gm app-binary | grep -i "crypto\|encrypt\|decrypt\|password\|auth"

# Look for Objective-C classes
nm -gm app-binary | grep "_OBJC_CLASS"
```

**Using otool (Mach-O tool):**
```bash
# List dependencies
otool -L app-binary

# Check for weak security settings
otool -l app-binary | grep -i "pie\|aslr\|stack"

# View load commands
otool -h app-binary
```

### 2.3 Objective-C Headers Extraction
**Objective:** Extract class/method information

**Using class-dump:**
```bash
# Extract headers
class-dump -H -o headers/ app-binary

# View extracted headers
ls -la headers/
cat headers/ViewController.h

# Search for interesting methods
grep -r "password\|auth\|encrypt\|crypto" headers/ | head -20
grep -r "init\|shared" headers/ | grep -i "manager\|service"
```

**Example Extracted Header:**
```objective-c
@interface LoginViewController : UIViewController
{
    UITextField *usernameField;
    UITextField *passwordField;
}

- (void)viewDidLoad;
- (void)authenticateUser:(id)arg1;
- (void)saveCredentials:(NSString *)username password:(NSString *)password;
- (BOOL)isValidEmail:(NSString *)email;

@end
```

**Using Cycript (Runtime Inspection):**
```bash
# On device, connect with SSH
cycript -p App

# Inspect runtime objects
# List all classes
ObjectiveC.classes

# Get instance of class
[NSString new]

# Call methods
[UIApplication sharedApplication]

# Dump instance variables
[appInstance yd]

# Modify values at runtime
var loginVC = [LoginViewController new]
loginVC.username = @"admin"
```

### 2.4 Info.plist Analysis
**Objective:** Extract app metadata and configuration

**Extract Info.plist:**
```bash
# From IPA
unzip -p app.ipa Payload/App.app/Info.plist > Info.plist

# View as XML (macOS)
plutil -p Info.plist
plutil -convert xml1 Info.plist
cat Info.plist

# Or use strings
strings app-binary | grep "NSAppTransportSecurity\|NSRequiresCertificateTransparency"
```

**Key Fields to Check:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <!-- Allows unencrypted HTTP -->
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- VULNERABLE -->
  </dict>
  
  <!-- URL schemes app responds to -->
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>myapp://</string>  <!-- Exploitable -->
        <string>instagram://</string>
      </array>
    </dict>
  </array>
  
  <!-- Permissions app requests -->
  <key>NSCameraUsageDescription</key>
  <string>App needs camera access</string>
  
  <key>NSLocationWhenInUseUsageDescription</key>
  <string>App needs location</string>
  
  <!-- Debugging flags -->
  <key>NSDictionary</key>
  <dict>
    <key>DEBUG</key>
    <true/>  <!-- Debug mode enabled -->
  </dict>
  
</dict>
</plist>
```

**Security Checklist:**
- [ ] NSAppTransportSecurity allows HTTP
- [ ] Certificate pinning implemented
- [ ] Debug mode enabled
- [ ] URL schemes exposed
- [ ] Permissions reasonable
- [ ] Encryption keys in plist

### 2.5 Hardcoded Secrets & API Keys
**Objective:** Search for exposed credentials

```bash
# Search binary
strings app-binary | grep -E "AKIA|api_key|secret|password|bearer|token" | head -20

# Search Info.plist
strings app-binary | grep -E "\.plist|.strings|.json"

# Search for base64-encoded data
strings app-binary | grep -E "^[A-Za-z0-9/+]{20,}==$" | head -10

# Search for known patterns
strings app-binary | grep -i "aws\|azure\|firebase\|apikey"

# Decompile and search
class-dump -H -o headers/ app-binary
grep -r "password\|api\|secret\|token" headers/

# Binary search with xxd (hex)
xxd app-binary | grep -i "pass\|key\|secret"
```

### 2.6 Insecure Coding Patterns (iOS)
**Objective:** Identify common vulnerabilities

**Common iOS Vulnerabilities:**

```
1. Insecure Network (HTTP)
   Pattern: [NSURL URLWithString:@"http://..."]
   Safe: Always use https://
   
2. Insecure Logging
   Pattern: NSLog(@"Password: %@", password)
   Safe: Don't log sensitive data
   
3. Hardcoded Secrets
   Pattern: NSString *apiKey = @"sk_test_12345..."
   Safe: Load from secure configuration
   
4. Broken Cryptography
   Pattern: CCCrypt with DES, MD5, SHA1
   Safe: Use AES-256, SHA-256, bcrypt
   
5. Unsafe Deserialization
   Pattern: [NSKeyedUnarchiver unarchiveObjectWithData:data]
   Safe: Use Codable, validate input
   
6. Weak Random
   Pattern: arc4random() or random()
   Safe: Use arc4random_buf() or SecRandomCopyBytes()
   
7. Information Disclosure
   Pattern: UIAlertView with sensitive data
   Safe: Log errors without user data
   
8. Insecure Storage
   Pattern: Plaintext in files or NSUserDefaults
   Safe: Use Keychain
   
9. Jailbreak/Debug Detection Bypass
   Pattern: Weak jailbreak checks
   Safe: Use multiple detection methods
```

**Search for Patterns in Headers:**
```bash
# HTTP connections
grep -r "http://" headers/

# Insecure storage
grep -r "NSUserDefaults\|Document\|Cache" headers/

# Weak crypto
grep -r "MD5\|SHA1\|DES\|Random" headers/

# Logging
grep -r "NSLog\|print" headers/

# Unsafe deserialization
grep -r "unarchiveObject\|NSKeyedUnarchiver" headers/
```

---

## Phase 3: iOS Dynamic Analysis & Runtime Testing

### 3.1 Frida Server Setup (iOS)
**Objective:** Install Frida for runtime instrumentation

**Install Frida on Jailbroken Device:**
```bash
# SSH into device
ssh root@<device-ip>

# Install via Cydia
# Cydia → Search → Frida → Install

# Or manually:
apt-get install frida

# Start Frida server
frida-server &

# Verify from macOS
frida-ps -U  # -U: USB device
frida-ps -R  # -R: Remote (over network)
```

**Install on Simulator:**
```bash
# Frida server for simulator
wget https://github.com/frida/frida/releases/download/[VERSION]/frida-server-[VERSION]-ios-arm64.xz
xz -d frida-server-[VERSION]-ios-arm64.xz

# Copy to simulator
/Applications/Xcode.app/.../ios-deploy-frida-server simulator
```

### 3.2 Frida Hooking & Method Interception
**Objective:** Intercept and modify function calls at runtime

**Hook Objective-C Methods:**

```javascript
// Hook Authentication
Java.perform(function() {  // Note: use ObjC.perform for iOS
var LoginViewController = ObjC.classes.LoginViewController;
var authenticate = LoginViewController["- authenticate:password:"];

Interceptor.attach(authenticate.implementation, {
  onEnter: function(args) {
    var self = args[0];
    var username = Memory.readUtf8String(args[1]);
    var password = Memory.readUtf8String(args[2]);
    console.log("[Auth] Username: " + username);
    console.log("[Auth] Password: " + password);
  },
  onLeave: function(retval) {
    console.log("[Auth] Result: " + retval);
  }
});
});
```

**Hook Keychain Access:**
```javascript
// Hook SecItemCopyMatching (read from Keychain)
Interceptor.attach(Module.findExportByName(null, "SecItemCopyMatching"), {
  onEnter: function(args) {
    console.log("[Keychain] Requesting item");
  },
  onLeave: function(retval) {
    console.log("[Keychain] Item returned, status: " + retval);
  }
});

// Hook SecItemAdd (write to Keychain)
Interceptor.attach(Module.findExportByName(null, "SecItemAdd"), {
  onEnter: function(args) {
    console.log("[Keychain] Adding item");
  }
});
```

**Hook HTTP Requests:**
```javascript
// Hook NSURLSession dataTaskWithURL
var NSURLSession = ObjC.classes.NSURLSession;
var dataTask = NSURLSession["+ sharedSession"];

Interceptor.attach(ObjC.classes.NSURLRequest.ctor.implementation, {
  onEnter: function(args) {
    var url = args[1];
    console.log("[Request] URL: " + url);
  }
});
```

**Hook SQLite Queries:**
```javascript
// Hook sqlite3_exec
Interceptor.attach(Module.findExportByName(null, "sqlite3_exec"), {
  onEnter: function(args) {
    var sql = Memory.readCString(args[1]);
    console.log("[SQLite] " + sql);
  }
});

// Hook sqlite3_step
Interceptor.attach(Module.findExportByName(null, "sqlite3_step"), {
  onLeave: function(retval) {
    if (retval == 100) {  // SQLITE_ROW
      console.log("[SQLite] Row returned");
    }
  }
});
```

**Running Hooks:**
```bash
# Save hook to hook.js
frida -U -f com.example.app -l hook.js --no-pause

# Or attach to running app
frida -U com.example.app -l hook.js

# Interactive console
frida -U com.example.app
[USB::iPhone::PID 1234]-> console.log("test")
```

### 3.3 Bypassing Jailbreak Detection
**Objective:** Disable anti-tampering mechanisms

**iOS Jailbreak Detection Methods:**

```
1. File existence checks
   - /Applications/Cydia.app
   - /usr/sbin/sshd
   - /Library/MobileSubstrate
   
2. Function tests
   - fork() (returns -1 on jailbroken)
   - ptrace() (PT_DENY_ATTACH)
   
3. System calls
   - stat() on Cydia paths
   - readlink() on dyld paths
   
4. Sandbox checks
   - NSFileManager access
```

**Bypass Strategy 1: Hook File Access**
```javascript
// Hook access() - most common jailbreak check
var libc = Module.findExportByName(null, "access");
Interceptor.replace(libc, new NativeCallback(function(path, mode) {
  var pathStr = Memory.readCString(path);
  
  var jailbreakPaths = [
    "/Applications/Cydia.app",
    "/usr/sbin/sshd",
    "/Library/MobileSubstrate",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/bin/sh",
    "/usr/sbin/ssh"
  ];
  
  for (var i = 0; i < jailbreakPaths.length; i++) {
    if (pathStr.includes(jailbreakPaths[i])) {
      console.log("[+] Blocked jailbreak check: " + pathStr);
      return -1;  // File not found
    }
  }
  
  return 0;  // Normal access
}, 'int', ['pointer', 'int']));
```

**Bypass Strategy 2: Hook System Calls**
```javascript
// Hook stat() to fake file permissions
var libc = Module.findExportByName(null, "stat");
Interceptor.attach(libc, {
  onEnter: function(args) {
    var path = Memory.readCString(args[0]);
    if (path.includes("Cydia") || path.includes("ssh")) {
      console.log("[+] Blocking stat check: " + path);
      // Modify to return error
      this.returnAddress = Module.findExportByName(null, "exit");
    }
  }
});
```

**Bypass Strategy 3: Hook ptrace()**
```javascript
// ptrace with PT_DENY_ATTACH prevents debugger
// Jailbreak detection uses this
var ptrace = Module.findExportByName(null, "ptrace");
Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
  if (request == 31) {  // PT_DENY_ATTACH
    console.log("[+] PT_DENY_ATTACH blocked");
    return 0;
  }
  return 0;
}, 'int', ['int', 'int', 'pointer', 'pointer']));
```

**Using Checkm8 or TrollStore (easier):**
```bash
# These tools patch the app itself, no need for complex hooks
# Checkm8: Older devices
# TrollStore: Newer devices, side-load without jailbreak
```

### 3.4 Debugger Attachment
**Objective:** Attach debugger for step-by-step analysis

**Using Xcode Debugger:**
```bash
# Open Xcode project
xcode-select --install

# Attach to running process
Xcode → Debug → Attach to Process → Select App

# Or from command line
lldb
(lldb) process attach --pid <pid>
(lldb) breakpoint set -f ViewController.m -l 10
(lldb) continue
(lldb) frame variable  # Inspect variables
```

**Using LLDB (Command Line):**
```bash
# Attach to process
lldb -p $(pgrep -f "com.example.app")

# Or start with debugger
lldb -n "AppName"
(lldb) continue
(lldb) breakpoint set -a 0x1000abcd
(lldb) register read
(lldb) memory read 0x1000 0x2000
```

**Using Frida for Tracing:**
```javascript
// Trace all Objective-C calls
Tracer.follow();

// Or trace specific class
var ViewController = ObjC.classes.ViewController;
Interceptor.attach(ViewController["- viewDidLoad"].implementation, {
  onEnter: function(args) {
    console.log("[viewDidLoad] Called");
  }
});
```

---

## Phase 4: Network Traffic Analysis (iOS)

### 4.1 Burp Suite Proxy Setup (iOS)
**Objective:** Intercept HTTPS/HTTP traffic

**Step 1: Install Burp CA Certificate**

**Works on Both Stock & Jailbroken iOS:**

```
Option A: Via Safari (Stock iOS)
1. On iPhone, open Safari
2. Navigate to: http://<burp-ip>:8080/
3. Click "CA Certificate" link
4. Install when prompted
5. Go to Settings → General → VPN & Device Management
6. Select "PortSwigger CA"
7. Tap "Install"
8. Verify trust: Settings → General → About → Certificate Trust Settings
   - Find "PortSwigger" and toggle to ON

Option B: Via Xcode (Simulator)
1. Export Burp CA certificate in DER format
2. Convert to PEM:
   openssl x509 -inform DER -in burp.der -out burp.pem
3. Drag into simulator
4. Settings → General → VPN & Device Management → Install
```

**Step 2: Configure WiFi Proxy**
```
Settings → WiFi → Long-press connected network
Tap "Modify Network"
Scroll to "HTTP Proxy"
Select "Manual"
Server: <burp-ip> (e.g., 192.168.1.100)
Port: 8080
Tap "Save"
```

**Step 3: Verify Certificate Trust (Critical)**
```
iOS 18.x (18.3+):
  Settings → General → VPN & Device Management
  Find "PortSwigger" → Tap → Verify "Full Trust" is ON

iOS 17.x and earlier:
  Settings → General → About → Certificate Trust Settings
  Find "PortSwigger CA" → Toggle ON
```

**Step 4: Test Traffic**
```bash
# On device, open app and navigate
# Check Burp for intercepted traffic

# Verify proxy is working:
# Open Settings → WiFi → View Network
# Should show proxy configured
```

**Using Transparent Proxy (Advanced):**
```bash
# For iOS on network, can use mitmproxy for transparent interception
# Requires network-level setup, more complex

# Or use pfctl on macOS:
sudo pfctl -ef mitmproxy.conf
```

### 4.2 Analyzing API Requests (iOS)
**Objective:** Test API endpoints for vulnerabilities

See **[Common Guide - API Testing](./mobile-app-security-common.md#42-analyzing-api-requests)**

### 4.3 Certificate Pinning Bypass (iOS)
**Objective:** Bypass certificate pinning to intercept HTTPS

**Certificate Pinning Detection:**
```bash
# Check if using pinning
strings app-binary | grep -i "certificate\|pin\|public.key"

# Check for common pinning libraries
nm -gm app-binary | grep -i "security\|certificate"
```

**Bypass Methods:**

**Method 1: Frida - Hook NSURLSession Delegate**
```javascript
// Disable certificate validation
Interceptor.attach(Module.findExportByName(null, "SecTrustEvaluate"), {
  onLeave: function(retval) {
    console.log("[+] SecTrustEvaluate called - bypassing");
    return 0;  // Trust evaluation success
  }
});
```

**Method 2: Frida - Hook SSL Verification**
```javascript
// Hook SSL_CTX_set_verify
var ssl_verify = Module.findExportByName(null, "SSL_CTX_set_verify");
Interceptor.replace(ssl_verify, new NativeCallback(function(ctx, mode) {
  console.log("[+] SSL_CTX_set_verify called - setting to VERIFY_NONE");
  return 0;  // SSL_VERIFY_NONE
}, 'int', ['pointer', 'int']));
```

**Method 3: Frida - Hook URLSession:**
```javascript
// Disable NSURLSession pinning
var URLSession = ObjC.classes.NSURLSession;
var delegate = ObjC.classes.NSURLSessionDelegate;

Interceptor.attach(delegate["- URLSession:didReceiveChallenge:completionHandler:"].implementation, {
  onEnter: function(args) {
    console.log("[+] SSL Challenge - auto-accepting");
    // Force challenge acceptance
  }
});
```

**Method 4: Modify IPA (Repackage)**
```bash
# Extract IPA
unzip app.ipa -d app-extracted

# Modify binary (remove pinning code)
# This is complex - usually done with tools like Frida gadget

# Or disable code signature verification:
rm -rf app-extracted/Payload/App.app/_CodeSignature

# Repackage
zip -r app-modified.ipa app-extracted/
```

---

## Phase 5: iOS Storage Security

### 5.1 iOS Local Storage Assessment
**Objective:** Identify insecure data storage

**File System Access (Jailbroken):**
```bash
ssh root@device

# App bundle location
ls -la /var/containers/Bundle/Application/

# Find app by name
find /var/containers -name "*.app" -type d

# App data location
ls -la /var/mobile/Containers/Data/Application/

# Common storage paths
# Documents:
find /var/mobile/Containers/Data/Application -name "Documents" -type d

# Library:
find /var/mobile/Containers/Data/Application -name "Library" -type d

# Cache:
find /var/mobile/Containers/Data/Application -name "Caches" -type d
```

**NSUserDefaults (Key-Value Storage):**
```bash
# Plaintext storage - everything visible
find /var/mobile/Containers/Data/Application -name "*.plist" | head -5

# Pull and analyze
scp root@device:/var/mobile/Containers/.../com.example.app.plist ./

# View (convert to XML if needed)
plutil -p com.example.app.plist
cat com.example.app.plist | xmllint --format -

# Search for secrets
strings com.example.app.plist | grep -i "password\|token\|secret"
```

**SQLite Databases:**
```bash
# Locate
find /var/mobile/Containers -name "*.db" -o -name "*.sqlite"

# Pull database
scp root@device:/path/to/database.db ./

# Query
sqlite3 database.db
sqlite> .tables
sqlite> SELECT * FROM users;
sqlite> SELECT * FROM credentials;
```

**File Storage:**
```bash
# Check app directory
ssh root@device ls -la /var/mobile/Containers/Data/Application/[UUID]/Documents/

# Pull all data
scp -r root@device:/var/mobile/Containers/Data/Application/[UUID]/Documents ./app-documents

# Analyze
find app-documents -type f | xargs file
strings app-documents/* | grep -i "password"
```

**Keychain (Credential Storage):**
```bash
# On device, query keychain
security find-generic-password -a | grep -v "Keychain"

# Or use Frida to hook access
Interceptor.attach(Module.findExportByName(null, "SecItemCopyMatching"), {
  onEnter: function(args) {
    console.log("[Keychain] Item requested");
  }
});

# Or manually export
ssh root@device
sqlite3 /var/Keychains/keychain-2.db "SELECT * FROM genp;"
```

---

## Phase 7: iOS Cryptography Assessment

### 7.1 Cryptographic Implementation Review
**Objective:** Identify weak cryptography

**Common iOS Crypto Issues:**
```
1. CCCrypt with DES - Too weak
2. MD5, SHA1 - Collision vulnerabilities
3. CCRandom - Not secure enough
4. Hardcoded encryption keys
5. No authentication (bare AES)
```

**Search for Weak Patterns:**
```bash
# Extract headers
class-dump -H -o headers/ app-binary

# Search for weak algorithms
grep -r "kCCAlgorithmDES\|kCCAlgorithmRC4" headers/
grep -r "MD5\|SHA1" headers/

# Search for random functions
grep -r "random\|rand" headers/ | grep -v "SecRandom"

# Search for hardcoded keys
strings app-binary | grep -E "^[0-9a-fA-F]{32,}" | head -10
```

**Vulnerable Patterns:**
```objective-c
// VULNERABLE: DES (weak)
CCCrypt(kCCEncrypt, kCCAlgorithmDES, ...);

// VULNERABLE: ECB mode (deterministic)
CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, ...);

// VULNERABLE: Weak random
uint32_t random_key = arc4random();

// SAFE: Strong encryption
CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, ...);
SecRandomCopyBytes(kSecRandomDefault, keyLength, key);
```

### 7.2 Key Management Testing (iOS)
**Objective:** Verify secure key storage

**Keychain Usage:**
```bash
# Check if using Keychain
class-dump -H -o headers/ app-binary
grep -r "Keychain\|SecItem\|Security" headers/

# Query Keychain
security find-generic-password -a
security find-certificate -a

# Vulnerable: Keys in NSUserDefaults
grep -r "password\|api_key" headers/ | grep "UserDefaults"
```

**Hardcoded Key Search:**
```bash
# Search for base64-encoded keys
strings app-binary | grep -E "^[A-Za-z0-9/+]{40,}={0,2}$" | head -10

# Search for PEM formats
strings app-binary | grep "-----BEGIN"

# Search in binary for key material
xxd app-binary | grep -i "secret\|password"
```

---

## Phase 8: iOS-Specific Vulnerabilities

### 8.1 iOS-Specific Issues
**Objective:** Test iOS-specific vulnerabilities

**URL Scheme Exploitation:**
**Objective:** Trigger unintended app behavior via URL schemes

**Extract URL Schemes:**
```bash
# From Info.plist
strings app-binary | grep "://"

# Or from class-dump
grep -r "URL\|Scheme" headers/ | grep -i "open\|handle"
```

**Example URL Schemes:**
```
myapp://user/123        # Deep link to user profile
myapp://admin           # Admin panel
myapp://api/users       # API endpoint
instagram://profile/123 # Third-party app invocation
```

**Exploit Scenarios:**
```bash
# On device
# Via Siri Shortcuts
# Via Safari
xcrun simctl openurl booted "myapp://admin"

# Or directly
ssh root@device
open myapp://user/123  # On device

# Frida hook
Interceptor.attach(ObjC.classes.AppDelegate["- application:openURL:options:"].implementation, {
  onEnter: function(args) {
    var url = Memory.readUtf8String(args[2]);
    console.log("[URL Scheme] " + url);
  }
});
```

**Pasteboard (Clipboard) Monitoring:**
**Objective:** Monitor sensitive data in clipboard

```javascript
// Monitor pasteboard access
var UIPasteboard = ObjC.classes.UIPasteboard;

Interceptor.attach(UIPasteboard["+ generalPasteboard"].implementation, {
  onLeave: function(retval) {
    console.log("[Pasteboard] Accessed");
    var pb = new ObjC.Object(retval);
    console.log("[Pasteboard] String: " + pb.string());
  }
});

// Or hook string property
var string = Module.findExportByName(null, "[UIPasteboard string]");
Interceptor.attach(string, {
  onLeave: function(retval) {
    console.log("[Clipboard] " + Memory.readUtf8String(retval));
  }
});
```

**App Transport Security (ATS) Bypass:**
**Objective:** Bypass HTTP blocking

```javascript
// Hook ATS validation
Interceptor.attach(Module.findExportByName(null, "_NSHTTPSWillBeRequiredForURL"), {
  onLeave: function(retval) {
    console.log("[ATS] HTTPS requirement check - bypassing");
    return 0;  // Return NO (false)
  }
});

// Hook SSL verification
Interceptor.attach(Module.findExportByName(null, "SecTrustEvaluate"), {
  onLeave: function(retval) {
    return 0;  // Trust success
  }
});
```

---

## Phase 9: iOS Data Exfiltration

### 9.1 iOS Data Extraction
**Objective:** Extract and analyze app data

**Full Data Pull:**
```bash
ssh root@device

# Get app UUID
find /var/mobile/Containers/Data/Application -name com.example.app.plist -o -type d | head -5

# Copy entire app data
scp -r root@device:/var/mobile/Containers/Data/Application/[UUID]/ ./app-data/

# Analyze
ls -la app-data/
cat app-data/Documents/*
```

**Database Dump:**
```bash
ssh root@device

# Find databases
find /var/mobile/Containers/Data/Application -name "*.db"

# Dump to SQL
sqlite3 /path/to/database.db ".dump" > database.sql

# Transfer
scp root@device:/tmp/database.sql ./
```

**Preferences Dump:**
```bash
scp root@device:/path/to/*.plist ./prefs/

# Convert and read
for f in prefs/*.plist; do
  plutil -p "$f" | less
done
```

### 9.2 iOS Memory Forensics
**Objective:** Extract sensitive data from memory

**Memory Dumping with Frida:**
```javascript
// Search memory for patterns
Interceptor.attach(Module.findExportByName(null, "malloc"), {
  onLeave: function(retval) {
    var ptr = retval;
    try {
      var str = Memory.readUtf8String(ptr);
      if (str.includes("password") || str.includes("token")) {
        console.log("[Memory] Found: " + str);
      }
    } catch (e) {}
  }
});
```

**Using LLDB:**
```bash
lldb -n "AppName"
(lldb) memory read 0x1000 0x2000
(lldb) po $rdi  # Print object
(lldb) register read rax  # Check register
```

### 9.3 iOS Log Analysis
**Objective:** Extract sensitive data from logs

**Console Output:**
```bash
# Real-time logs
deviceconsole

# Or via Xcode
Xcode → Window → Devices → Select Device → View Device Logs

# Search
deviceconsole | grep -i "password\|token\|secret"
```

**Using Frida for Logging:**
```javascript
// Intercept NSLog calls
Interceptor.attach(Module.findExportByName(null, "NSLog"), {
  onEnter: function(args) {
    var format = Memory.readUtf8String(args[0]);
    console.log("[NSLog] " + format);
  }
});
```

---

## Phase 10: iOS Exploitation & Privilege Escalation

### 10.1 iOS Privilege Escalation
**Objective:** Escalate privileges (on jailbroken device)

**Dangerous Permissions (iOS):**
```
Health Data
→ Access user's health/fitness data
→ Medical information leak

Contacts
→ Access all contacts
→ Phone numbers, emails exfiltration

Calendar
→ Access calendar events
→ Learn user's schedule

Photos
→ Access camera roll
→ Steal private photos

Location
→ Track user in real-time
→ Location history

Microphone
→ Monitor conversations
→ Voice/audio recording

Camera
→ Record video
→ Spy on user

Bluetooth
→ Connect to user's devices
→ Smartwatch, headphones, etc.
```

**Jailbreak Privileges:**
```
With jailbreak, can:
- Read/write system files
- Modify app behavior
- Hook any function
- Bypass code signing
- Access restricted APIs
```

**Example Exploitation:**
```bash
# Read health data
sqlite3 /var/mobile/Containers/.../HealthKit.db "SELECT * FROM objects;"

# Access private photos
scp -r root@device:/var/mobile/Media/PhotoData ./photos/

# Modify app code
# Inject Frida gadget into app binary
# Resign with custom certificate
```

---

## Tools & References

### Decompilation & Analysis
- **Hopper Disassembler** - Binary analysis
- **class-dump** - Extract headers
- **Frida** - Runtime instrumentation
- **MobSF** - Mobile security scanning
- **strings/nm/otool** - Binary utilities

### Interception & Debugging
- **Burp Suite** - Proxy & intercept
- **Xcode** - Debugger
- **LLDB** - Command line debugger
- **Cycript** - JavaScript REPL
- **Console.app** - System logs

### Jailbreaking
- **Checkra1n** - Older devices
- **unc0ver** - Alternative
- **Palera1n** - Newer devices
- **TrollStore** - No jailbreak needed

---

**Last Updated:** 2026-03-20
**Version:** 2.0 (split into common + platform-specific)
