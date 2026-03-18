# 2. Configuration and Deployment Management Testing - WSTG-CONF Tests

## WSTG-CONF-01 | Test Network Infrastructure Configuration

**Description:** Verify network segmentation, firewall rules, and server isolation.

**Example Commands:**
```bash
nmap -p- target.com
nmap -sU target.com
nmap -sV -p 22,80,443,3306,5432 target.com
curl -I https://target.com | grep -i "x-forwarded\|x-real"
traceroute target.com
```

---

## WSTG-CONF-02 | Test Application Platform Configuration

**Description:** Verify secure defaults in application server configuration (debug mode disabled, error details hidden).

**Example Commands:**
```bash
curl https://target.com/debug
curl https://target.com/__debug__
curl https://target.com/.env
curl -u admin:admin https://target.com/admin
curl https://target.com/config.json
```

---

## WSTG-CONF-03 | Test File Extensions Handling for Sensitive Information

**Description:** Test if server mishandles file extensions (.php, .bak, .old, .tmp, .swp).

**Example Commands:**
```bash
curl https://target.com/index.php.bak
curl https://target.com/index.php~
curl https://target.com/index.php.old
curl https://target.com/shell.php.jpg
curl "https://target.com/shell.php%00.jpg"
ffuf -u https://target.com/index.FUZZ -w extensions.txt
```

---

## WSTG-CONF-04 | Review Old Backup and Unreferenced Files

**Description:** Search for backup files (.bak, .backup, .sql, .zip, .tar.gz) containing sensitive data.

**Example Commands:**
```bash
ffuf -u https://target.com/FUZZ -w common-backups.txt
curl https://target.com/index.php.bak
curl https://target.com/config.php.backup
curl https://target.com/database.sql
curl https://target.com/.git/config
curl https://target.com/.git/HEAD
```

---

## WSTG-CONF-05 | Enumerate Infrastructure and Application Admin Interfaces

**Description:** Discover hidden admin panels, control dashboards, and privileged interfaces.

**Example Commands:**
```bash
ffuf -u https://target.com/FUZZ -w admin-paths.txt
curl https://target.com/admin
curl https://target.com/administrator
curl https://target.com/wp-admin
curl https://target.com/phpmyadmin
curl https://target.com/api/admin
```

---

## WSTG-CONF-06 | Test HTTP Methods

**Description:** Verify that unnecessary HTTP methods (PUT, DELETE, TRACE, CONNECT) are disabled.

**Example Commands:**
```bash
curl -X OPTIONS -v https://target.com
curl -I -X OPTIONS https://target.com
curl -X PUT -d "malicious content" https://target.com/shell.php
curl -X DELETE https://target.com/important_file.php
curl -X TRACE https://target.com
curl -X CONNECT https://target.com:443
```

---

## WSTG-CONF-07 | Test HTTP Strict Transport Security

**Description:** Verify HSTS header is present and properly configured to enforce HTTPS.

**Example Commands:**
```bash
curl -I https://target.com | grep -i "strict-transport"
curl -I http://target.com
curl -I https://subdomain.target.com | grep -i "strict-transport"
# Check HSTS preload list: https://hstspreload.org/
```

---

## WSTG-CONF-08 | Test RIA Cross Domain Policy

**Description:** Review crossdomain.xml and clientaccesspolicy.xml for overly permissive CORS policies.

**Example Commands:**
```bash
curl https://target.com/crossdomain.xml
curl https://target.com/clientaccesspolicy.xml
curl -H "Origin: https://attacker.com" -I https://target.com
curl -X OPTIONS -H "Origin: https://attacker.com" -H "Access-Control-Request-Method: POST" https://target.com
```

---

## WSTG-CONF-09 | Test File Permission

**Description:** Verify file and directory permissions on the server.

**Example Commands:**
```bash
ls -la /var/www/html
stat /path/to/file
find /var/www -type f -perm /004 -o -perm /002
ls -la /var/www/html/uploads
ftp target.com  # Test anonymous FTP access
```

---

## WSTG-CONF-11 | Test Cloud Storage

**Description:** Identify and test cloud storage buckets (S3, Azure Blob, GCS) for misconfigured access.

**Example Commands:**
```bash
curl https://target-backup.s3.amazonaws.com
aws s3 ls s3://target-bucket --no-sign-request
curl https://target.blob.core.windows.net/container/?restype=container&comp=list
curl https://storage.googleapis.com/target-bucket
ffuf -u https://FUZZ.s3.amazonaws.com -w subdomains.txt
```

---

## WSTG-CONF-12 | Testing for Content Security Policy ⭐

**Description:** Verify CSP header is present and restrictive enough to prevent XSS attacks. Weak or missing CSP allows inline scripts and arbitrary resource loading.

**Keywords:** CSP, XSS Prevention, Security Headers, Bypass Techniques, nonce, unsafe-inline, unsafe-eval

**Example Commands:**
```bash
# Check CSP header presence
curl -I https://target.com | grep -i "content-security-policy"

# Full header inspection
curl -I https://target.com

# Test CSP bypass with different payloads
curl "https://target.com/?q=<img src=x onerror=alert(1)>"
curl "https://target.com/?q=<script>alert(1)</script>"
curl "https://target.com/?q=<svg onload=alert(1)>"

# Test nonce-based CSP
curl -s https://target.com | grep "nonce="

# Extract and reuse nonce if found
# Analyze if nonce is properly validated

# Test unsafe-inline bypass
# If 'unsafe-inline' is present, inline styles/scripts work

# Test unsafe-eval bypass
# If 'unsafe-eval' is present, eval() and similar functions work

# Google CSP Evaluator
# Visit: https://csp-evaluator.withgoogle.com/
```

**Expected Output (Vulnerable):**
```
No Content-Security-Policy header
or
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'
or
Content-Security-Policy: default-src 'self'; script-src *
```

**CSP Security Levels:**
- **Bad:** No CSP, CSP with * wildcard, unsafe-inline, unsafe-eval
- **Weak:** CSP with nonce but reused/predictable, missing directives
- **Good:** Restrictive CSP with proper nonce rotation, no wildcards
- **Best:** CSP with hashes, strict nonce validation, report-uri configured

**Common CSP Bypass Techniques:**
1. **Nonce Reuse:** Capture and reuse nonces across multiple requests
2. **Unsafe-inline:** Inject inline styles/scripts if directive present
3. **Unsafe-eval:** Use eval(), Function() if directive present
4. **Wildcard Domains:** If script-src allows *.cdn.com, attack via cdn.com subdomains
5. **Data URIs:** Inject as data:text/html,<script>alert(1)</script>
6. **Object-src:** Missing = can inject objects/embeds
7. **JSONP Endpoints:** If allowed, can be leveraged for XSS
8. **SVG/XML:** If image-src allows SVG, can embed scripts

**Testing Checklist:**
- [ ] CSP header present?
- [ ] Nonce/hash used instead of unsafe-inline?
- [ ] Wildcard directives present?
- [ ] Report-URI configured?
- [ ] Directives for all resource types (script, style, image, etc.)?
- [ ] Missing default-src fallback?
- [ ] Can nonce be predicted/reused?
- [ ] Can you inject inline event handlers?

**CSP Evaluator Tool:** https://csp-evaluator.withgoogle.com/

**Resource Link:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Testing_for_Content_Security_Policy

---

**Resource Links:**
- WSTG-CONF-01: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- WSTG-CONF-02: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration
- WSTG-CONF-03: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information
- WSTG-CONF-04: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
- WSTG-CONF-05: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces
- WSTG-CONF-06: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
- WSTG-CONF-07: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security
- WSTG-CONF-08: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy
- WSTG-CONF-09: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission
- WSTG-CONF-11: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage
- WSTG-CONF-12: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Testing_for_Content_Security_Policy
