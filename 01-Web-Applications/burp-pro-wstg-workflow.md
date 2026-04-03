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

**Version:** 1.0  
**Last Updated:** 2026-04-03  
**For:** Burp Suite Pro users following WSTG methodology
