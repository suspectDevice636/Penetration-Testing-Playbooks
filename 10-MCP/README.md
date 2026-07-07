# MCP Penetration Testing Playbooks

Comprehensive testing guides for Model Context Protocol (MCP) servers and agent-side exploitation vectors.

---

## 📚 Playbooks

### MCP_Penetration_Testing_Playbook_Comprehensive.md
**Full-coverage remote testing approach**

- Server-side security gaps (discovery, authentication, authorization)
- Resource access controls and method enumeration
- Input validation and error handling
- Complete attack surface matrix
- Burp Suite workflows and automation
- Reporting templates

**Use this when:** Testing MCP servers end-to-end, building comprehensive assessments, need structured methodology from discovery through exploitation.

**Coverage:** ~50KB | 20 sections | Full protocol → authentication → tools → resources → agent-side attacks

---

### MCP_Penetration_Testing_Playbook_Agentic.md
**Agent-side exploitation focus**

- Tool poisoning and content inspection
- Prompt injection via tool parameters
- Confused deputy attacks
- Tool chain exploitation
- Credential extraction from tools
- OAuth token misuse scenarios

**Use this when:** Testing agent-specific vulnerabilities, deep diving into how agents can be manipulated via MCP tools, auditing tool chains for security gaps.

**Coverage:** ~30KB | 8 sections | Assumes tools are connected; focuses on agent manipulation

---

## 🎯 Quick Decision Guide

| Scenario | Use |
|----------|-----|
| First-time MCP security audit | Comprehensive |
| Testing agent behavior with MCP tools | Agentic |
| Complete attack surface mapping | Comprehensive |
| Tool chain vulnerability research | Agentic |
| Compliance/reporting needed | Comprehensive |
| Agent jailbreak/prompt injection testing | Agentic |

---

## 🔄 Typical Workflow

1. **Start with Comprehensive** — discover endpoints, enumerate tools, map attack surface
2. **Move to Agentic** — test how connected agents behave with discovered tools
3. **Cross-reference** — use both playbooks for complete coverage

---

## 📋 Testing Checklist

- [ ] MCP endpoint discovery (robots.txt, .well-known)
- [ ] Authentication & authorization testing
- [ ] Tool enumeration and parameter validation
- [ ] Resource access controls
- [ ] Tool poisoning scenarios
- [ ] Prompt injection via tool descriptions/instructions
- [ ] Confused deputy attack paths
- [ ] Error handling and information disclosure
- [ ] OAuth token usage patterns
- [ ] Agent-specific vulnerability assessment

---

## 🛠️ Primary Tools

- **curl/bash** — Direct HTTP-based testing, SSE parsing
- **Burp Suite Pro** — Protocol analysis, workflow automation
- **jq** — JSON parsing and response inspection
- **Custom scripts** — SSE parsing, attack automation

---

## 📖 References

- [Model Context Protocol Spec](https://spec.modelcontextprotocol.io/)
- JSON-RPC 2.0 Specification
- Server-Sent Events (SSE) Protocol
- OWASP Agent Security Testing Guide

---

**Last Updated:** July 7, 2026  
**Status:** Complete
