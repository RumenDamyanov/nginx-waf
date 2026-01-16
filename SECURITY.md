# Security Policy

## ⚠️ Project Status

**nginx-waf is experimental and NOT production-ready.**

Use at your own risk. Security vulnerabilities are expected during early development.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

### Contact

**Email:** security@rumenx.com

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Resolution:** Depends on severity and complexity

### What to Expect

1. We'll acknowledge receipt of your report
2. We'll investigate and assess the issue
3. We'll work on a fix
4. We'll credit you in the release notes (unless you prefer otherwise)

## Scope

### In Scope

- nginx-waf module code
- Configuration parsing vulnerabilities
- Memory safety issues
- Access control bypasses

### Out of Scope

- Issues in nginx itself (report to nginx.org)
- Issues in dependencies
- Theoretical attacks without proof of concept
- Social engineering

## Security Considerations

### Known Limitations (Experimental Status)

- Code has not been security audited
- No formal security review has been conducted
- Memory safety is a goal but not guaranteed

### Design Principles

- Use nginx memory pools (no malloc/free)
- Validate all input
- Fail securely (deny by default on errors)
- Minimal attack surface

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter notifies us privately
2. We investigate and develop a fix
3. We release the fix
4. We publicly disclose after patch is available

Please allow reasonable time for us to address issues before public disclosure.

---

Thank you for helping keep nginx-waf secure!
