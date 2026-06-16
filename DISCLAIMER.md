# ⚠️ DISCLAIMER & LEGAL NOTICE

**VulnScan PRO** is a security testing tool intended **EXCLUSIVELY** for authorized penetration testing, security research, and educational purposes.

---

## 🚨 CRITICAL LEGAL WARNING

### Unauthorized Access is ILLEGAL

**Unauthorized computer access is a federal crime in most jurisdictions:**

- **USA**: Computer Fraud and Abuse Act (CFAA) — Up to 10 years imprisonment + fines
- **EU**: GDPR & eIDAS — Administrative fines up to €20,000,000
- **UK**: Computer Misuse Act 1990 — Up to 10 years imprisonment
- **Canada**: Criminal Code (s. 342.1) — Up to 2 years imprisonment
- **Other Jurisdictions**: Similar or harsher penalties

**You are personally liable for your actions.**

---

## ✅ AUTHORIZED USE ONLY

You may use VulnScan PRO **ONLY IF**:

1. ✅ You own the target system, OR
2. ✅ You have **explicit written authorization** from the system owner or authorized representative, OR
3. ✅ You are conducting testing in a **controlled lab environment** you own, OR
4. ✅ You are using this for **educational purposes** on systems designed for training

### What "Explicit Written Authorization" Means

- ❌ **NOT**: "My friend said it's okay"
- ❌ **NOT**: Verbal permission from IT staff
- ❌ **NOT**: Assumption that security testing is allowed
- ✅ **YES**: Signed contract specifying:
  - Target scope (domains, IPs, applications)
  - Testing methodology (web scanning, port scanning, etc.)
  - Duration of testing
  - Authorized tester name(s)
  - Client contact for issues
  - Legal indemnification clauses

---

## ⚠️ TOOL-SPECIFIC DISCLAIMERS

### JWT Analyzer

**IMPORTANT**: This tool decodes JWT claims **WITHOUT verifying the signature.**

- ❌ **Does NOT**: Validate JWT authenticity
- ❌ **Does NOT**: Prove signature vulnerabilities
- ✅ **Does**: Extract claims and test against common weak secrets

**Findings from JWT analysis must be manually verified:**

```python
# Example: If tool reports "Weak HMAC Secret: 'secret'"
# You MUST:
# 1. Manually verify the secret is actually 'secret' (not just guessed)
# 2. Test with real JWT tokens from the application
# 3. Confirm the application actually uses this secret
# 4. Report the finding only if verified
