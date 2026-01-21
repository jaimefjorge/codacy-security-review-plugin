---
name: security-review
description: Comprehensive security review combining Codacy CLI v2 static analysis with AI-powered security insights. Analyzes code for vulnerabilities, provides remediation guidance, and generates security reports.
argument-hint: "[path] [--tool <tool>] [--severity <level>] [--sarif]"
---

# Comprehensive Security Review

You are performing a comprehensive security review that combines Codacy's static analysis tools with your AI-powered security expertise. **This review is enhanced by project-specific profiles and security patterns generated during setup.**

## Arguments

The user may provide: `$ARGUMENTS`

- `path`: Specific file or directory to analyze (default: entire project)
- `--tool <tool>`: Focus on specific tool (eslint, trivy, semgrep, pylint, etc.)
- `--severity <level>`: Minimum severity to report (info, warning, error, critical)
- `--sarif`: Generate SARIF output file for integration

## Security Review Workflow

### Phase 1: Load Project Profile

**CRITICAL**: Before running any analysis, check for and load the project profile:

```bash
# Check for project profile
ls -la .codacy/project-profile.yaml 2>/dev/null
ls -la .codacy/security-patterns.yaml 2>/dev/null
```

If the profile exists, read it to understand:
- Project type and architecture
- Primary languages and frameworks
- Security-relevant components (auth, database, file handling, etc.)
- Entry points for user input
- Critical files to review

If the profile does NOT exist, suggest running `/codacy:setup` first for a more targeted analysis.

### Phase 2: Environment Check

1. Verify Codacy CLI v2 is installed and configured (binary is named `codacy-cli-v2`):
```bash
~/.local/bin/codacy-cli-v2 version 2>/dev/null || codacy-cli-v2 version
```

2. Check for existing configuration:
```bash
ls -la .codacy/ 2>/dev/null || echo "Not configured"
```

If not configured, suggest running `/codacy:setup` first.

**Note**: Use `~/.local/bin/codacy-cli-v2` for all commands if the binary is not in PATH.

### Phase 3: Run Codacy Static Analysis

Execute the full analysis suite:

**All tools (default):**
```bash
~/.local/bin/codacy-cli-v2 analyze 2>&1
```

**Specific tool (if requested):**
```bash
~/.local/bin/codacy-cli-v2 analyze --tool <tool> 2>&1
```

**With SARIF output (if requested):**
```bash
~/.local/bin/codacy-cli-v2 analyze --format sarif -o security-report.sarif 2>&1
```

### Phase 4: Apply Project-Specific Security Patterns

If `.codacy/security-patterns.yaml` exists, use it to guide additional checks:

#### 4.1 Language-Specific Pattern Scanning

Based on detected languages, search for patterns using Grep:

**For JavaScript/TypeScript projects:**
```
Search for patterns like:
- eval\s*\(
- innerHTML\s*=
- dangerouslySetInnerHTML
- child_process\.exec
- new Function\s*\(
```

**For Python projects:**
```
Search for patterns like:
- exec\s*\(|eval\s*\(
- pickle\.loads?
- subprocess.*shell\s*=\s*True
- yaml\.load\s*\(
```

**For Go projects:**
```
Search for patterns like:
- fmt\.Sprintf.*sql
- exec\.Command.*\+
- template\.HTML
```

#### 4.2 Framework-Specific Scanning

If frameworks are detected in the profile, search for framework-specific vulnerabilities:

**React:**
- `dangerouslySetInnerHTML` usage
- Dynamic `href` attributes with user input
- Improper state handling with sensitive data

**Express:**
- Missing input validation on `req.body`, `req.query`, `req.params`
- Open redirects via `res.redirect`
- CORS misconfiguration

**Django:**
- `| safe` filter usage
- Raw SQL queries
- ALLOWED_HOSTS configuration

**Flask:**
- `| safe` in templates
- `send_file` path traversal risks
- Secret key handling

**FastAPI:**
- CORS `allow_origins=["*"]`
- Unvalidated path parameters

#### 4.3 Security Component Analysis

Based on detected security components, perform targeted analysis:

**If Authentication detected:**
- Check JWT implementation for common issues (none algorithm, missing expiry, weak secrets)
- Look for session configuration issues (missing httpOnly, secure flags)
- Verify password handling (hashing, storage)

**If Database detected:**
- Scan for SQL injection patterns in the detected ORM/database files
- Check for raw query usage
- Verify parameterized query usage

**If File Handling detected:**
- Look for path traversal vulnerabilities
- Check file type validation
- Verify upload size limits

**If External APIs detected:**
- Check for hardcoded API keys
- Verify SSL/TLS usage
- Look for sensitive data in logs

### Phase 5: Secrets Detection

Scan for secrets using patterns from security-patterns.yaml:

```
Search for:
- AWS keys: AKIA[0-9A-Z]{16}
- GitHub tokens: gh[pousr]_[A-Za-z0-9_]{36,}
- Generic API keys: api[_-]?key.*[:=].*['"][a-zA-Z0-9]{20,}
- Database URLs: (mysql|postgres|mongodb)://
- Private keys: -----BEGIN.*PRIVATE KEY-----
```

### Phase 6: Critical Files Review

From the project profile or patterns, identify and review critical files:

- Authentication logic (`**/auth/**`, `**/login/**`)
- Security middleware (`**/middleware/**`)
- Configuration files (`**/config/**`, `**/.env*`)
- Infrastructure files (`**/Dockerfile*`, `**/kubernetes/**`, `**/terraform/**`)

For each critical file found, perform a brief security-focused review.

### Phase 7: AI-Powered Deep Analysis

For each significant finding from Codacy AND custom pattern matching, provide:

1. **Severity Assessment**: Evaluate the real-world risk considering:
   - Exploitability (how easy is it to exploit?)
   - Impact (what's the damage if exploited?)
   - Context (is this user-facing, internal, test code?)
   - Project type (API vs library vs frontend affects risk)

2. **Root Cause Analysis**: Explain WHY this is a vulnerability, not just WHAT it is

3. **Remediation Guidance**: Provide specific, actionable fixes with code examples

4. **Related Concerns**: Identify similar patterns that might exist elsewhere

### Phase 8: Manual Code Review (AI Enhancement)

Beyond static analysis, perform intelligent code review focusing on areas identified in the project profile:

1. **Authentication & Authorization** (if detected)
   - Check for proper auth checks on sensitive operations
   - Look for authorization bypasses
   - Verify session management

2. **Input Validation** (at detected entry points)
   - Focus on routes/controllers identified in profile
   - Check for proper sanitization
   - Look for injection vectors

3. **Cryptography**
   - Identify weak algorithms (MD5, SHA1, DES)
   - Check for hardcoded keys/IVs
   - Verify proper random number generation

4. **Data Exposure**
   - Look for sensitive data in logs
   - Check for PII handling issues
   - Identify information disclosure

5. **Error Handling**
   - Check for verbose error messages
   - Look for exception handling gaps
   - Verify fail-secure patterns

6. **Business Logic**
   - Identify race conditions
   - Check for TOCTOU issues
   - Look for logic flaws

### Phase 9: Generate Security Report

Create a structured report with project context:

```markdown
# Security Review Report

## Project Context
- **Project**: <from profile>
- **Type**: <web-app|api|library|cli>
- **Architecture**: <monolith|microservices|serverless>
- **Primary Language**: <language>
- **Frameworks**: <list>

## Executive Summary
- Total issues found: X
- Critical: X | High: X | Medium: X | Low: X
- Overall risk assessment
- Key areas of concern based on project type

## Critical Findings
[List critical issues with full details]

### Issue 1: <Title>
- **Severity**: Critical
- **Location**: `file:line`
- **CWE**: CWE-XXX
- **Description**: What the issue is
- **Impact**: What could happen if exploited
- **Remediation**: How to fix it
- **Code Example**:
```<lang>
// Before (vulnerable)
...

// After (fixed)
...
```

## High Priority Issues
[List high priority issues with same format]

## Medium Priority Issues
[List medium priority issues]

## Low Priority / Informational
[List low priority issues]

## Patterns Checked
Based on project profile, the following patterns were specifically checked:
- [x] JavaScript XSS patterns (15 patterns)
- [x] React-specific vulnerabilities (3 patterns)
- [x] Express middleware issues (5 patterns)
- [x] JWT authentication (4 patterns)
- [x] Secrets detection (7 patterns)

## Files Reviewed
| File | Reason | Issues Found |
|------|--------|--------------|
| src/auth/jwt.ts | Authentication logic | 2 |
| src/middleware/auth.ts | Request processing | 1 |
| config/config.yaml | Configuration | 0 |

## Recommendations
### Immediate Actions (Fix Now)
1. [Critical/High severity items]

### Short-term Improvements (This Sprint)
2. [Medium severity items]

### Long-term Security Enhancements (Roadmap)
3. [Low severity + architectural improvements]

## Tools Used
- Codacy CLI v2 with: [list tools]
- AI-powered code review
- Project-specific patterns from: .codacy/security-patterns.yaml
```

## Output Guidelines

1. **Be Specific**: Include file paths, line numbers, and code snippets
2. **Be Actionable**: Every finding should have a clear remediation path
3. **Prioritize**: Help the user focus on what matters most
4. **Context Matters**: Consider the project type and architecture from the profile
5. **No False Positives**: If uncertain, investigate further before reporting
6. **Leverage Profile**: Use project-specific knowledge for more accurate assessment

## OWASP Top 10 Checklist

Ensure coverage of:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Logging Failures
- A10: SSRF

## Example Workflow

```bash
# Load project profile first
cat .codacy/project-profile.yaml

# Run full analysis
~/.local/bin/codacy-cli-v2 analyze

# For specific concerns based on profile:
# - If Python + Flask detected:
~/.local/bin/codacy-cli-v2 analyze --tool pylint
~/.local/bin/codacy-cli-v2 analyze --tool semgrep

# - If JavaScript + React detected:
~/.local/bin/codacy-cli-v2 analyze --tool eslint
~/.local/bin/codacy-cli-v2 analyze --tool semgrep

# - For dependency vulnerabilities:
~/.local/bin/codacy-cli-v2 analyze --tool trivy
```

After Codacy analysis:
1. Read the project profile to understand context
2. Read the security patterns to know what to look for
3. Apply custom patterns via Grep searches
4. Read relevant files to perform deeper AI analysis on flagged issues
5. Focus on security components identified in the profile
