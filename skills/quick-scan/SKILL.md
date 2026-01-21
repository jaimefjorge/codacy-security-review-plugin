---
name: quick-scan
description: Quick security scan of specific files, staged changes, or recent commits. Faster than full review, ideal for pre-commit checks and PR reviews.
argument-hint: "[file] [--staged] [--commit <sha>] [--pr <number>] [--fix]"
---

# Quick Security Scan

You are performing a quick, targeted security scan. This is faster than a full review and ideal for:
- Pre-commit validation
- Pull request reviews
- Checking specific files
- Validating recent changes

**This scan is enhanced by project-specific profiles when available.**

## Arguments

The user may provide: `$ARGUMENTS`

- `file`: Specific file path to scan
- `--staged`: Scan only staged git changes
- `--commit <sha>`: Scan changes in a specific commit
- `--pr <number>`: Scan changes in a pull request (requires gh CLI)
- `--fix`: Attempt auto-fix for supported issues

## Prerequisites

Ensure Codacy CLI v2 is installed. The binary is named `codacy-cli-v2` and is typically installed at `~/.local/bin/codacy-cli-v2`. If not configured, run `/codacy:setup` first.

## Quick Scan Workflow

### Step 1: Load Project Profile (If Available)

Check for and load the project profile for context-aware scanning:

```bash
# Check for project profile
ls -la .codacy/project-profile.yaml 2>/dev/null
ls -la .codacy/security-patterns.yaml 2>/dev/null
```

If the profile exists, read it to understand:
- Primary language and frameworks
- Which security patterns are enabled
- Critical files that need extra attention

This allows the quick scan to be **smarter and more targeted** than a generic scan.

### Step 2: Determine Scan Mode

Based on arguments provided, select the appropriate scan mode:

---

## Mode 1: Specific File Scan

If a file path is provided:

```bash
# Run Codacy analysis on the project directory
~/.local/bin/codacy-cli-v2 analyze 2>&1
```

Then filter the results to show only issues in the specified file.

**If project profile exists**, also run targeted pattern checks:
- Identify file language from extension
- Apply language-specific patterns from `.codacy/security-patterns.yaml`
- If file matches a framework (e.g., React component), apply framework patterns

Then perform AI analysis focusing on:
- Security issues in the specific file
- Context-aware risk assessment (using profile info)
- Quick remediation suggestions

---

## Mode 2: Staged Changes Scan

If `--staged` is specified:

```bash
# Get list of staged files to know what to focus on
git diff --cached --name-only

# Run Codacy analysis on the project directory
~/.local/bin/codacy-cli-v2 analyze 2>&1
```

Then filter the results to show only issues in the staged files.

**Profile-Enhanced Scanning:**
- If profile exists, filter files by detected languages (ignore non-source files)
- Prioritize files in security-critical directories (auth/, middleware/, config/)
- Apply framework-specific patterns to relevant files

Focus on:
- New code being introduced
- Changes to existing security controls
- Potential regressions

---

## Mode 3: Commit Scan

If `--commit <sha>` is specified:

```bash
# Get files changed in commit to know what to focus on
git diff-tree --no-commit-id --name-only -r <sha>

# Get the actual diff for context
git show <sha> --no-stat

# Run Codacy analysis on the project directory
~/.local/bin/codacy-cli-v2 analyze 2>&1
```

Then filter the results to show only issues in the files changed in that commit.

**Profile-Enhanced:**
- Highlight changes in security-critical files
- Apply relevant patterns based on file types changed

---

## Mode 4: Pull Request Scan

If `--pr <number>` is specified:

```bash
# Get PR diff using GitHub CLI for context
gh pr diff <number>

# Get list of changed files to know what to focus on
gh pr view <number> --json files -q '.files[].path'

# Run Codacy analysis on the project directory
~/.local/bin/codacy-cli-v2 analyze 2>&1
```

Then filter the results to show only issues in the files changed in the PR.

**Profile-Enhanced:**
- Provide context about which security components are affected
- Flag if authentication, database, or other critical areas are touched

---

## Step 3: Apply Profile-Based Pattern Matching

If `.codacy/security-patterns.yaml` exists, apply relevant patterns:

### For each file, determine:
1. **Language** - from file extension
2. **Framework** - from profile (if file is in framework-specific directory)
3. **Security component** - if file is in auth/, config/, etc.

### Run targeted pattern searches:

**JavaScript/TypeScript files:**
```
Search for: eval\s*\(, innerHTML\s*=, dangerouslySetInnerHTML, child_process\.exec
```

**Python files:**
```
Search for: exec\s*\(, pickle\.loads?, subprocess.*shell=True, yaml\.load\s*\(
```

**Go files:**
```
Search for: fmt\.Sprintf.*sql, exec\.Command.*\+, template\.HTML
```

### Framework-specific (if detected in profile):

**React components:**
```
Search for: dangerouslySetInnerHTML, href\s*=\s*\{
```

**Express routes:**
```
Search for: req\.query, req\.params, req\.body, res\.redirect
```

**Flask/Django:**
```
Search for: \|\s*safe, raw\s*\(, send_file
```

## Step 4: Secrets Scan

Quick check for secrets in changed files:

```
Search for:
- AKIA[0-9A-Z]{16}  (AWS keys)
- gh[pousr]_[A-Za-z0-9_]{36,}  (GitHub tokens)
- api[_-]?key.*[:=].*['"][a-zA-Z0-9]{20,}  (Generic API keys)
- (mysql|postgres|mongodb)://  (Database URLs)
```

## Quick Scan Output Format

Provide a concise, actionable report:

```markdown
## Quick Scan Results

**Scope**: [file/staged/commit/PR]
**Files Scanned**: X
**Project Profile**: [Used/Not found]
**Issues Found**: X (Critical: X, High: X, Medium: X, Low: X)

### Project Context (if profile exists)
- **Primary Language**: Python
- **Frameworks**: Flask, SQLAlchemy
- **Security Patterns Applied**: Python (12), Flask (5), Database (3)

### Issues Requiring Attention

| File | Line | Severity | Issue | Quick Fix |
|------|------|----------|-------|-----------|
| src/auth/login.py | 45 | High | Bare except clause | Catch specific exceptions |
| src/api/users.py | 23 | Medium | SQL formatting risk | Use parameterized query |

### Pattern Matches (from project profile)

| Pattern | File | Line | Description |
|---------|------|------|-------------|
| `yaml.load` | config/loader.py | 12 | Unsafe YAML loading |
| `| safe` | templates/user.html | 34 | XSS risk in template |

### Secrets Check
- [x] No AWS keys found
- [x] No GitHub tokens found
- [x] No hardcoded API keys found

### Summary
- **Main concerns**: [Brief list]
- **Files touching security components**: [List if any]

### Recommended Actions
1. [Most critical action]
2. [Second action]
```

## Security Patterns Priority

For quick scans, prioritize high-impact patterns:

### Critical Patterns (Block merge)
- Hardcoded credentials/secrets
- SQL injection vectors
- Command injection
- Path traversal
- Unsafe deserialization

### High Priority (Review carefully)
- XSS vulnerabilities
- CSRF issues
- Insecure randomness
- Weak cryptography
- Missing authentication

### Medium Priority (Consider fixing)
- Information disclosure
- Verbose error handling
- Missing input validation
- Insecure defaults

## Auto-Fix Support

If `--fix` is specified and Codacy supports auto-fix for the tool:

```bash
~/.local/bin/codacy-cli-v2 analyze --fix 2>&1
```

Then show what was fixed and what still needs manual attention.

## Integration Tips

Suggest to the user based on their project profile:

### Pre-commit Hook
```bash
# In .git/hooks/pre-commit or via husky
claude "/codacy:quick-scan --staged"
```

### CI/CD Pipeline
```yaml
# In .github/workflows/security.yml
- name: Quick Security Scan
  run: |
    claude "/codacy:quick-scan --pr ${{ github.event.pull_request.number }}"
```

### VS Code Task
```json
{
  "label": "Security Scan Current File",
  "type": "shell",
  "command": "claude",
  "args": ["/codacy:quick-scan", "${file}"]
}
```

## When to Suggest Full Review

After a quick scan, suggest running `/codacy:security-review` if:
- Changes touch authentication or authorization code
- New dependencies are added
- Infrastructure files are modified
- Multiple high-severity issues are found
- Files in critical_files list (from profile) are modified
