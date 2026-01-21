---
name: help
description: Show help information about the Codacy plugin, available commands, and usage examples.
disable-model-invocation: true
---

# Codacy Plugin - Help

You are providing help information about the Codacy plugin.

## Display This Information

```markdown
# Codacy Plugin

Comprehensive security code review combining **Codacy CLI v2** static analysis
with **Claude's AI-powered** security insights.

## Available Commands

### `/codacy:setup`
Initialize and configure Codacy CLI v2 for your project.

**Usage:**
- `/codacy:setup` - Local setup (uses existing configs)
- `/codacy:setup --remote` - Setup with Codacy cloud integration
- `/codacy:setup --force` - Force re-initialization

**What it does:**
1. Checks if Codacy CLI v2 is installed
2. Initializes configuration in `.codacy/`
3. Auto-detects project languages
4. Installs required analysis tools

---

### `/codacy:security-review`
Full security review with AI-enhanced analysis.

**Usage:**
- `/codacy:security-review` - Full project review
- `/codacy:security-review src/` - Review specific directory
- `/codacy:security-review --tool trivy` - Focus on specific tool
- `/codacy:security-review --sarif` - Generate SARIF report

**What it does:**
1. Runs Codacy static analysis (multiple tools)
2. Parses and categorizes findings
3. Performs AI deep-dive on critical issues
4. Checks for OWASP Top 10 vulnerabilities
5. Provides remediation guidance
6. Generates comprehensive security report

---

### `/codacy:quick-scan`
Fast, targeted security scan for specific changes.

**Usage:**
- `/codacy:quick-scan file.js` - Scan specific file
- `/codacy:quick-scan --staged` - Scan staged git changes
- `/codacy:quick-scan --commit abc123` - Scan specific commit
- `/codacy:quick-scan --pr 42` - Scan pull request changes
- `/codacy:quick-scan --fix` - Auto-fix supported issues

**Ideal for:**
- Pre-commit checks
- Pull request reviews
- Quick validation of changes

---

### `/codacy:help`
Show this help information.

---

## Supported Analysis Tools

Codacy CLI v2 integrates with:

| Tool | Languages | Focus |
|------|-----------|-------|
| **ESLint** | JavaScript, TypeScript | Code quality, security |
| **Trivy** | All | Dependency vulnerabilities |
| **Semgrep** | Multiple | Security patterns |
| **Pylint** | Python | Code quality |
| **PMD** | Java | Code quality, security |
| **Bandit** | Python | Security |
| **Gosec** | Go | Security |
| **And more...** | | |

## Prerequisites

1. **Codacy CLI v2** installed:
   - macOS: `brew install codacy/codacy-cli-v2/codacy-cli-v2`
   - Linux: `bash <(curl -Ls https://raw.githubusercontent.com/codacy/codacy-cli-v2/main/codacy-cli.sh)`

2. **Docker** (optional, for some tools)

3. **Git** (for change-based scanning)

## Quick Start

1. Run `/codacy:setup` to initialize
2. Run `/codacy:security-review` for full analysis
3. Use `/codacy:quick-scan --staged` before commits

## More Information

- Codacy CLI v2: https://github.com/codacy/codacy-cli-v2
- OWASP Top 10: https://owasp.org/Top10/
```

Present this information clearly formatted to the user.
