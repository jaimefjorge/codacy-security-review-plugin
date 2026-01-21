# Codacy Security Review Plugin for Claude Code

A powerful Claude Code plugin that combines **Codacy CLI v2** static analysis with **Claude's AI-powered** security expertise for comprehensive code security reviews.

## Features

- **Project Profiling**: Automatically analyzes your codebase to understand languages, frameworks, and architecture
- **Project-Specific Security Patterns**: Generates custom security rules based on your detected stack
- **Automated Static Analysis**: Leverages Codacy's suite of analysis tools (ESLint, Trivy, Semgrep, Pylint, PMD, Bandit, Gosec, and more)
- **AI-Enhanced Review**: Claude provides deep security analysis, context-aware risk assessment, and actionable remediation guidance
- **OWASP Coverage**: Systematic checking for OWASP Top 10 vulnerabilities
- **Flexible Scanning**: Full project reviews, quick scans of staged changes, PR reviews, and file-specific analysis
- **SARIF Support**: Generate industry-standard SARIF reports for integration with other tools

## Installation

### Prerequisites

- **Claude Code** (latest version)

### Step 1: Install the Plugin

```bash
/plugin marketplace add jaimefjorge/codacy-security-review-plugin
```

### Step 2: Run Setup (Required)

**You must run setup before using any other commands.** This installs Codacy CLI v2 and configures your project:

```bash
/codacy-security-review:setup
```

The setup command will:
- Install Codacy CLI v2 if not already installed
- Profile your project (languages, frameworks, architecture)
- Generate project-specific security patterns
- Configure the appropriate analysis tools

## Updating the Plugin

```bash
claude plugin update codacy-security-review
```

Or enable auto-updates via `/plugin` → Marketplaces → Enable auto-update.

## Usage

### Quick Start

```bash
# 1. Setup (installs Codacy CLI v2 + profiles project + generates security patterns)
/codacy-security-review:setup

# 2. Run a full security review (uses project profile)
/codacy-security-review:security-review

# 3. Quick scan before committing
/codacy-security-review:quick-scan --staged
```

### Available Commands

| Command | Description |
|---------|-------------|
| `/codacy-security-review:setup` | **Required first.** Install Codacy CLI v2, profile project, and generate security patterns |
| `/codacy-security-review:security-review` | Full security review with AI analysis |
| `/codacy-security-review:quick-scan` | Fast scan of specific files or changes |
| `/codacy-security-review:help` | Show help information |

## Project Profiling (New!)

The setup command now performs comprehensive project analysis to optimize security scanning:

### What Gets Analyzed

1. **Directory Structure**
   - Source directories (src/, lib/, app/, etc.)
   - Test directories
   - Configuration directories
   - CI/CD pipelines
   - Infrastructure as code

2. **Languages and Versions**
   - Detects all programming languages
   - Identifies versions from config files
   - Counts files per language

3. **Frameworks Detection**
   - **JavaScript/TypeScript**: React, Vue, Angular, Next.js, Express, Fastify, NestJS
   - **Python**: Django, Flask, FastAPI, Tornado
   - **Go**: Gin, Echo, Fiber, Chi
   - **Java**: Spring Boot, Quarkus, Micronaut
   - **Ruby**: Rails, Sinatra
   - **PHP**: Laravel, Symfony

4. **Security Components**
   - Authentication (JWT, sessions, OAuth)
   - Database access (ORMs, raw queries)
   - File handling (uploads, downloads)
   - External API integrations
   - User input entry points

### Generated Files

After setup, two files are created in `.codacy/`:

#### `.codacy/project-profile.yaml`
Contains your project's structure, languages, frameworks, and security-relevant components.

```yaml
project:
  name: "my-app"
  type: "web-app"
  architecture: "monolith"

languages:
  primary: "typescript"
  all:
    - name: "typescript"
      version: "5.x"
      files_count: 200
      percentage: 60

frameworks:
  - name: "react"
    version: "18.x"
    type: "frontend"
  - name: "express"
    version: "4.x"
    type: "backend"

security_components:
  authentication:
    present: true
    type: "jwt"
    files:
      - "src/auth/"
```

#### `.codacy/security-patterns.yaml`
Contains project-specific security patterns to check, organized by:

- **Language patterns** (JavaScript, Python, Go, etc.)
- **Framework patterns** (React, Express, Django, Flask, etc.)
- **Component patterns** (authentication, database, file handling)
- **Secrets patterns** (AWS keys, API keys, tokens)
- **Critical files list** (files that always need review)

### How It Helps

1. **Smarter Scanning**: Quick scans know which patterns to apply based on your stack
2. **Better Prioritization**: Security reviews focus on your actual entry points
3. **Framework-Aware**: Checks for React XSS, Express CORS, Django safe filters, etc.
4. **Component-Aware**: JWT-specific checks if you use JWT, SQL injection patterns if you use databases
5. **Reduced False Positives**: Patterns only apply to relevant files

### Command Details

#### Setup
```bash
# Basic setup with project profiling (recommended)
/codacy-security-review:setup

# Setup with Codacy cloud integration
/codacy-security-review:setup --remote

# Force re-initialization and regenerate profile
/codacy-security-review:setup --force
```

#### Security Review
```bash
# Full project review (uses project profile if available)
/codacy-security-review:security-review

# Review specific directory
/codacy-security-review:security-review src/

# Use specific tool
/codacy-security-review:security-review --tool trivy

# Generate SARIF report
/codacy-security-review:security-review --sarif

# Filter by severity
/codacy-security-review:security-review --severity high
```

#### Quick Scan
```bash
# Scan specific file (applies language+framework patterns)
/codacy-security-review:quick-scan src/auth/login.js

# Scan staged changes (great for pre-commit)
/codacy-security-review:quick-scan --staged

# Scan specific commit
/codacy-security-review:quick-scan --commit abc123

# Scan pull request
/codacy-security-review:quick-scan --pr 42

# Auto-fix supported issues
/codacy-security-review:quick-scan --fix
```

## What Gets Analyzed

### Codacy Static Analysis Tools

| Tool | Languages | Focus |
|------|-----------|-------|
| ESLint | JavaScript, TypeScript | Code quality, security patterns |
| Trivy | All | Dependency vulnerabilities, container security |
| Semgrep | Multiple | Security patterns, custom rules |
| Pylint | Python | Code quality, error detection |
| Bandit | Python | Security vulnerabilities |
| PMD | Java | Code quality, security |
| Gosec | Go | Security vulnerabilities |
| SpotBugs | Java | Bug detection, security |

### AI-Powered Analysis

Claude enhances the static analysis with:

1. **Context-Aware Risk Assessment**
   - Evaluates real-world exploitability
   - Considers application context (from project profile)
   - Assesses actual impact based on architecture

2. **Root Cause Analysis**
   - Explains why something is vulnerable
   - Identifies underlying patterns
   - Finds related issues

3. **Remediation Guidance**
   - Provides specific code fixes
   - Suggests architectural improvements
   - Recommends best practices

4. **OWASP Top 10 Coverage**
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

## Example Output

```markdown
# Security Review Report

## Project Context
- **Project**: my-app
- **Type**: web-app
- **Architecture**: monolith
- **Primary Language**: TypeScript
- **Frameworks**: React 18.x, Express 4.x

## Executive Summary
- Total issues found: 12
- Critical: 1 | High: 3 | Medium: 5 | Low: 3
- Overall risk: HIGH - Critical vulnerability requires immediate attention

## Patterns Checked
Based on project profile:
- [x] JavaScript/TypeScript patterns (15 rules)
- [x] React-specific vulnerabilities (3 rules)
- [x] Express middleware issues (5 rules)
- [x] JWT authentication (4 rules)
- [x] Secrets detection (7 patterns)

## Critical Findings

### SQL Injection in User Query
**File**: `src/db/users.js:45`
**Tool**: Semgrep (security/sql-injection)
**CWE**: CWE-89

**Issue**: User input directly concatenated into SQL query
**Code**:
```javascript
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

**Risk**: An attacker can manipulate the userId parameter to execute
arbitrary SQL commands, potentially accessing or modifying all data.

**Remediation**:
```javascript
const query = 'SELECT * FROM users WHERE id = ?';
const [rows] = await connection.execute(query, [userId]);
```

## Files Reviewed
| File | Reason | Issues Found |
|------|--------|--------------|
| src/auth/jwt.ts | Authentication logic | 2 |
| src/middleware/auth.ts | Request processing | 1 |
| config/config.yaml | Configuration | 0 |

## Recommendations
1. **Immediate**: Fix SQL injection vulnerability
2. **Short-term**: Add input validation layer
3. **Long-term**: Implement ORM or query builder
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Review
  run: |
    claude "/codacy-security-review:security-review --sarif"
    # Upload SARIF to GitHub Security
```

### Pre-commit Hook
```bash
#!/bin/sh
claude "/codacy-security-review:quick-scan --staged"
```

### VS Code Task
```json
{
  "label": "Security Scan Current File",
  "type": "shell",
  "command": "claude",
  "args": ["/codacy-security-review:quick-scan", "${file}"]
}
```

## Configuration

The plugin uses Codacy CLI v2's configuration in `.codacy/`:

- `.codacy/codacy.yaml` - Main Codacy configuration
- `.codacy/project-profile.yaml` - **Project structure and metadata (NEW)**
- `.codacy/security-patterns.yaml` - **Custom security patterns (NEW)**
- `.codacy/tools-configs/` - Tool-specific settings
- `.codacy/tools-configs/languages-config.yaml` - Language detection

### Customizing Security Patterns

After setup, you can customize `.codacy/security-patterns.yaml`:

```yaml
# Enable/disable framework-specific patterns
react:
  enabled: true  # Set to false if not using React

# Adjust severity levels
javascript_typescript:
  high:
    - pattern: "eval\\s*\\("
      severity: "critical"  # Upgrade from high to critical

# Add custom patterns
project_specific:
  custom:
    - pattern: "UNSAFE_"
      severity: "high"
      description: "Custom unsafe prefix pattern"
```

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [Codacy CLI v2](https://github.com/codacy/codacy-cli-v2)
- [Claude Code](https://claude.ai/claude-code)
- [OWASP Top 10](https://owasp.org/Top10/)
