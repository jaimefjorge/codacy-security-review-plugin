---
name: setup
description: Initialize and configure Codacy CLI v2 for security analysis in your project. Detects languages, installs required tools, and sets up configuration.
argument-hint: "[--remote] [--force]"
---

# Codacy CLI v2 Setup with Project Profiling

You are helping the user set up Codacy CLI v2 for security analysis in their project. This setup includes comprehensive project profiling to optimize future security analysis.

## Arguments

The user may provide: `$ARGUMENTS`

- `--remote`: Configure with Codacy cloud integration (requires API token)
- `--force`: Force re-initialization even if already configured

## Setup Workflow

### Step 1: Check Prerequisites

First, verify Codacy CLI v2 is installed. **IMPORTANT**: The binary name is `codacy-cli-v2` (not `codacy-cli`).

Check for existing installation:
```bash
# Check common locations - the binary is named codacy-cli-v2
codacy-cli-v2 version 2>/dev/null || ~/.local/bin/codacy-cli-v2 version 2>/dev/null
```

If not installed, **use direct GitHub release download** (most reliable method):

```bash
# 1. Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && ARCH="arm64"

# 2. Map OS names (Darwin -> darwin for macOS)
[[ "$OS" == "darwin" ]] && OS="darwin"
[[ "$OS" == "linux" ]] && OS="linux"

# 3. Get latest release download URL
DOWNLOAD_URL=$(curl -sL "https://api.github.com/repos/codacy/codacy-cli-v2/releases/latest" | grep -o "https://github.com/codacy/codacy-cli-v2/releases/download/[^\"]*${OS}_${ARCH}.tar.gz" | head -1)

# 4. Download and install to ~/.local/bin
mkdir -p ~/.local/bin
curl -L "$DOWNLOAD_URL" -o /tmp/codacy-cli-v2.tar.gz
tar -xzf /tmp/codacy-cli-v2.tar.gz -C ~/.local/bin
rm /tmp/codacy-cli-v2.tar.gz

# 5. Verify installation
~/.local/bin/codacy-cli-v2 version
```

### Step 2: Project Profiling (CRITICAL - Do This Before Codacy Init)

Before running Codacy initialization, perform comprehensive project analysis to create a project profile. This profile will dramatically improve future security analysis.

#### 2.1 Analyze Directory Structure

Use Glob and Read tools to understand the project:

```
# Find all source directories and key files
- Look for: src/, lib/, app/, pkg/, cmd/, internal/, components/, pages/, routes/, api/, services/, utils/, helpers/, models/, controllers/, views/
- Look for config files: package.json, pyproject.toml, Cargo.toml, go.mod, pom.xml, build.gradle, Gemfile, composer.json
- Look for CI/CD: .github/workflows/, .gitlab-ci.yml, Jenkinsfile, .circleci/, azure-pipelines.yml
- Look for containerization: Dockerfile, docker-compose.yml, kubernetes/, helm/
- Look for infrastructure: terraform/, cloudformation/, pulumi/
```

#### 2.2 Detect Languages and Versions

Identify all programming languages by examining:
- File extensions: `.js`, `.ts`, `.py`, `.go`, `.rs`, `.java`, `.rb`, `.php`, `.cs`, `.swift`, `.kt`
- Package managers and their lock files
- Configuration files specifying language versions

#### 2.3 Detect Frameworks and Libraries

**JavaScript/TypeScript:**
- Check `package.json` for: react, vue, angular, next, nuxt, express, fastify, koa, nest, hapi, electron, react-native
- Look for framework-specific files: `next.config.js`, `nuxt.config.js`, `angular.json`, `vue.config.js`

**Python:**
- Check `requirements.txt`, `pyproject.toml`, `setup.py` for: django, flask, fastapi, tornado, pyramid, aiohttp, sanic
- Look for framework-specific files: `manage.py` (Django), `app.py` (Flask)

**Go:**
- Check `go.mod` for: gin, echo, fiber, chi, gorilla/mux, beego

**Java:**
- Check `pom.xml` or `build.gradle` for: spring-boot, spring-security, jakarta, quarkus, micronaut

**Ruby:**
- Check `Gemfile` for: rails, sinatra, hanami

**PHP:**
- Check `composer.json` for: laravel, symfony, codeigniter, yii

#### 2.4 Detect Architecture Patterns

Identify the application architecture:
- **Monolith**: Single package.json/go.mod at root, all code in one structure
- **Microservices**: Multiple services directories, docker-compose with multiple services
- **Serverless**: serverless.yml, SAM template, Lambda handlers
- **API-only**: No frontend files, only API routes/handlers
- **Full-stack**: Both frontend (React/Vue/Angular) and backend code
- **Library/Package**: Focus on exports, minimal application code
- **CLI Tool**: Main entry point with command parsing

#### 2.5 Identify Security-Relevant Components

Look for:
- **Authentication**: auth/, login, oauth, jwt, passport, session
- **Database access**: models/, repositories/, ORM configs, raw SQL patterns
- **File handling**: upload, download, file storage, S3
- **External APIs**: HTTP clients, API integrations, webhooks
- **Cryptography**: crypto usage, key management, encryption
- **User input handling**: forms, parsers, validators

### Step 3: Generate Project Profile

After analysis, create `.codacy/project-profile.yaml`:

```yaml
# Auto-generated by Codacy Security Review Setup
# Last updated: <timestamp>

project:
  name: "<detected or directory name>"
  type: "<web-app|api|library|cli|mobile|desktop>"
  architecture: "<monolith|microservices|serverless|monorepo>"

languages:
  primary: "<main language>"
  all:
    - name: "javascript"
      version: "ES2022"  # from tsconfig or package.json engines
      files_count: 150
      percentage: 45
    - name: "typescript"
      version: "5.x"
      files_count: 200
      percentage: 55

frameworks:
  - name: "react"
    version: "18.x"
    type: "frontend"
  - name: "express"
    version: "4.x"
    type: "backend"
  - name: "prisma"
    version: "5.x"
    type: "orm"

structure:
  source_directories:
    - "src/"
    - "lib/"
  test_directories:
    - "tests/"
    - "__tests__/"
  config_directories:
    - "config/"
    - ".config/"
  has_ci_cd: true
  has_docker: true
  has_infrastructure_as_code: false

security_components:
  authentication:
    present: true
    type: "jwt"
    files:
      - "src/auth/jwt.ts"
      - "src/middleware/auth.ts"
  database:
    present: true
    type: "orm"
    orm: "prisma"
    files:
      - "prisma/schema.prisma"
      - "src/repositories/"
  file_handling:
    present: true
    files:
      - "src/services/upload.ts"
  external_apis:
    present: true
    files:
      - "src/integrations/"
  user_input:
    entry_points:
      - "src/routes/"
      - "src/controllers/"

dependencies:
  package_manager: "npm"
  lock_file: "package-lock.json"
  has_audit_support: true
```

### Step 4: Generate Security Patterns

Based on the profile, create `.codacy/security-patterns.yaml` with project-specific security checks:

```yaml
# Auto-generated security patterns specific to this project
# Based on: languages, frameworks, architecture detected

metadata:
  generated_at: "<timestamp>"
  codacy_version: "<version>"
  profile_hash: "<hash of project-profile.yaml>"

# ============================================
# LANGUAGE-SPECIFIC PATTERNS
# ============================================

javascript_typescript:
  enabled: true
  critical:
    - pattern: "eval\\s*\\("
      description: "Avoid eval() - code injection risk"
      cwe: "CWE-95"
      remediation: "Use JSON.parse() for data, or safer alternatives"

    - pattern: "innerHTML\\s*="
      description: "innerHTML can lead to XSS"
      cwe: "CWE-79"
      remediation: "Use textContent or sanitize with DOMPurify"

    - pattern: "document\\.write\\s*\\("
      description: "document.write can be exploited for XSS"
      cwe: "CWE-79"
      remediation: "Use DOM manipulation methods instead"

    - pattern: "new Function\\s*\\("
      description: "Dynamic function creation is dangerous"
      cwe: "CWE-95"
      remediation: "Avoid dynamic code execution"

  high:
    - pattern: "dangerouslySetInnerHTML"
      description: "React's dangerouslySetInnerHTML bypasses XSS protection"
      cwe: "CWE-79"
      remediation: "Sanitize content with DOMPurify before use"
      frameworks: ["react"]

    - pattern: "\\$\\{.*\\}.*sql|sql.*\\$\\{"
      description: "Potential SQL injection via template literals"
      cwe: "CWE-89"
      remediation: "Use parameterized queries"

    - pattern: "child_process\\.exec\\s*\\("
      description: "shell command execution risk"
      cwe: "CWE-78"
      remediation: "Use execFile with explicit arguments array"

    - pattern: "res\\.redirect\\s*\\([^)]*req\\."
      description: "Open redirect vulnerability"
      cwe: "CWE-601"
      remediation: "Validate redirect URLs against allowlist"
      frameworks: ["express"]

  medium:
    - pattern: "Math\\.random\\s*\\("
      description: "Math.random is not cryptographically secure"
      cwe: "CWE-330"
      remediation: "Use crypto.randomBytes() or crypto.getRandomValues()"

    - pattern: "localStorage\\.setItem|sessionStorage\\.setItem"
      description: "Storing sensitive data in browser storage"
      cwe: "CWE-922"
      remediation: "Avoid storing sensitive data; use httpOnly cookies"

    - pattern: "cors\\s*\\(\\s*\\)"
      description: "CORS with no options allows all origins"
      cwe: "CWE-942"
      remediation: "Specify allowed origins explicitly"
      frameworks: ["express"]

python:
  enabled: true
  critical:
    - pattern: "exec\\s*\\(|eval\\s*\\("
      description: "Code execution from string"
      cwe: "CWE-95"
      remediation: "Avoid exec/eval; use ast.literal_eval for data"

    - pattern: "pickle\\.loads?\\s*\\("
      description: "Pickle deserialization is unsafe with untrusted data"
      cwe: "CWE-502"
      remediation: "Use JSON or other safe serialization formats"

    - pattern: "subprocess\\..*shell\\s*=\\s*True"
      description: "Shell=True enables command injection"
      cwe: "CWE-78"
      remediation: "Use shell=False with list of arguments"

    - pattern: "\\.format\\s*\\(.*\\).*SELECT|SELECT.*\\.format\\s*\\("
      description: "SQL injection via string formatting"
      cwe: "CWE-89"
      remediation: "Use parameterized queries"

  high:
    - pattern: "yaml\\.load\\s*\\([^)]*Loader\\s*=\\s*None"
      description: "Unsafe YAML loading"
      cwe: "CWE-502"
      remediation: "Use yaml.safe_load()"

    - pattern: "hashlib\\.md5\\s*\\(|hashlib\\.sha1\\s*\\("
      description: "Weak hash algorithm"
      cwe: "CWE-328"
      remediation: "Use SHA-256 or stronger"

    - pattern: "os\\.system\\s*\\("
      description: "OS command execution"
      cwe: "CWE-78"
      remediation: "Use subprocess with list arguments"

    - pattern: "@app\\.route.*methods.*POST(?!.*csrf)"
      description: "POST endpoint may lack CSRF protection"
      cwe: "CWE-352"
      remediation: "Enable CSRF protection in Flask-WTF"
      frameworks: ["flask"]

  medium:
    - pattern: "DEBUG\\s*=\\s*True"
      description: "Debug mode enabled"
      cwe: "CWE-489"
      remediation: "Disable debug in production"

    - pattern: "random\\.(random|randint|choice)\\s*\\("
      description: "Non-cryptographic random"
      cwe: "CWE-330"
      remediation: "Use secrets module for security-sensitive randomness"

    - pattern: "except:\\s*$|except Exception:"
      description: "Bare except may hide errors"
      cwe: "CWE-755"
      remediation: "Catch specific exception types"

go:
  enabled: true
  critical:
    - pattern: "fmt\\.Sprintf.*%s.*sql|sql.*fmt\\.Sprintf.*%s"
      description: "SQL injection via string formatting"
      cwe: "CWE-89"
      remediation: "Use parameterized queries"

    - pattern: "exec\\.Command\\s*\\([^,)]+\\+|\\+[^,)]+exec\\.Command"
      description: "Command injection via string concatenation"
      cwe: "CWE-78"
      remediation: "Pass arguments as separate parameters"

  high:
    - pattern: "http\\.ListenAndServe\\s*\\([^)]*nil\\s*\\)"
      description: "Using default ServeMux is less secure"
      cwe: "CWE-16"
      remediation: "Use custom mux with proper middleware"

    - pattern: "ioutil\\.ReadAll\\s*\\("
      description: "Unbounded read can cause DoS"
      cwe: "CWE-400"
      remediation: "Use io.LimitReader"

    - pattern: "template\\.HTML\\s*\\("
      description: "Bypasses HTML escaping"
      cwe: "CWE-79"
      remediation: "Only use with trusted, sanitized content"

# ============================================
# FRAMEWORK-SPECIFIC PATTERNS
# ============================================

react:
  enabled: false  # Set to true if React detected
  patterns:
    - pattern: "dangerouslySetInnerHTML"
      severity: "high"
      description: "XSS risk - bypasses React's escaping"
      remediation: "Sanitize with DOMPurify: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}}"

    - pattern: "useEffect\\s*\\([^)]*\\[\\s*\\]\\s*\\)"
      severity: "low"
      description: "Empty dependency array - runs only on mount"
      remediation: "Ensure this is intentional; add dependencies if needed"

    - pattern: "href\\s*=\\s*\\{.*\\}"
      severity: "medium"
      description: "Dynamic href can enable javascript: URLs"
      remediation: "Validate URLs or use react-router Link"

express:
  enabled: false  # Set to true if Express detected
  patterns:
    - pattern: "app\\.use\\s*\\(\\s*express\\.static\\s*\\("
      severity: "medium"
      description: "Static file serving - check path traversal"
      remediation: "Ensure proper path validation; use helmet"

    - pattern: "req\\.query|req\\.params|req\\.body"
      severity: "info"
      description: "User input - validate and sanitize"
      remediation: "Use validation library like express-validator"

    - pattern: "res\\.send\\s*\\(.*req\\."
      severity: "high"
      description: "Reflecting user input - XSS risk"
      remediation: "Sanitize before reflecting; use proper content-type"

nextjs:
  enabled: false  # Set to true if Next.js detected
  patterns:
    - pattern: "getServerSideProps.*headers"
      severity: "medium"
      description: "Exposing server headers to client"
      remediation: "Filter sensitive headers before passing to page"

    - pattern: "dangerouslySetInnerHTML"
      severity: "high"
      description: "XSS in SSR context is especially dangerous"
      remediation: "Sanitize on server side before rendering"

django:
  enabled: false  # Set to true if Django detected
  patterns:
    - pattern: "\\|\\s*safe"
      severity: "high"
      description: "Django safe filter bypasses escaping"
      remediation: "Only use with content you've sanitized"

    - pattern: "ALLOWED_HOSTS\\s*=\\s*\\[\\s*['\"]\\*['\"]"
      severity: "high"
      description: "Wildcard allowed hosts"
      remediation: "Specify exact allowed hostnames"

    - pattern: "raw\\s*\\(|extra\\s*\\("
      severity: "high"
      description: "Raw SQL in Django ORM"
      remediation: "Use parameterized queries with %s placeholders"

flask:
  enabled: false  # Set to true if Flask detected
  patterns:
    - pattern: "\\|\\s*safe"
      severity: "high"
      description: "Jinja2 safe filter bypasses escaping"
      remediation: "Sanitize content before marking as safe"

    - pattern: "send_file\\s*\\("
      severity: "medium"
      description: "File serving - check for path traversal"
      remediation: "Use safe_join() for path construction"

    - pattern: "app\\.secret_key\\s*=\\s*['\"][^'\"]{0,20}['\"]"
      severity: "high"
      description: "Weak or hardcoded secret key"
      remediation: "Use strong random key from environment variable"

fastapi:
  enabled: false  # Set to true if FastAPI detected
  patterns:
    - pattern: "Response\\s*\\(.*content.*media_type.*html"
      severity: "medium"
      description: "HTML response - ensure proper escaping"
      remediation: "Use templates with auto-escaping"

    - pattern: "allow_origins\\s*=\\s*\\[\\s*['\"]\\*['\"]"
      severity: "high"
      description: "CORS allows all origins"
      remediation: "Specify allowed origins explicitly"

spring:
  enabled: false  # Set to true if Spring detected
  patterns:
    - pattern: "@RequestParam.*required\\s*=\\s*false"
      severity: "low"
      description: "Optional parameter - ensure null handling"
      remediation: "Add null checks or use Optional"

    - pattern: "ResponseEntity\\.ok\\s*\\(.*\\+.*\\)"
      severity: "medium"
      description: "String concatenation in response - XSS risk"
      remediation: "Return proper objects; use content type"

# ============================================
# PROJECT-SPECIFIC PATTERNS
# (These are generated based on detected components)
# ============================================

project_specific:
  # Authentication patterns (if auth detected)
  authentication:
    enabled: false
    jwt:
      - pattern: "algorithm.*none|none.*algorithm"
        severity: "critical"
        description: "JWT none algorithm attack"
        remediation: "Always specify and validate algorithm"

      - pattern: "verify\\s*[=:]\\s*false|verify.*False"
        severity: "critical"
        description: "JWT signature verification disabled"
        remediation: "Always verify JWT signatures"

      - pattern: "expiresIn.*['\"]\\d+d['\"]|exp.*\\+.*86400.*\\*.*[7-9]|exp.*\\+.*604800"
        severity: "medium"
        description: "Long-lived JWT tokens (7+ days)"
        remediation: "Use short-lived access tokens with refresh tokens"

    session:
      - pattern: "httpOnly\\s*[=:]\\s*false"
        severity: "high"
        description: "Cookie without httpOnly flag"
        remediation: "Set httpOnly: true for session cookies"

      - pattern: "secure\\s*[=:]\\s*false"
        severity: "high"
        description: "Cookie without secure flag"
        remediation: "Set secure: true in production"

  # Database patterns (if database detected)
  database:
    enabled: false
    patterns:
      - pattern: "\\$\\{|\\$\\(|%s|%d|\\?"
        context: "near SQL keywords"
        severity: "high"
        description: "Potential SQL injection point"
        remediation: "Use ORM or parameterized queries"

  # File handling patterns (if file handling detected)
  file_handling:
    enabled: false
    patterns:
      - pattern: "\\.\\./"
        severity: "high"
        description: "Path traversal sequence"
        remediation: "Validate and normalize file paths"

      - pattern: "mimetype|content-type.*req\\.|req\\..*mimetype"
        severity: "medium"
        description: "User-controlled content type"
        remediation: "Validate against allowlist of types"

# ============================================
# FILES TO ALWAYS REVIEW
# (Security-critical files that deserve manual review)
# ============================================

critical_files:
  - pattern: "**/auth/**"
    reason: "Authentication logic"
  - pattern: "**/security/**"
    reason: "Security implementations"
  - pattern: "**/middleware/**"
    reason: "Request processing"
  - pattern: "**/config/**"
    reason: "Configuration including secrets"
  - pattern: "**/.env*"
    reason: "Environment variables"
  - pattern: "**/Dockerfile*"
    reason: "Container security"
  - pattern: "**/docker-compose*.yml"
    reason: "Service configuration"
  - pattern: "**/kubernetes/**"
    reason: "K8s security configs"
  - pattern: "**/terraform/**"
    reason: "Infrastructure security"

# ============================================
# SECRETS PATTERNS
# ============================================

secrets:
  patterns:
    - name: "AWS Access Key"
      pattern: "AKIA[0-9A-Z]{16}"
      severity: "critical"

    - name: "AWS Secret Key"
      pattern: "['\"][0-9a-zA-Z/+]{40}['\"]"
      context: "near AWS or aws"
      severity: "critical"

    - name: "GitHub Token"
      pattern: "gh[pousr]_[A-Za-z0-9_]{36,}"
      severity: "critical"

    - name: "Generic API Key"
      pattern: "api[_-]?key['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9]{20,}['\"]"
      severity: "high"

    - name: "JWT Secret"
      pattern: "jwt[_-]?secret['\"]?\\s*[:=]\\s*['\"][^'\"]+['\"]"
      severity: "critical"

    - name: "Database URL"
      pattern: "(mysql|postgres|mongodb)://[^\\s'\"]+"
      severity: "high"

    - name: "Private Key"
      pattern: "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
      severity: "critical"
```

### Step 5: Check Existing Configuration

Check if `.codacy/codacy.yaml` exists. If it does and `--force` was not provided, ask the user if they want to reconfigure.

### Step 6: Initialize Codacy Configuration

Run the appropriate initialization. Use `~/.local/bin/codacy-cli-v2` if not in PATH:

**Local mode (default):**
```bash
~/.local/bin/codacy-cli-v2 init
```

**Remote mode (if `--remote` specified):**
Ask the user for:
- API token (or check for `CODACY_API_TOKEN` environment variable)
- Provider (gh/gl/bb)
- Organization name
- Repository name

Then run:
```bash
~/.local/bin/codacy-cli-v2 init --api-token <token> --provider <provider> --organization <org> --repository <repo>
```

### Step 7: Discover Languages

Scan the project to auto-detect languages and configure appropriate tools:

```bash
~/.local/bin/codacy-cli-v2 config discover .
```

### Step 8: Install Dependencies

Install all required runtimes and analysis tools:

```bash
~/.local/bin/codacy-cli-v2 install
```

### Step 9: Enable Framework-Specific Patterns

After detecting frameworks, update `.codacy/security-patterns.yaml`:
- Set `enabled: true` for detected frameworks
- Set `enabled: true` for detected security components

### Step 10: Final Summary

Provide a comprehensive summary including:

```markdown
## Setup Complete

### Project Profile Created
- **Project Type**: <type>
- **Architecture**: <architecture>
- **Primary Language**: <language>

### Languages Detected
| Language | Version | Files | Percentage |
|----------|---------|-------|------------|
| TypeScript | 5.x | 200 | 55% |
| JavaScript | ES2022 | 150 | 45% |

### Frameworks Detected
- React 18.x (frontend)
- Express 4.x (backend)
- Prisma 5.x (ORM)

### Security Components Identified
- Authentication: JWT-based (src/auth/)
- Database: Prisma ORM
- File Handling: Upload service
- User Input: Routes and controllers

### Security Patterns Enabled
- JavaScript/TypeScript patterns: 15 rules
- React-specific patterns: 3 rules
- Express-specific patterns: 3 rules
- Authentication (JWT) patterns: 4 rules
- Secrets detection: 7 patterns

### Files Generated
- `.codacy/project-profile.yaml` - Project structure and metadata
- `.codacy/security-patterns.yaml` - Custom security patterns

### Codacy Tools Configured
<list from codacy.yaml>

### Next Steps
1. Review `.codacy/project-profile.yaml` and adjust if needed
2. Review `.codacy/security-patterns.yaml` and customize severity levels
3. Run `/codacy:security-review` for comprehensive analysis
4. Run `/codacy:quick-scan` for fast targeted scans

### Recommended Git Actions
```bash
# Add to version control (optional but recommended)
git add .codacy/project-profile.yaml .codacy/security-patterns.yaml
git commit -m "Add Codacy security configuration"
```
```

## Error Handling

- If installation fails, suggest checking Docker availability (some tools require it)
- If language detection finds nothing, suggest checking if the project has source files
- If remote mode fails, verify API token permissions

## Profile Maintenance

The project profile should be regenerated when:
- Major refactoring occurs
- New frameworks are added
- Architecture changes significantly

Run `/codacy:setup --force` to regenerate the profile.
