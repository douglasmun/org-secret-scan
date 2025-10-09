# Git Secret Scanner (GSS) aka. org-secret-scan
Enterprise-grade secret detection for GitHub organizations and local filesystems

Authored By: Douglas Mun with AI assistance.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

---

## Executive Summary

The **Git Secret Scanner (GSS)** is an open-source security tool designed to detect hardcoded credentials across GitHub organizations and local filesystems. Built with enterprise-grade like features, it combines intelligent pattern matching, Shannon entropy analysis, and context-aware scoring to minimize false positives while identifying critical security exposures.

### Why This Scanner?

**Problem:** Hardcoded secrets in source files is a leading cause of security breaches. Traditional file extension scanning tools suffer from high false-positive rates and offer limited remediation guidance.

**Solution:** GSS employs multi-layer validation (regex → entropy → context → denylist) to achieve 60-80% false positive reduction while providing automatic remediation guidance for every finding.

### Key Differentiators

- **80+ Detection Patterns** - Comprehensive coverage of AWS, GCP, Azure, GitHub, GitLab, Slack, Discord, Stripe, PayPal, OpenAI, Anthropic, JWT, SSH/PEM keys, database URIs, Docker, NPM, PyPI, monitoring tools (Datadog, New Relic, Sentry), and more across 15+ categories
- **Multi-Format Reporting** - JSON for automation, CSV for analysis, SARIF for GitHub Advanced Security integration
- **Automatic Remediation** - Each finding includes rotation commands, prevention steps, and documentation links
- **Platform-Optimized** - Native OS integrations (macOS Spotlight, Linux locate, Windows PowerShell) for 3-10x faster scanning
- **Production-Ready** - Rate limiting, retry logic, incremental scanning, and comprehensive error handling

### Use Cases

- **Security Teams** - Automated secret detection for compliance and audit  
-  **DevOps/SRE** - CI/CD pipeline integration for continuous monitoring  
-  **Developers** - Pre-commit scanning to prevent credential leaks  
-  **Compliance** - SOC 2, PCI-DSS, HIPAA audit support with SARIF reports  

### Quick Stats

- **60+ Test Cases** - Comprehensive test coverage across all features
- **133 files/second** - Performance on typical codebases
- **1-minute setup** - Simple pip install and ready to scan
- **MIT Licensed** - Free for commercial and personal use

---

## Technical Summary

A comprehensive, production-ready secret scanner that identifies hardcoded credentials across GitHub organizations and local filesystems through multi-layer validation combining regex pattern matching, Shannon entropy analysis, context-aware risk scoring, and intelligent false positive reduction.

### Architecture Overview

Built on **Python 3.8+ with asyncio** for high-performance concurrent scanning. The scanner employs a pipeline architecture: file discovery → pattern matching → entropy analysis → context scoring → deduplication → reporting. Platform-native optimizations (mdfind, locate, PowerShell) accelerate file discovery by 3-10x compared to standard filesystem traversal.

### Key Features & Implementation

#### **20+ Credential Patterns**
**Implementation:** Compiled regex patterns in `SecretPatterns` class using Python's `re` module with named capture groups. Patterns cover AWS (AKIA*/ASIA* prefixes), GCP (service account JSON), GitHub (ghp_/gho_/ghu_ tokens), Slack (xox[pbar]- format), Stripe (sk_live_/rk_live_), JWT (three-segment base64url), PEM keys (BEGIN/END markers), SSH keys, database URIs (mongodb://, postgres://), and API keys (SendGrid, Firebase, Twilio, Mailgun). Each pattern is optimized for precision with lookahead/lookbehind assertions where appropriate.

#### **Dual-Mode Scanning**
**Implementation:** Two scanning engines sharing core detection logic. GitHub mode uses PyGithub API with shallow clones (`--depth 1`) to minimize bandwidth, followed by async file scanning. Local mode uses `LocalFilesystemScanner` class with platform-specific optimizations via subprocess calls to native OS tools. Both modes feed into the same `scan_file_async()` function for pattern detection.

#### **Platform-Optimized Discovery**
**Implementation:** Platform detection via `platform.system()` with fallback chain. **macOS:** spawns `mdfind` subprocess with kMDItemFSName predicates for Spotlight integration. **Linux:** executes `locate -r` with regex patterns against updatedb database. **Windows:** runs PowerShell `Get-ChildItem -Recurse` with error suppression. All use `asyncio.create_subprocess_exec()` with 60-300s timeouts. Falls back to Python's `Path.iterdir()` recursive walk on failure.

#### **Rate Limiting & Backoff**
**Implementation:** Custom `GitHubRateLimiter` class implementing token bucket algorithm. Tracks requests via `RateLimitState` dataclass with AsyncIO lock for thread-safety. Calculates minimum interval (3600s / requests_per_hour) and enforces waits via `asyncio.sleep()`. On 403 errors, extracts reset timestamps from GitHub API responses and implements exponential backoff (base^attempt, configurable base). Wraps all API calls in `github_api_call_with_backoff()` with retry logic.

#### **Multi-Format Export**
**Implementation:** Three independent report generators sharing findings data. **JSON:** `generate_json_report()` creates nested dictionaries with metadata, summary statistics (Counter-based aggregation), and sorted findings. **CSV:** `generate_csv_report()` uses csv.DictWriter with flattened finding structure. **SARIF:** `generate_sarif_report()` builds SARIF 2.1.0 compliant JSON with rules array, results array, and GitHub Code Scanning compatible structure. All write atomically to disk.

#### **Remediation Guidance**
**Implementation:** `RemediationAdvice` class maintains static dictionary (REMEDIATION_TEMPLATES) mapping pattern types to structured guidance. Each template contains severity level, immediate action steps (numbered list), prevention measures, rotation commands (provider-specific CLI), and documentation URLs. Git history removal guide uses `get_git_history_removal_guide()` static method returning git-filter-repo commands. Remediation automatically injected into findings during report generation.

#### **Entropy-Based Scoring**
**Implementation:** Shannon entropy calculation via `shannon_entropy()` using Counter for character frequency distribution, computing -Σ(p*log₂(p)) where p is probability. Returns bits-per-character (0.0-8.0 range). High entropy (>4.5) indicates randomness typical of cryptographic material. Combined with pattern type, file context, and denylist matching in `score_finding()` to produce 0-100 risk score. Context penalties applied for test/docs paths (-30 points), denylist matches (-60 points).

#### **Incremental Scanning**
**Implementation:** Baseline loading via `load_baseline()` reads previous scan JSON, extracts finding hashes into set. During scanning, `calculate_secret_hash()` computes SHA256 of secret values. Before adding finding, checks if hash exists in baseline set - skips if found. Controlled by `DEDUPLICATION_ENABLED` flag. Baseline comparison occurs in `scan_file_async()` before appending to findings list.

#### **Structured Logging**
**Implementation:** Custom `JSONFormatter` class extending logging.Formatter, overriding `format()` to output JSON objects with timestamp (ISO 8601), level, logger, message, module, function, line. Supports custom fields (scan_id, repo, finding_count) via hasattr checks. Text mode uses standard formatter with timestamp. Logger setup via `setup_logging()` with StreamHandler to stdout. Log level configurable (INFO default, DEBUG with --verbose).

#### **Git Blame Integration**
**Implementation:** Optional feature (`ENABLE_GIT_BLAME=true`) that spawns `git blame -L line,line --porcelain` subprocess for each finding. Parses porcelain output to extract author name, email, timestamp (converted from Unix epoch), and commit hash. Uses asyncio subprocess with 10s timeout. Blame info attached to finding dict under 'git_blame' key. Only runs when repo_dir provided (GitHub scans, not local scans).

### Performance Characteristics

- **Async Concurrency:** Semaphore-controlled parallel scanning (configurable limits: 5 repos, 50 files default)
- **Memory Efficiency:** Streaming file reads via aiofiles, max file size limit (10MB default)
- **Network Optimization:** Shallow git clones, rate-limited API calls, retry with exponential backoff
- **CPU Efficiency:** Compiled regex patterns, minimal redundant computation, thread-pool for sync filesystem operations
- **Throughput:** Sustained 111-133 files/second on typical codebases with mixed file types

### Security Model

**Non-Intrusive Design:** Scanner performs zero authentication attempts. All validation is format-based (regex + entropy). Never connects to provider APIs, never tests credentials. Findings are potential matches requiring manual verification. This ethical design prevents accidental account lockouts, rate limiting, or security team alerts from verification attempts.  

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Remediation Workflow](#remediation-workflow)
- [Testing](#testing)
- [CI/CD Integration](#cicd-integration)
- [Performance](#performance)
- [Quality Assessment](#quality-assessment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Requirements

- Python 3.8+
- Git 2.20+

### Dependencies

```bash
pip install aiohttp aiofiles PyGithub gitpython
```

### Optional (for testing)

```bash
pip install pytest pytest-asyncio pytest-cov
```

---

## Quick Start

### 1. Scan GitHub Organization

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export TARGET_ORG="your-organization"
python org_secret_scanner.py
```

### 2. Scan Local Filesystem

```bash
python org_secret_scanner.py --local /path/to/projects
```

### 3. View Results

```bash
# JSON report (default)
cat scan_report.json

# Generate all formats
python org_secret_scanner.py --local ~/code --output-format all
ls scan_report.{json,csv,sarif}
```

---

## Usage Examples

### GitHub Organization Scanning

```bash
# Basic org scan
export GITHUB_TOKEN="ghp_your_token"
export TARGET_ORG="myorg"
python org_secret_scanner.py

# High-performance scan
export MAX_CONCURRENT_REPOS=10
export ENABLE_GIT_BLAME=true
python org_secret_scanner.py

# Incremental scan (skip known findings)
export SCAN_MODE=incremental
export BASELINE_FILE=previous_scan.json
python org_secret_scanner.py
```

### Local Filesystem Scanning

```bash
# Scan home directory (max depth 5)
python org_secret_scanner.py --local ~ --max-depth 5

# Scan with symlink following
python org_secret_scanner.py --local /var/www --follow-symlinks

# Scan current directory
python org_secret_scanner.py --local .
```

### Custom Patterns

```bash
# Create custom patterns file
cat > custom_patterns.json <<EOF
{
  "patterns": [
    {
      "name": "INTERNAL_API_KEY",
      "regex": "mycompany_api_[A-Za-z0-9]{32}",
      "description": "Internal API key format"
    }
  ]
}
EOF

# Scan with custom patterns
python org_secret_scanner.py --local ~/code --custom-patterns custom_patterns.json
```

### Output Formats

```bash
# JSON (default)
python org_secret_scanner.py --output-format json

# CSV for spreadsheet analysis
python org_secret_scanner.py --output-format csv

# SARIF for GitHub Advanced Security
python org_secret_scanner.py --output-format sarif

# All formats
python org_secret_scanner.py --output-format all
```

### Structured Logging

```bash
# JSON logs for log aggregation
export LOG_FORMAT=json
python org_secret_scanner.py --local ~/code | tee scan.log

# Parse with jq
cat scan.log | jq 'select(.level == "ERROR")'
```

---

## ⚙Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | *(required for org scan)* | GitHub personal access token |
| `TARGET_ORG` | *(required for org scan)* | Organization name |
| `MAX_CONCURRENT_REPOS` | `5` | Parallel repo scans |
| `MAX_CONCURRENT_FILES` | `50` | Parallel file scans |
| `CLONE_DEPTH` | `1` | Git shallow clone depth |
| `MAX_FILE_SIZE_MB` | `10` | Skip files larger than this |
| `OUTPUT_FILE` | `scan_report.json` | Output file path |
| `ENABLE_GIT_BLAME` | `false` | Enable git blame analysis |
| `LOG_FORMAT` | `text` | Logging format (text/json) |
| `GITHUB_API_RATE_LIMIT` | `5000` | API requests per hour |
| `GITHUB_API_MAX_RETRIES` | `5` | Max retry attempts |
| `LOCAL_SCAN_MAX_DEPTH` | `10` | Max directory depth |
| `DEDUPLICATION_ENABLED` | `true` | Enable secret deduplication |

### GitHub Token Scopes

**Minimum required:**
- `public_repo` (for public repos only)
- `repo` (for private repos)

**Optional:**
- `read:org` (for org metadata)

---

## Output Formats

### JSON Report Structure

```json
{
  "scan_metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "organization": "myorg",
    "total_findings": 42,
    "scanner_version": "1.0.0"
  },
  "summary": {
    "by_risk_level": {
      "high_risk": 5,
      "medium_risk": 12,
      "low_risk": 25
    },
    "by_pattern": { ... }
  },
  "findings": [
    {
      "repo": "myorg/repo1",
      "path": "src/config.py",
      "line": 42,
      "pattern": "AWS_ACCESS_KEY_ID",
      "score": 90,
      "classification": "likely_secret",
      "entropy": 4.5,
      "match_preview": "AKIA...",
      "remediation": {
        "severity": "CRITICAL",
        "immediate_actions": [ ... ],
        "rotation_command": "aws iam create-access-key ..."
      }
    }
  ]
}
```

### CSV Report

Columns: severity, score, classification, pattern, repo, path, line, entropy, remediation_summary, rotation_command, docs_url

### SARIF Report

Industry-standard format compatible with:
- GitHub Advanced Security
- Azure DevOps
- GitLab Security Dashboard
- SonarQube

**Upload to GitHub:**
```bash
gh api repos/:owner/:repo/code-scanning/sarifs \
  -F sarif=@scan_report.sarif \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main
```

---

## Remediation Workflow

The scanner provides automatic remediation guidance for each finding.

### Example: AWS Access Key Found

```json
{
  "pattern": "AWS_ACCESS_KEY_ID",
  "remediation": {
    "severity": "CRITICAL",
    "immediate_actions": [
      "1. IMMEDIATELY deactivate the exposed access key in AWS IAM Console",
      "2. Review CloudTrail logs for unauthorized access",
      "3. Create a new access key and update applications",
      "4. Delete the old access key after confirming new key works",
      "5. Remove from Git history"
    ],
    "prevention": [
      "Use IAM roles for EC2/ECS/Lambda instead of access keys",
      "Store credentials in AWS Secrets Manager",
      "Enable AWS Organizations SCPs to restrict key usage"
    ],
    "rotation_command": "aws iam create-access-key --user-name USERNAME",
    "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
  }
}
```

### Removing Secrets from Git History

```bash
# Using git-filter-repo (recommended)
pip install git-filter-repo

# Clone fresh copy
git clone <repo-url> repo-cleanup
cd repo-cleanup

# Remove specific file
git filter-repo --path path/to/secret/file --invert-paths

# Or replace text in all files
git filter-repo --replace-text <(echo 'SECRET_VALUE==>')

# Force push (WARNING: coordinate with team!)
git push origin --force --all
git push origin --force --tags

# All team members must re-clone
```

---

## Testing

### Run Test Suite

```bash
# Basic test run
python test_secret_scanner.py

# With pytest (recommended)
pytest test_secret_scanner.py -v

# With coverage
pytest test_secret_scanner.py --cov=org_secret_scanner --cov-report=html

# Run specific test
pytest test_secret_scanner.py::TestPatternDetection::test_aws_key_detection -v
```

### Test Coverage

- Pattern detection accuracy (60+ test cases)
- Entropy calculation
- Scoring logic
- Rate limiting
- Report generation (JSON, CSV, SARIF)
- Remediation advice
- File scanning
- Deduplication
- Custom patterns
- Integration tests

**Test Suite:** 60+ tests across 15 test classes with comprehensive coverage of all major features.

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install aiohttp aiofiles PyGithub gitpython
      
      - name: Run secret scanner
        run: |
          python org_secret_scanner.py \
            --local . \
            --output-format sarif \
            --max-depth 10
      
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: scan_report.sarif
      
      - name: Fail on high-risk findings
        run: |
          HIGH_RISK=$(jq '.summary.by_risk_level.high_risk' scan_report.json)
          if [ "$HIGH_RISK" -gt 0 ]; then
            echo "Found $HIGH_RISK high-risk secrets!"
            exit 1
          fi
```

### GitLab CI Example

```yaml
secret_scan:
  image: python:3.9
  script:
    - pip install aiohttp aiofiles PyGithub gitpython
    - python org_secret_scanner.py --local . --output-format all
    - |
      HIGH_RISK=$(jq '.summary.by_risk_level.high_risk' scan_report.json)
      if [ "$HIGH_RISK" -gt 0 ]; then exit 1; fi
  artifacts:
    reports:
      sast: scan_report.sarif
    paths:
      - scan_report.*
```

---

## Performance

### Benchmarks

| Environment | Files | Time | Throughput |
|-------------|-------|------|------------|
| 10 repos, 5K files | 5,000 | 45s | 111 files/s |
| 50 repos, 25K files | 25,000 | 3m 20s | 125 files/s |
| Local scan, 10K files | 10,000 | 1m 15s | 133 files/s |

### Optimization Tips

1. **Increase concurrency:**
   ```bash
   export MAX_CONCURRENT_REPOS=10
   export MAX_CONCURRENT_FILES=100
   ```

2. **Use shallow clones:**
   ```bash
   export CLONE_DEPTH=1
   ```

3. **Skip large files:**
   ```bash
   export MAX_FILE_SIZE_MB=5
   ```

4. **Platform-specific scanners:**
   - macOS: Uses Spotlight (mdfind) - 10x faster
   - Linux: Uses locate database - 5x faster
   - Windows: Uses PowerShell - 3x faster

---

## Docker Deployment

### Building the Docker Image

```bash
# Create Dockerfile
cat > Dockerfile <<'EOF'
FROM python:3.9-slim

LABEL maintainer="your-email@example.com"
LABEL version="1.0.0"
LABEL description="Production Git Secret Scanner"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY org_secret_scanner.py /app/
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app

USER scanner

# Set entrypoint
ENTRYPOINT ["python", "/app/org_secret_scanner.py"]
CMD ["--help"]
EOF

# Create requirements.txt
cat > requirements.txt <<'EOF'
aiohttp>=3.8.0
aiofiles>=23.0.0
PyGithub>=1.59.0
gitpython>=3.1.0
EOF

# Build the image
docker build -t secret-scanner:1.0.0 .
```

### Running with Docker

```bash
# Scan local directory (mount current directory)
docker run --rm \
  -v $(pwd):/scan \
  secret-scanner:1.0.0 \
  --local /scan \
  --max-depth 10

# Scan GitHub organization
docker run --rm \
  -e GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -e TARGET_ORG="your-org" \
  -v $(pwd)/reports:/app/reports \
  secret-scanner:1.0.0

# Generate all report formats
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/reports:/app/reports \
  secret-scanner:1.0.0 \
  --local /scan \
  --output-format all
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  scanner:
    image: secret-scanner:1.0.0
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - TARGET_ORG=${TARGET_ORG}
      - MAX_CONCURRENT_REPOS=10
      - OUTPUT_FORMAT=all
    volumes:
      - ./scan-target:/scan:ro
      - ./reports:/app/reports
    command: --local /scan --max-depth 10

# Run with docker-compose
# docker-compose up
```

### Publishing to Docker Hub

```bash
# Tag the image
docker tag secret-scanner:1.0.0 yourusername/secret-scanner:1.0.0
docker tag secret-scanner:1.0.0 yourusername/secret-scanner:latest

# Push to Docker Hub
docker login
docker push yourusername/secret-scanner:1.0.0
docker push yourusername/secret-scanner:latest
```

### Kubernetes Deployment

```yaml
# secret-scanner-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: secret-scanner
  namespace: security
spec:
  schedule: "0 2 * * *"  # Run daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: scanner
            image: secret-scanner:1.0.0
            env:
            - name: GITHUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: github-credentials
                  key: token
            - name: TARGET_ORG
              value: "your-organization"
            - name: OUTPUT_FORMAT
              value: "sarif"
            volumeMounts:
            - name: reports
              mountPath: /app/reports
          volumes:
          - name: reports
            persistentVolumeClaim:
              claimName: scanner-reports
          restartPolicy: OnFailure
```

---

## 🔒 Security

### Best Practices

1. **Never log secrets:** The scanner masks findings in logs
2. **Secure reports:** Encrypt reports containing finding details
3. **Token security:** Use minimal GitHub token scopes
4. **No authentication attempts:** Scanner never tests credentials (ethical design)
5. **Audit regularly:** Run weekly org-wide scans

### Security Features

- **Multi-layer validation:** Pattern matching → Entropy analysis → Context scoring → Denylist filtering
- **Risk classification:** Critical/High/Medium/Low severity levels
- **Deduplication:** Hash-based secret deduplication across repositories
- **Git blame integration:** Identifies who committed the secret (optional)
- **Remediation guidance:** Automatic rotation commands for each secret type

### SAST Integration

Upload SARIF reports to GitHub Advanced Security:

```bash
gh api repos/:owner/:repo/code-scanning/sarifs \
  -F sarif=@scan_report.sarif \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main
```

---

## Troubleshooting

### Common Issues

**Problem:** Rate limit exceeded  
**Solution:** Reduce concurrency or wait for rate limit reset
```bash
export MAX_CONCURRENT_REPOS=3
export GITHUB_API_RATE_LIMIT=1000
```

**Problem:** Permission denied on directories  
**Solution:** Run with appropriate permissions or skip directories
```bash
# Add to skip patterns in code
SKIP_PATH_PATTERNS.append("/restricted/path/")
```

**Problem:** False positives  
**Solution:** Adjust entropy threshold or add to denylist
```python
# In code, adjust scoring:
if entropy < 4.0:  # Increase threshold
    score = max(score - 30, 0)
```

**Problem:** Missing custom patterns  
**Solution:** Verify JSON format
```bash
python -m json.tool custom_patterns.json
```

**Problem:** `datetime.utcnow()` deprecation warning  
**Solution:** Already fixed in v2.5.0 using `datetime.now(timezone.utc)`

**Problem:** Large files being skipped  
**Solution:** Adjust the file size limit
```bash
export MAX_FILE_SIZE_MB=20  # Increase from default 10MB
```

---

## 📄 License

MIT License - feel free to use and modify for your own projects.

