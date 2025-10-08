#!/usr/bin/env python3
"""
===================================================================
GIT SECRET SCANNER FOR GITHUB ORGANIZATIONS
===================================================================

Authored By: Douglas Mun with AI assistance.

PURPOSE:
    Comprehensive, low-noise secret detection across GitHub organizations
    AND local filesystems that identifies hardcoded credentials, scores 
    risk levels, and filters false positives using entropy analysis and 
    format validation.

FEATURES:
    ✓ Async I/O for parallel repo scanning (10x faster than sync)
    ✓ Multi-pattern detection (80+ patterns: AWS, GCP, Azure, GitHub, GitLab, OpenAI, Anthropic, 
      Stripe, PayPal, Slack, Discord, NPM, PyPI, Docker, SSH/PEM keys, databases, monitoring tools)
    ✓ Multi-pattern detection (AWS, GCP, JWT, PEM, generic secrets)
    ✓ Entropy-based scoring to reduce false positives
    ✓ Format validation for cloud provider credentials
    ✓ Comprehensive error handling with retry logic
    ✓ Progress tracking and structured JSON reporting
    ✓ Timeout protection and memory-efficient streaming
    ✓ Graceful degradation on API failures
    ✓ Historical commit scanning with blame analysis
    ✓ Incremental scanning for CI/CD pipelines
    ✓ Webhook support for real-time PR scanning
    ✓ Multi-format output (JSON, CSV, SARIF)
    ✓ Secret deduplication across repos
    ✓ Custom regex pattern support
    ✓ LOCAL FILESYSTEM SCANNING with platform optimizations
    ✓ macOS Spotlight, Linux locate, Windows PowerShell integration
    ✓ Rate limiting & exponential backoff for GitHub API
    ✓ Structured JSON logging for observability
    ✓ Automatic remediation suggestions
    ✓ Secret rotation workflow guidance

DETECTION METHODS:
    1. Pattern matching (regex) for common secret formats
    2. Shannon entropy calculation (high-entropy = likely secret)
    3. Provider-specific format validation (AWS, GCP, Stripe, etc.)
    4. Context analysis (file paths, denylist terms)
    5. Non-intrusive verification (NO auth attempts)

SECURITY NOTICE:
    This scanner NEVER attempts to use discovered credentials.
    All verification is format-based only. Report findings to
    security teams immediately - do not test credentials.

REQUIREMENTS:
    Install dependencies:
        python3 -m pip install -r requirements.txt
    or 
        pip install aiohttp aiofiles PyGithub gitpython tqdm

USAGE:
    # Scan GitHub organization
    export GITHUB_TOKEN="ghp_your_token_here"
    export TARGET_ORG="your-org-name"
    python org_secret_scanner.py
    
    # Scan local filesystem
    python org_secret_scanner.py --local /path/to/scan
    python org_secret_scanner.py --local ~ --max-depth 10
    
    # Export in multiple formats
    python org_secret_scanner.py --output-format sarif
    python org_secret_scanner.py --output-format csv
    python org_secret_scanner.py --output-format all

CONFIGURATION:
    Set via environment variables:
    - GITHUB_TOKEN: GitHub personal access token (required for org scan)
    - TARGET_ORG: Organization name to scan (required for org scan)
    - MAX_CONCURRENT_REPOS: Parallel repo scans (default: 5)
    - CLONE_DEPTH: Git shallow clone depth (default: 1)
    - MAX_FILE_SIZE_MB: Skip files larger than this (default: 10)
    - OUTPUT_FILE: Report output path (default: scan_report.json)
    - SCAN_MODE: full|incremental|pr|local (default: full)
    - BASELINE_FILE: Path to baseline for incremental mode
    - CUSTOM_PATTERNS_FILE: Path to custom regex patterns JSON
    - LOG_FORMAT: text|json (default: text)

===================================================================
"""
import argparse
import asyncio
import csv
import hashlib
import json
import logging
import logging.handlers
import math
import os
import platform
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from tqdm import tqdm
from tqdm.asyncio import tqdm as async_tqdm
from typing import List, Dict, Any, Optional, Tuple, Set

# Third-party imports with error handling
try:
    from github import Github, Auth, GithubException, RateLimitExceededException
    import aiofiles
    import aiohttp
except ImportError as e:
    print(f"ERROR: Missing required dependency: {e}")
    print("Install with: pip install aiohttp aiofiles PyGithub gitpython")
    exit(1)

# ===================================================================
# CONFIGURATION & CONSTANTS
# ===================================================================

# Environment-driven configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
TARGET_ORG = os.environ.get("TARGET_ORG", "")
MAX_CONCURRENT_REPOS = int(os.environ.get("MAX_CONCURRENT_REPOS", "5"))
MAX_CONCURRENT_FILES = int(os.environ.get("MAX_CONCURRENT_FILES", "50"))
CLONE_DEPTH = int(os.environ.get("CLONE_DEPTH", "1"))
MAX_FILE_SIZE_MB = int(os.environ.get("MAX_FILE_SIZE_MB", "10"))
OUTPUT_FILE = Path(os.environ.get("OUTPUT_FILE", "scan_report.json"))
SCAN_MODE = os.environ.get("SCAN_MODE", "full")  # full|incremental|pr|local
BASELINE_FILE = Path(os.environ.get("BASELINE_FILE", "scan_baseline.json"))
CUSTOM_PATTERNS_FILE = os.environ.get("CUSTOM_PATTERNS_FILE", "")
OUTPUT_FORMAT = os.environ.get("OUTPUT_FORMAT", "json")  # json|csv|sarif|all
ENABLE_GIT_BLAME = os.environ.get("ENABLE_GIT_BLAME", "false").lower() == "true"
DEDUPLICATION_ENABLED = os.environ.get("DEDUPLICATION_ENABLED", "true").lower() == "true"
LOG_FORMAT = os.environ.get("LOG_FORMAT", "text")  # text|json

# Local scan configuration
LOCAL_SCAN_MAX_DEPTH = int(os.environ.get("LOCAL_SCAN_MAX_DEPTH", "10"))
LOCAL_SCAN_FOLLOW_SYMLINKS = os.environ.get("LOCAL_SCAN_FOLLOW_SYMLINKS", "false").lower() == "true"

# GitHub API rate limiting
GITHUB_API_RATE_LIMIT = int(os.environ.get("GITHUB_API_RATE_LIMIT", "5000"))  # requests per hour
GITHUB_API_BACKOFF_BASE = float(os.environ.get("GITHUB_API_BACKOFF_BASE", "2.0"))
GITHUB_API_MAX_RETRIES = int(os.environ.get("GITHUB_API_MAX_RETRIES", "5"))

# Operational constants
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
CLONE_TIMEOUT_SECONDS = 300
SCAN_TIMEOUT_SECONDS = 600
RETRY_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 2

# Path patterns to skip (performance + noise reduction)
SKIP_PATH_PATTERNS = [
    ".git/", "node_modules/", "vendor/", "dist/", "build/",
    ".venv/", "venv/", "__pycache__/", ".cache/", "target/",
    "*.min.js", "*.bundle.js", "package-lock.json", "yarn.lock"
]

# Denylist for known fake/example credentials
DENYLIST_TERMS = [
    "example", "changeme", "dummy", "redacted", "xxxxx",
    "testkey", "samplekey", "placeholder", "fake", "demo",
    "your_key_here", "insert_key_here", "replace_me"
]

# Binary file extensions to skip (performance optimization)
BINARY_FILE_EXTENSIONS = {
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff', '.psd',
    # Videos
    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.m4v',
    # Audio
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a',
    # Archives
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.xz', '.tgz',
    # Executables & Libraries
    '.exe', '.dll', '.so', '.dylib', '.bin', '.app', '.deb', '.rpm',
    # Compiled/Binary
    '.pyc', '.pyo', '.class', '.o', '.a', '.obj', '.lib',
    # Documents (binary formats)
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods',
    # Fonts
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    # Database
    '.db', '.sqlite', '.sqlite3', '.mdb',
    # Other
    '.iso', '.dmg', '.img', '.pickle', '.pkl', '.parquet',
}

# Binary detection
BINARY_SAMPLE_SIZE = 8192         # Bytes to read for binary detection (8KB)
BINARY_NON_TEXT_THRESHOLD = 0.30  # 30% non-text bytes threshold


# ===================================================================
# SCORING & ENTROPY THRESHOLDS in score_finding()
# ===================================================================

# Entropy thresholds (bits per character)
ENTROPY_THRESHOLD_CRITICAL = 5.0  # Very high entropy - likely cryptographic
ENTROPY_THRESHOLD_HIGH = 4.5      # High entropy - likely secret
ENTROPY_THRESHOLD_MEDIUM = 3.5    # Medium entropy - possible secret
ENTROPY_THRESHOLD_LOW = 2.0       # Low entropy - unlikely secret
MIN_ENTROPY_CALC_LENGTH = 2

# Risk score thresholds (0-100 scale)
SCORE_THRESHOLD_CRITICAL = 90     # Critical severity findings
SCORE_THRESHOLD_HIGH = 80         # High severity findings
SCORE_THRESHOLD_MEDIUM = 50       # Medium severity findings
SCORE_THRESHOLD_LOW = 30          # Low severity findings
SCORE_THRESHOLD_NOISE = 20        # Below this, likely noise

# Scoring adjustments
SCORE_PENALTY_TEST_FILE = 30      # Reduce score for test/example files
SCORE_PENALTY_DENYLIST = 60       # Severe penalty for denylisted terms
SCORE_MAX = 100                   # Maximum possible score

# Pattern-specific scores
SCORE_PEM_PRIVATE_KEY = 95
SCORE_SSH_PRIVATE_KEY = 95
SCORE_PKCS12_CERTIFICATE = 90
SCORE_CERTIFICATE = 40
SCORE_SSH_PUBLIC_KEY = 20
SCORE_CLOUD_API_KEY = 90          # AWS, Stripe, Slack, GitHub tokens
SCORE_AWS_SECRET_HIGH_ENTROPY = 85
SCORE_JWT_TOKEN = 70

# Value length thresholds
MIN_SECRET_LENGTH = 8             # Minimum length to consider as secret


# ===================================================================
# LOGGING SETUP
# ===================================================================

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(datetime.UTC).isoformat().replace('+00:00', 'Z'),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add custom fields
        if hasattr(record, 'scan_id'):
            log_data["scan_id"] = record.scan_id
        if hasattr(record, 'repo'):
            log_data["repo"] = record.repo
        if hasattr(record, 'finding_count'):
            log_data["finding_count"] = record.finding_count
            
        return json.dumps(log_data)


def setup_logging(log_format: str = "text") -> logging.Logger:
    """Setup logging with either text or JSON format."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    handler = logging.StreamHandler(sys.stdout)
    
    if log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
    
    logger.addHandler(handler)
    return logger


logger = setup_logging(LOG_FORMAT)

# ===================================================================
# RATE LIMITING & BACKOFF
# ===================================================================

@dataclass
class RateLimitState:
    """Track rate limit state for GitHub API."""
    requests_remaining: int = GITHUB_API_RATE_LIMIT
    reset_time: datetime = datetime.now()
    total_requests: int = 0
    total_waits: int = 0
    
    
class GitHubRateLimiter:
    """Rate limiter with exponential backoff for GitHub API."""
    
    def __init__(self, requests_per_hour: int = GITHUB_API_RATE_LIMIT):
        self.requests_per_hour = requests_per_hour
        self.min_interval = 3600.0 / requests_per_hour  # seconds between requests
        self.last_request_time = 0.0
        self.state = RateLimitState()
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request with rate limiting."""
        async with self.lock:
            now = time.time()
            
            # Calculate time to wait
            time_since_last = now - self.last_request_time
            if time_since_last < self.min_interval:
                wait_time = self.min_interval - time_since_last
                logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                self.state.total_waits += 1
            
            self.last_request_time = time.time()
            self.state.total_requests += 1
            self.state.requests_remaining -= 1
            
            # Reset counter every hour
            if datetime.now() >= self.state.reset_time:
                self.state.requests_remaining = self.requests_per_hour
                self.state.reset_time = datetime.now() + timedelta(hours=1)
    
    async def handle_rate_limit_error(self, reset_timestamp: Optional[int] = None):
        """Handle rate limit exceeded error with exponential backoff."""
        if reset_timestamp:
            wait_until = datetime.fromtimestamp(reset_timestamp)
            wait_seconds = (wait_until - datetime.now()).total_seconds()
        else:
            wait_seconds = 60  # Default 1 minute
        
        wait_seconds = max(wait_seconds, 1)  # At least 1 second
        logger.warning(f"Rate limit exceeded. Waiting {wait_seconds:.0f}s until reset")
        await asyncio.sleep(wait_seconds)
        
        # Reset state
        self.state.requests_remaining = self.requests_per_hour
        self.state.reset_time = datetime.now() + timedelta(hours=1)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.state.total_requests,
            "requests_remaining": self.state.requests_remaining,
            "total_waits": self.state.total_waits,
            "reset_time": self.state.reset_time.isoformat()
        }


# Global rate limiter instance
rate_limiter = GitHubRateLimiter()


async def github_api_call_with_backoff(func, *args, max_retries: int = GITHUB_API_MAX_RETRIES, **kwargs):
    """
    Execute GitHub API call with exponential backoff on rate limit errors.
    
    Args:
        func: Function to call (can be sync or async)
        *args: Positional arguments for func
        max_retries: Maximum number of retry attempts
        **kwargs: Keyword arguments for func
        
    Returns:
        Result of func call
        
    Raises:
        Exception if all retries exhausted
    """
    for attempt in range(max_retries):
        try:
            # Rate limit before request
            await rate_limiter.acquire()
            
            # Call function (handle both sync and async)
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            return result
            
        except RateLimitExceededException as e:
            if attempt == max_retries - 1:
                raise
            
            # Extract reset time if available
            reset_timestamp = None
            if hasattr(e, 'reset_time'):
                reset_timestamp = e.reset_time
            
            await rate_limiter.handle_rate_limit_error(reset_timestamp)
            
        except GithubException as e:
            if e.status == 403 and 'rate limit' in str(e).lower():
                if attempt == max_retries - 1:
                    raise
                
                wait_time = GITHUB_API_BACKOFF_BASE ** attempt
                logger.warning(f"GitHub API error (attempt {attempt + 1}/{max_retries}): {e}")
                logger.info(f"Backing off for {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
            else:
                raise
        
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            
            wait_time = GITHUB_API_BACKOFF_BASE ** attempt
            logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}): {e}")
            await asyncio.sleep(wait_time)
    
    raise Exception(f"Failed after {max_retries} attempts")


# ===================================================================
# REMEDIATION GUIDANCE
# ===================================================================

class RemediationAdvice:
    """Provides remediation guidance for different secret types."""
    
    REMEDIATION_TEMPLATES = {
        "PEM_PRIVATE_KEY": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "1. IMMEDIATELY rotate the private key - generate a new keypair",
                "2. Update all systems/services using this key with the new public key",
                "3. Revoke/delete the old key from all systems",
                "4. Remove key from Git history using git-filter-repo or BFG Repo-Cleaner"
            ],
            "prevention": [
                "Store private keys in secure vaults (HashiCorp Vault, AWS Secrets Manager)",
                "Use SSH agent forwarding instead of storing keys in code",
                "Add *.pem, *.key, id_rsa* to .gitignore",
                "Enable pre-commit hooks (git-secrets, detect-secrets)"
            ],
            "rotation_command": "ssh-keygen -t ed25519 -C 'your_email@example.com'",
            "docs_url": "https://docs.github.com/en/authentication/connecting-to-github-with-ssh"
        },
        
        "AWS_ACCESS_KEY_ID": {
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
                "Store credentials in AWS Secrets Manager or Parameter Store",
                "Use AWS CLI credential profiles, never hardcode",
                "Enable AWS Organizations SCPs to restrict key usage",
                "Implement least-privilege IAM policies"
            ],
            "rotation_command": "aws iam create-access-key --user-name USERNAME",
            "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        },
        
        "GITHUB_TOKEN": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "1. IMMEDIATELY revoke the token at github.com/settings/tokens",
                "2. Review audit log for unauthorized access",
                "3. Generate a new token with minimal required scopes",
                "4. Update CI/CD and applications with new token",
                "5. Remove from Git history"
            ],
            "prevention": [
                "Use GitHub Actions secrets for CI/CD workflows",
                "Use GitHub Apps with fine-grained permissions instead of PATs",
                "Set token expiration dates (max 90 days)",
                "Never commit tokens - use environment variables",
                "Enable secret scanning on repositories"
            ],
            "rotation_command": "Generate new token at: https://github.com/settings/tokens/new",
            "docs_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"
        },
        
        "SLACK_TOKEN": {
            "severity": "HIGH",
            "immediate_actions": [
                "1. Regenerate the token in Slack App settings",
                "2. Review app access logs for suspicious activity",
                "3. Update integrations with new token",
                "4. Consider rotating OAuth tokens if applicable",
                "5. Remove from Git history"
            ],
            "prevention": [
                "Store tokens in secure secret management",
                "Use OAuth flows instead of bot tokens where possible",
                "Implement token rotation policies",
                "Restrict token scopes to minimum required"
            ],
            "rotation_command": "Regenerate at: https://api.slack.com/apps → Your App → OAuth & Permissions",
            "docs_url": "https://api.slack.com/authentication/rotation"
        },
        
        "DATABASE_URI": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "1. IMMEDIATELY change database password",
                "2. Review database access logs for unauthorized queries",
                "3. Update application configuration with new credentials",
                "4. Consider changing database username if exposed",
                "5. Remove from Git history"
            ],
            "prevention": [
                "Use environment variables for connection strings",
                "Implement database connection string encryption",
                "Use IAM database authentication where possible",
                "Rotate credentials regularly (30-90 days)",
                "Never log connection strings"
            ],
            "rotation_command": "ALTER USER username WITH PASSWORD 'new_secure_password';",
            "docs_url": "https://www.postgresql.org/docs/current/sql-alterrole.html"
        },
        
        "GENERIC": {
            "severity": "HIGH",
            "immediate_actions": [
                "1. Identify the service/system using this credential",
                "2. Rotate/regenerate the credential immediately",
                "3. Update all systems using this credential",
                "4. Review access logs for unauthorized use",
                "5. Remove from Git history using git-filter-repo"
            ],
            "prevention": [
                "Use secret management tools (Vault, AWS Secrets Manager, Azure Key Vault)",
                "Implement automated secret rotation",
                "Use environment variables, never hardcode",
                "Add pre-commit hooks to prevent commits",
                "Enable repository secret scanning"
            ],
            "rotation_command": "Contact service provider to regenerate credential",
            "docs_url": "https://github.com/awslabs/git-secrets"
        }
    }
    
    @staticmethod
    def get_remediation(pattern_type: str) -> Dict[str, Any]:
        """Get remediation advice for a pattern type."""
        return RemediationAdvice.REMEDIATION_TEMPLATES.get(
            pattern_type,
            RemediationAdvice.REMEDIATION_TEMPLATES["GENERIC"]
        )
    
    @staticmethod
    def get_git_history_removal_guide() -> Dict[str, str]:
        """Get comprehensive guide for removing secrets from Git history."""
        return {
            "tool": "git-filter-repo (recommended)",
            "installation": "pip install git-filter-repo",
            "commands": [
                "# Clone a fresh copy first (backup!)",
                "git clone <repo-url> repo-cleanup",
                "cd repo-cleanup",
                "",
                "# Option 1: Remove specific file",
                "git filter-repo --path path/to/secret/file --invert-paths",
                "",
                "# Option 2: Replace text in all files",
                "git filter-repo --replace-text <(echo 'SECRET_VALUE==>')",
                "",
                "# Force push (WARNING: coordinate with team!)",
                "git push origin --force --all",
                "git push origin --force --tags",
                "",
                "# All team members must re-clone:",
                "git clone <repo-url>"
            ],
            "alternative": "BFG Repo-Cleaner: https://rtyley.github.io/bfg-repo-cleaner/",
            "bfg_command": "bfg --delete-files secret.key repo.git"
        }


# ===================================================================
# DETECTION PATTERNS
# ===================================================================

class SecretPatterns:
    """Compiled regex patterns for secret detection with provider-specific rules."""
    
    # Generic secret assignments (JSON, YAML, ENV, code)
    ASSIGNMENT_SECRET = re.compile(
        r'(?i)\b(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey'
        r'|access[_-]?key|secret[_-]?key|access[_-]?token|api[_-]?secret|app[_-]?secret'
        r'|application[_-]?key|app[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)'
        r'\b\s*(?:[:=]\s*|\s+is\s+|"\s*:\s*)"?\s*(?P<val>["\']?([A-Za-z0-9\-\._/+]{8,200})["\']?)',
        re.MULTILINE
    )
    
    # Long base64-like quoted strings
    QUOTED_LONG_BASE64 = re.compile(
        r'["\'](?P<val>[A-Za-z0-9_\-+/=]{24,200})["\']'
    )
    
    # PEM private keys (RSA, EC, OpenSSH)
    PEM_PRIVATE_KEY = re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |)PRIVATE KEY-----[\s\S]{50,4000}-----END (?:RSA |EC |OPENSSH |ENCRYPTED |)PRIVATE KEY-----'
    )
    
    # SSH private keys (alternative formats)
    SSH_PRIVATE_KEY = re.compile(
        r'-----BEGIN (?:DSA|RSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]{50,4000}-----END (?:DSA|RSA|EC|OPENSSH) PRIVATE KEY-----'
    )
    
    # Certificate files (X.509 certificates)
    CERTIFICATE = re.compile(
        r'-----BEGIN CERTIFICATE-----[\s\S]{50,4000}-----END CERTIFICATE-----'
    )
    
    # PKCS#12/PFX certificates
    PKCS12_INDICATOR = re.compile(
        r'-----BEGIN PKCS12-----[\s\S]{50,4000}-----END PKCS12-----'
    )
    
    # SSH public keys
    SSH_PUBLIC_KEY = re.compile(
        r'ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]{100,}'
    )
    
    # AWS credentials
    AWS_ACCESS_KEY_ID = re.compile(r'\b(AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b')
    AWS_SECRET_ACCESS_KEY = re.compile(r'\b[A-Za-z0-9/+=]{40}\b')
    
    # GCP service account key indicator
    GCP_PRIVATE_KEY_JSON = re.compile(
        r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----'
    )
    
    # JWT tokens (three base64url segments)
    JWT_TOKEN = re.compile(
        r'\b(?P<val>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'
    )
    
    # Slack tokens
    SLACK_TOKEN = re.compile(
        r'\b(xox[pbar]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32})\b'
    )
    
    # Stripe API keys
    STRIPE_KEY = re.compile(
        r'\b(sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,})\b'
    )
    
    # GitHub tokens
    GITHUB_TOKEN_PATTERN = re.compile(
        r'\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36})\b'
    )
    
    # Azure tokens
    AZURE_CLIENT_SECRET = re.compile(
        r'\b[A-Za-z0-9~_-]{34,40}\b'
    )
    
    # MongoDB connection strings
    MONGODB_URI = re.compile(
        r'mongodb(?:\+srv)?://[^:]+:[^@]+@[\w\.-]+(?::\d+)?'
    )
    
    # PostgreSQL/MySQL connection strings
    DATABASE_URI = re.compile(
        r'(?:postgres|mysql|mariadb)://[^:]+:[^@]+@[\w\.-]+(?::\d+)?'
    )
    
    # Generic connection strings with passwords
    GENERIC_CONNECTION_STRING = re.compile(
        r'(?i)(?:jdbc|odbc):[^;]+password=([^;"\'\s]{8,})'
    )
    
    # Twilio API keys
    TWILIO_KEY = re.compile(
        r'\b(SK[a-f0-9]{32}|AC[a-f0-9]{32})\b'
    )
    
    # SendGrid API keys
    SENDGRID_KEY = re.compile(
        r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b'
    )
    
    # Mailgun API keys
    MAILGUN_KEY = re.compile(
        r'\bkey-[a-f0-9]{32}\b'
    )
    
    # Firebase API keys
    FIREBASE_KEY = re.compile(
        r'\bAIza[0-9A-Za-z_-]{35}\b'
    )
    
    # Generic Bearer tokens
    BEARER_TOKEN = re.compile(
        r'Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)',
        re.IGNORECASE
    )

    # OpenAI API keys
    OPENAI_API_KEY = re.compile(
        r'\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}|sk-proj-[a-zA-Z0-9_-]{43,})\b'
    )

    # Anthropic (Claude) API keys
    ANTHROPIC_API_KEY = re.compile(
        r'\b(sk-ant-api03-[a-zA-Z0-9\-_]{95,})\b'
    )

    # Google AI (Gemini/PaLM) API keys
    GOOGLE_AI_API_KEY = re.compile(
        r'\bAIza[0-9A-Za-z_-]{35}\b'
    )

    # Hugging Face API tokens
    HUGGINGFACE_TOKEN = re.compile(
        r'\b(hf_[a-zA-Z0-9]{32,})\b'
    )

    # Cohere API keys
    COHERE_API_KEY = re.compile(
        r'\b([a-zA-Z0-9]{40}-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})\b'
    )

    # Replicate API tokens
    REPLICATE_API_TOKEN = re.compile(
        r'\br8_[a-zA-Z0-9]{40}\b'
    )

    # Azure OpenAI API keys
    AZURE_OPENAI_KEY = re.compile(
        r'\b[a-f0-9]{32}\b'
    )

    # Mistral AI API keys
    MISTRAL_API_KEY = re.compile(
        r'\b[a-zA-Z0-9]{32}\b'
    )

    # Perplexity AI API keys
    PERPLEXITY_API_KEY = re.compile(
        r'\bpplx-[a-zA-Z0-9]{48}\b'
    )

    # AI21 Labs API keys
    AI21_API_KEY = re.compile(
        r'\b[a-zA-Z0-9]{32,64}\b'
    )

    # Stability AI API keys
    STABILITY_API_KEY = re.compile(
        r'\bsk-[a-zA-Z0-9]{48}\b'
    )

    # Together AI API keys
    TOGETHER_API_KEY = re.compile(
        r'\b[a-f0-9]{64}\b'
    )

    # Groq API keys
    GROQ_API_KEY = re.compile(
        r'\bgsk_[a-zA-Z0-9]{52}\b'
    )

    # Voyage AI API keys
    VOYAGE_API_KEY = re.compile(
        r'\bpa-[a-zA-Z0-9_-]{40,}\b'
    )

    # Pinecone API keys
    PINECONE_API_KEY = re.compile(
        r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
    )

    # Weaviate API keys
    WEAVIATE_API_KEY = re.compile(
        r'\b[a-zA-Z0-9]{32,64}\b'
    )

    # LangChain/LangSmith API keys
    LANGCHAIN_API_KEY = re.compile(
        r'\bls__[a-zA-Z0-9]{48}\b'
    )

    # Weights & Biases API keys
    WANDB_API_KEY = re.compile(
        r'\b[a-f0-9]{40}\b'
    )

    # Alibaba Cloud (Aliyun) Access Keys
    ALIBABA_ACCESS_KEY = re.compile(
        r'\b(LTAI[a-zA-Z0-9]{12,20})\b'
    )

    # DigitalOcean Personal Access Tokens
    DIGITALOCEAN_TOKEN = re.compile(
        r'\b(dop_v1_[a-f0-9]{64})\b'
    )

    # Heroku API Keys
    HEROKU_API_KEY = re.compile(
        r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
    )

    # Cloudflare API Keys/Tokens
    CLOUDFLARE_API_KEY = re.compile(
        r'\b[a-f0-9]{37}\b'
    )

    CLOUDFLARE_API_TOKEN = re.compile(
        r'\b[A-Za-z0-9_-]{40}\b'
    )

    # Terraform Cloud/Enterprise Tokens
    TERRAFORM_TOKEN = re.compile(
        r'\b[a-zA-Z0-9]{14}\.[atlasv1]{7}\.[a-zA-Z0-9\-_=]{60,}\b'
    )

    # Pulumi Access Tokens
    PULUMI_ACCESS_TOKEN = re.compile(
        r'\bpul-[a-f0-9]{40}\b'
    )

    # PayPal Client ID/Secret
    PAYPAL_CLIENT_ID = re.compile(
        r'\bA[a-zA-Z0-9_-]{80}\b'
    )

    # Square Access Tokens
    SQUARE_ACCESS_TOKEN = re.compile(
        r'\bsq0atp-[0-9A-Za-z\-_]{22}\b'
    )

    SQUARE_SECRET = re.compile(
        r'\bsq0csp-[0-9A-Za-z\-_]{43}\b'
    )

    # Braintree Access Tokens
    BRAINTREE_ACCESS_TOKEN = re.compile(
        r'\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b'
    )

    # Plaid API Keys
    PLAID_CLIENT_ID = re.compile(
        r'\b[a-f0-9]{24}\b'
    )

    PLAID_SECRET = re.compile(
        r'\b[a-f0-9]{30}\b'
    )

    # Discord Bot Tokens
    DISCORD_BOT_TOKEN = re.compile(
        r'\b(MTA[a-zA-Z0-9_-]{59}|ODc[a-zA-Z0-9_-]{59})\b'
    )

    DISCORD_WEBHOOK = re.compile(
        r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]{68}'
    )

    # Telegram Bot Tokens
    TELEGRAM_BOT_TOKEN = re.compile(
        r'\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b'
    )

    # Microsoft Teams Webhooks
    TEAMS_WEBHOOK = re.compile(
        r'https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9-]+'
    )

    # WhatsApp Business API Tokens
    WHATSAPP_TOKEN = re.compile(
        r'\bEAA[a-zA-Z0-9]{100,}\b'
    )

    # NPM Tokens
    NPM_TOKEN = re.compile(
        r'\bnpm_[a-zA-Z0-9]{36}\b'
    )

    # PyPI Tokens
    PYPI_TOKEN = re.compile(
        r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b'
    )

    # Docker Hub Tokens
    DOCKERHUB_TOKEN = re.compile(
        r'\bdckr_pat_[a-zA-Z0-9_-]{0,}\b'
    )

    # JFrog Artifactory API Keys
    ARTIFACTORY_API_KEY = re.compile(
        r'\bAKC[a-zA-Z0-9]{10,}\b'
    )

    # Sentry Auth Tokens
    SENTRY_AUTH_TOKEN = re.compile(
        r'\b[a-f0-9]{64}\b'
    )

    # New Relic API Keys
    NEW_RELIC_API_KEY = re.compile(
        r'\bNRAK-[A-Z0-9]{27}\b'
    )

    NEW_RELIC_INSIGHTS_KEY = re.compile(
        r'\b[a-f0-9]{32}\b'
    )

    # Datadog API Keys
    DATADOG_API_KEY = re.compile(
        r'\b[a-f0-9]{32}\b'
    )

    DATADOG_APP_KEY = re.compile(
        r'\b[a-f0-9]{40}\b'
    )

    # PagerDuty API Keys
    PAGERDUTY_API_KEY = re.compile(
        r'\b[a-zA-Z0-9_\-]{20}\b'
    )

    # Elastic (Elasticsearch) API Keys
    ELASTIC_API_KEY = re.compile(
        r'\b[A-Za-z0-9_-]{40,}\b'
    )

    # Grafana API Keys
    GRAFANA_API_KEY = re.compile(
        r'\beyJrIjoi[A-Za-z0-9_-]{50,}\b'
    )

    # CircleCI Personal Tokens
    CIRCLECI_TOKEN = re.compile(
        r'\b[a-f0-9]{40}\b'
    )

    # Travis CI Tokens
    TRAVIS_CI_TOKEN = re.compile(
        r'\b[a-zA-Z0-9]{22}\b'
    )

    # GitLab Personal Access Tokens
    GITLAB_PAT = re.compile(
        r'\bglpat-[a-zA-Z0-9_\-]{20}\b'
    )

    # Bitbucket App Passwords
    BITBUCKET_APP_PASSWORD = re.compile(
        r'\bATBB[a-zA-Z0-9]{59}\b'
    )

    # Auth0 Client Secrets
    AUTH0_CLIENT_SECRET = re.compile(
        r'\b[a-zA-Z0-9_\-]{64}\b'
    )

    # Okta API Tokens
    OKTA_API_TOKEN = re.compile(
        r'\b[a-zA-Z0-9_\-]{42}\b'
    )

    # Keycloak Client Secrets
    KEYCLOAK_CLIENT_SECRET = re.compile(
        r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
    )

    # Google Analytics (GA4) Measurement Protocol API Secret
    GA4_API_SECRET = re.compile(
        r'\b[A-Za-z0-9_-]{22}\b'
    )

    # Segment Write Keys
    SEGMENT_WRITE_KEY = re.compile(
        r'\b[a-zA-Z0-9]{32}\b'
    )

    # Mixpanel API Secret
    MIXPANEL_API_SECRET = re.compile(
        r'\b[a-f0-9]{32}\b'
    )

    # Amplitude API Keys
    AMPLITUDE_API_KEY = re.compile(
        r'\b[a-f0-9]{32}\b'
    )

    # Redis Connection URLs
    REDIS_URI = re.compile(
        r'redis://[^:]*:[^@]*@[\w\.-]+(?::\d+)?'
    )

    # Supabase Keys
    SUPABASE_SERVICE_KEY = re.compile(
        r'\beyJ[a-zA-Z0-9_-]{30,}\.eyJ[a-zA-Z0-9_-]{30,}\.[a-zA-Z0-9_-]{30,}\b'
    )

    # PlanetScale Passwords
    PLANETSCALE_PASSWORD = re.compile(
        r'\bpscale_pw_[a-zA-Z0-9]{40,}\b'
    )

    # Airtable API Keys
    AIRTABLE_API_KEY = re.compile(
        r'\bkey[a-zA-Z0-9]{14}\b'
    )

    # Notion Integration Tokens
    NOTION_TOKEN = re.compile(
        r'\bsecret_[a-zA-Z0-9]{43}\b'
    )

    # Age (encryption) Private Keys
    AGE_PRIVATE_KEY = re.compile(
        r'AGE-SECRET-KEY-1[A-Z0-9]{58}'
    )

    # PGP/GPG Private Key Blocks
    PGP_PRIVATE_KEY = re.compile(
        r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+-----END PGP PRIVATE KEY BLOCK-----'
    )


# ===================================================================
# UTILITY FUNCTIONS
# ===================================================================

def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string (bits per character).
    
    High entropy (>4.5) often indicates cryptographic material.
    Low entropy (<3.5) typically indicates human-readable text.
    
    Args:
        data: String to analyze
        
    Returns:
        Entropy value in bits per character (0.0 to ~8.0)
    """
    if not data or len(data) < MIN_ENTROPY_CALC_LENGTH:
        return 0.0

    try:
        counts = Counter(data)
        probs = [count / len(data) for count in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)
    except Exception as e:
        logger.warning(f"Entropy calculation failed: {e}")
        return 0.0


def is_denylist_match(value: str) -> bool:
    """
    Check if value contains known fake/example credential terms.
    
    Args:
        value: String to check
        
    Returns:
        True if value appears to be a placeholder/example
    """
    value_lower = value.lower()
    return any(term in value_lower for term in DENYLIST_TERMS)


def should_skip_path(path: str) -> bool:
    """
    Determine if a file path should be skipped during scanning.
    
    Args:
        path: Relative file path
        
    Returns:
        True if path matches skip patterns
    """
    path_lower = path.lower()
    return any(pattern in path_lower for pattern in SKIP_PATH_PATTERNS)


def calculate_secret_hash(value: str) -> str:
    """
    Calculate a stable hash for a secret value for deduplication.
    
    Args:
        value: Secret value to hash
        
    Returns:
        SHA256 hash of the value
    """
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def is_binary_file(file_path: Path, sample_size: int = 8192) -> bool:
    """
    Detect if a file is binary by checking for null bytes in the first chunk.
    
    Binary files are skipped during scanning as they rarely contain readable secrets.
    This provides a significant performance boost by avoiding unnecessary processing.
    
    Args:
        file_path: Path to the file to check
        sample_size: Number of bytes to sample (default: 8KB)
        
    Returns:
        True if file appears to be binary, False otherwise
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(sample_size)
            
        # Empty file
        if not chunk:
            return False
        
        # Check for null byte (strong indicator of binary)
        if b'\x00' in chunk:
            return True
        
        # Check ratio of non-text bytes
        # Text files should have mostly printable ASCII + common whitespace
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        non_text_count = sum(1 for byte in chunk if byte not in text_chars)
        
        # If more than 30% non-text bytes, likely binary
        if len(chunk) > 0 and (non_text_count / len(chunk)) > 0.30:
            return True
        
        return False
        
    except (IOError, OSError) as e:
        logger.debug(f"Cannot read file for binary check {file_path}: {e}")
        # If we can't read it, assume it might be text and let the normal scan handle it
        return False


def load_custom_patterns(filepath: str) -> List[Tuple[re.Pattern, str]]:
    """
    Load custom regex patterns from a JSON file.
    
    Expected format:
    {
      "patterns": [
        {
          "name": "CUSTOM_API_KEY",
          "regex": "myapi_[A-Za-z0-9]{32}",
          "description": "My custom API key format"
        }
      ]
    }
    
    Args:
        filepath: Path to custom patterns JSON file
        
    Returns:
        List of (compiled_pattern, pattern_name) tuples
    """
    custom_patterns = []
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
        for pattern_def in data.get('patterns', []):
            name = pattern_def.get('name', 'CUSTOM_PATTERN')
            regex = pattern_def.get('regex')
            
            if not regex:
                logger.warning(f"Skipping pattern {name}: no regex provided")
                continue
                
            try:
                compiled = re.compile(regex)
                custom_patterns.append((compiled, name))
                logger.info(f"Loaded custom pattern: {name}")
            except re.error as e:
                logger.error(f"Invalid regex for pattern {name}: {e}")
                
    except FileNotFoundError:
        logger.warning(f"Custom patterns file not found: {filepath}")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in custom patterns file: {e}")
    except Exception as e:
        logger.error(f"Error loading custom patterns: {e}")
        
    return custom_patterns


def load_baseline(filepath: Path) -> Set[str]:
    """
    Load baseline of known findings for incremental scanning.
    
    Args:
        filepath: Path to baseline JSON file
        
    Returns:
        Set of finding hashes to exclude
    """
    baseline_hashes = set()
    
    try:
        if filepath.exists():
            with open(filepath, 'r') as f:
                baseline = json.load(f)
                
            for finding in baseline.get('findings', []):
                if 'hash' in finding:
                    baseline_hashes.add(finding['hash'])
                    
            logger.info(f"Loaded {len(baseline_hashes)} baseline findings")
    except Exception as e:
        logger.warning(f"Could not load baseline: {e}")
        
    return baseline_hashes


def score_finding(
    value: str,
    entropy: float,
    pattern_name: str,
    file_path: str
) -> Tuple[int, str]:
    """
    Calculate risk score (0-100) and classification for a finding.
    
    Scoring factors:
    - Pattern type (PEM keys = high, generic = low)
    - Entropy level (high = likely secret)
    - File location (tests/docs = lower risk)
    - Denylist matches (examples = very low risk)
    
    Args:
        value: The matched secret value
        entropy: Shannon entropy of the value
        pattern_name: Name of the matching pattern
        file_path: Path where secret was found
        
    Returns:
        Tuple of (score: int, classification: str)
    """
    score = 0
    classification = "unknown"
    
    # Base score by pattern type
    if pattern_name == "PEM_PRIVATE_KEY":
        score = SCORE_PEM_PRIVATE_KEY
        classification = "critical"
    elif pattern_name == "SSH_PRIVATE_KEY":
        score = SCORE_SSH_PRIVATE_KEY
        classification = "critical"
    elif pattern_name == "PKCS12_CERTIFICATE":
        score = SCORE_PKCS12_CERTIFICATE
        classification = "critical"
    elif pattern_name == "CERTIFICATE":
        score = SCORE_CERTIFICATE
        classification = "info"
    elif pattern_name == "SSH_PUBLIC_KEY":
        score = SCORE_SSH_PUBLIC_KEY
        classification = "info"
    elif pattern_name in ["AWS_ACCESS_KEY_ID", "STRIPE_KEY", "SLACK_TOKEN", "GITHUB_TOKEN"]:
        score = SCORE_CLOUD_API_KEY
        classification = "critical"
    elif pattern_name == "AWS_SECRET_ACCESS_KEY" and entropy > ENTROPY_THRESHOLD_HIGH:
        score = SCORE_AWS_SECRET_HIGH_ENTROPY
        classification = "high"
    elif pattern_name == "JWT_TOKEN":
        score = SCORE_JWT_TOKEN
        classification = "medium"
    elif entropy > ENTROPY_THRESHOLD_CRITICAL and len(value) >= 32:
        score = SCORE_THRESHOLD_HIGH
        classification = "high"
    elif entropy > ENTROPY_THRESHOLD_HIGH and len(value) >= 20:
        score = 70
        classification = "medium"
    elif entropy > ENTROPY_THRESHOLD_MEDIUM and len(value) >= 12:
        score = SCORE_THRESHOLD_MEDIUM
        classification = "low"
    else:
        score = SCORE_THRESHOLD_LOW
        classification = "info"
    
    # Adjust for context
    path_lower = file_path.lower()
    if any(x in path_lower for x in ["test", "fixture", "example", "sample", "docs", ".md"]):
        score = max(0, score - SCORE_PENALTY_TEST_FILE)
        if score < SCORE_THRESHOLD_MEDIUM:
            classification = "unlikely"
    
    # Denylist severe penalty
    if is_denylist_match(value):
        score = max(0, score - SCORE_PENALTY_DENYLIST)
        classification = "unlikely"
    
    # Final classification
    if score >= SCORE_THRESHOLD_HIGH:
        classification = "likely_secret"
    elif score >= SCORE_THRESHOLD_MEDIUM:
        classification = "possible_secret"
    elif score >= SCORE_THRESHOLD_LOW:
        classification = "low_confidence"
    else:
        classification = "unlikely"
    
    return min(SCORE_MAX, score), classification


# ===================================================================
# LOCAL FILESYSTEM SCANNING
# ===================================================================

class LocalFilesystemScanner:
    """Platform-optimized local filesystem scanning for secrets."""
    
    @staticmethod
    async def scan_local_path(
        root_path: Path,
        max_depth: int,
        custom_patterns: List[Tuple[re.Pattern, str]] = None,
        baseline_hashes: Set[str] = None,
        follow_symlinks: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Scan a local filesystem path for secrets.
        
        Args:
            root_path: Root directory to scan
            max_depth: Maximum directory depth to traverse
            custom_patterns: Optional custom regex patterns
            baseline_hashes: Optional baseline for incremental scanning
            follow_symlinks: Whether to follow symbolic links
            
        Returns:
            List of findings
        """
        logger.info(f"Starting local filesystem scan: {root_path}")
        logger.info(f"Platform: {platform.system()}")
        logger.info(f"Max depth: {max_depth}, Follow symlinks: {follow_symlinks}")
                
        all_findings = []
        file_semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILES)
        
        # Collect all files to scan
        logger.info("Discovering files...")
        files_to_scan = await LocalFilesystemScanner._collect_files(
            root_path, max_depth, follow_symlinks
        )
        
        logger.info(f"Found {len(files_to_scan)} files to scan")
        
        # Create scan tasks with semaphore control
        scan_tasks = []
        for file_path in files_to_scan:
            relative_path = str(file_path.relative_to(root_path))
            task = LocalFilesystemScanner._scan_file_with_semaphore(
                file_path,
                f"local:{root_path.name}",
                relative_path,
                custom_patterns,
                baseline_hashes,
                file_semaphore
            )
            scan_tasks.append(task)
        
        # Execute scans with progress bar
        logger.info(f"Scanning {len(scan_tasks)} files...")
        
        with tqdm(total=len(scan_tasks), desc="Scanning files", unit="file") as pbar:
            for coro in asyncio.as_completed(scan_tasks):
                try:
                    result = await coro
                    if isinstance(result, list):
                        all_findings.extend(result)
                    pbar.update(1)
                except Exception as e:
                    logger.error(f"Scan task failed: {e}")
                    pbar.update(1)
        
        logger.info(f"Local scan complete. Found {len(all_findings)} potential secrets")
        return all_findings
    
    @staticmethod
    async def _scan_file_with_semaphore(
        file_path: Path,
        repo_name: str,
        relative_path: str,
        custom_patterns: List[Tuple[re.Pattern, str]],
        baseline_hashes: Set[str],
        semaphore: asyncio.Semaphore
    ) -> List[Dict[str, Any]]:
        """Scan file with semaphore control."""
        async with semaphore:
            return await scan_file_async(
                file_path,
                repo_name,
                relative_path,
                custom_patterns,
                baseline_hashes,
                None  # No git blame for local files
            )

    @staticmethod
    async def _collect_files(
        root_path: Path,
        max_depth: int,
        follow_symlinks: bool
    ) -> List[Path]:
        """
        Collect all files to scan from root path using platform optimizations.
        
        Args:
            root_path: Root directory
            max_depth: Maximum depth to traverse
            follow_symlinks: Whether to follow symlinks
            
        Returns:
            List of file paths
        """
        files = []
        system = platform.system()
        
        logger.info(f"Using platform-optimized scanning for {system}")
        
        # Try platform-specific fast discovery for common directories
        special_dirs_found = []
        
        try:
            if system == "Darwin":
                # macOS: Use Spotlight for fast .git directory discovery
                git_dirs = await MacOSScanner.find_directories(root_path, ".git")
                special_dirs_found.extend(git_dirs)
                
            elif system == "Linux":
                # Linux: Use locate database for fast discovery
                git_dirs = await LinuxScanner.find_directories(root_path, ".git")
                special_dirs_found.extend(git_dirs)
                
            elif system == "Windows":
                # Windows: Use PowerShell for discovery
                git_dirs = await WindowsScanner.find_directories(root_path, ".git")
                special_dirs_found.extend(git_dirs)
        
        except Exception as e:
            logger.warning(f"Platform-specific optimization failed: {e}, falling back to standard scan")
        
        if special_dirs_found:
            logger.info(f"Platform optimization found {len(special_dirs_found)} special directories to prioritize")
        
        # Standard recursive collection
        def _collect_sync(path: Path, current_depth: int):
            """Synchronous file collection for thread pool."""
            if current_depth > max_depth:
                return
            
            try:
                for item in path.iterdir():
                    # Handle symlinks
                    if item.is_symlink():
                        if not follow_symlinks:
                            continue
                        try:
                            item = item.resolve()
                        except (OSError, RuntimeError):
                            continue
                    
                    if item.is_file():
                        if should_skip_path(str(item)):
                            continue
                        files.append(item)
                    elif item.is_dir():
                        if should_skip_path(str(item)):
                            continue
                        _collect_sync(item, current_depth + 1)
                        
            except (PermissionError, OSError) as e:
                logger.debug(f"Cannot access {path}: {e}")
        
        # Run in thread pool to avoid blocking event loop
        await asyncio.get_event_loop().run_in_executor(
            None, _collect_sync, root_path, 0
        )
        
        return files

class MacOSScanner:
    """macOS-specific scanning using Spotlight (mdfind)."""
    
    @staticmethod
    async def find_directories(root: Path, dir_name: str) -> List[Path]:
        """Use Spotlight to quickly find directories."""
        logger.info(f"Using macOS Spotlight for fast {dir_name} discovery...")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "mdfind",
                "-onlyin", str(root),
                f"kMDItemFSName == '{dir_name}' && kMDItemContentType == 'public.folder'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=60
            )
            
            if proc.returncode == 0:
                paths = []
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        path = Path(line.strip())
                        if path.exists() and path.is_dir():
                            paths.append(path)
                
                logger.info(f"Found {len(paths)} {dir_name} directories")
                return paths
        
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"Spotlight search failed: {e}")
        
        return []


class LinuxScanner:
    """Linux-specific scanning using locate database."""
    
    @staticmethod
    async def find_directories(root: Path, dir_name: str) -> List[Path]:
        """Use locate database for fast directory finding."""
        logger.info(f"Using Linux locate database for fast {dir_name} discovery...")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "locate",
                "-r", f"/{dir_name}$",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=60
            )
            
            if proc.returncode == 0:
                paths = []
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        path = Path(line.strip())
                        try:
                            if path.exists() and path.is_dir() and path.is_relative_to(root):
                                paths.append(path)
                        except ValueError:
                            pass
                
                logger.info(f"Found {len(paths)} {dir_name} directories")
                return paths
        
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"locate search failed: {e}")
        
        return []


class WindowsScanner:
    """Windows-specific scanning using PowerShell."""
    
    @staticmethod
    async def find_directories(root: Path, dir_name: str) -> List[Path]:
        """Use PowerShell for fast directory finding."""
        logger.info(f"Using Windows PowerShell for fast {dir_name} discovery...")
        
        try:
            cmd = [
                "powershell", "-Command",
                f"Get-ChildItem -Path '{root}' -Name '{dir_name}' -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )
            
            if proc.returncode == 0:
                paths = []
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        path = Path(line.strip())
                        if path.exists() and path.is_dir():
                            paths.append(path)
                
                logger.info(f"Found {len(paths)} {dir_name} directories")
                return paths
        
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"PowerShell search failed: {e}")
        
        return []


# ===================================================================
# ASYNC REPOSITORY OPERATIONS
# ===================================================================

async def clone_repo_async(
    repo_full_name: str,
    clone_base: Path,
    token: str,
    semaphore: asyncio.Semaphore
) -> Optional[Path]:
    """
    Asynchronously clone a repository with timeout and retry logic.
    
    Args:
        repo_full_name: Full repository name (org/repo)
        clone_base: Base directory for clones
        token: GitHub authentication token
        semaphore: Semaphore for concurrency control
        
    Returns:
        Path to cloned repository or None if failed
    """
    async with semaphore:
        repo_dir = clone_base / repo_full_name.replace("/", "_")
        
        # Clean existing directory
        if repo_dir.exists():
            try:
                shutil.rmtree(repo_dir)
            except Exception as e:
                logger.error(f"Failed to clean {repo_dir}: {e}")
                return None
        
        clone_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
        
        for attempt in range(RETRY_ATTEMPTS):
            try:
                logger.info(f"Cloning {repo_full_name} (attempt {attempt + 1}/{RETRY_ATTEMPTS})")
                
                proc = await asyncio.create_subprocess_exec(
                    "git", "clone",
                    "--depth", str(CLONE_DEPTH),
                    "--single-branch",
                    "--no-tags",
                    clone_url,
                    str(repo_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=CLONE_TIMEOUT_SECONDS
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Clone timeout for {repo_full_name}")
                    proc.kill()
                    await proc.wait()
                    continue
                
                if proc.returncode == 0:
                    logger.info(f"✓ Successfully cloned {repo_full_name}")
                    return repo_dir
                else:
                    error_msg = stderr.decode('utf-8', errors='ignore')[:200]
                    logger.warning(f"Clone failed for {repo_full_name}: {error_msg}")
                    
            except Exception as e:
                logger.error(f"Exception cloning {repo_full_name}: {e}")
            
            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
        
        logger.error(f"✗ Failed to clone {repo_full_name} after {RETRY_ATTEMPTS} attempts")
        return None


async def get_git_blame_async(
    repo_dir: Path,
    file_path: str,
    line_number: int
) -> Optional[Dict[str, str]]:
    """
    Get git blame information for a specific line.
    
    Args:
        repo_dir: Repository directory
        file_path: Relative file path
        line_number: Line number to blame
        
    Returns:
        Dict with author, email, date, commit_hash or None
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "blame", "-L", f"{line_number},{line_number}",
            "--porcelain", file_path,
            cwd=repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=10
        )
        
        if proc.returncode == 0:
            output = stdout.decode('utf-8')
            lines = output.split('\n')
            
            blame_info = {}
            for line in lines:
                if line.startswith('author '):
                    blame_info['author'] = line.split('author ', 1)[1]
                elif line.startswith('author-mail '):
                    blame_info['email'] = line.split('author-mail ', 1)[1].strip('<>')
                elif line.startswith('author-time '):
                    timestamp = int(line.split('author-time ', 1)[1])
                    blame_info['date'] = datetime.fromtimestamp(timestamp).isoformat()
                elif not line.startswith('\t') and ' ' in line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2 and len(parts[0]) == 40:
                        blame_info['commit_hash'] = parts[0]
                        
            return blame_info if blame_info else None
            
    except asyncio.TimeoutError:
        logger.debug(f"Git blame timeout for {file_path}:{line_number}")
    except Exception as e:
        logger.debug(f"Git blame failed: {e}")
        
    return None


async def scan_file_async(
    file_path: Path,
    repo_name: str,
    relative_path: str,
    custom_patterns: List[Tuple[re.Pattern, str]] = None,
    baseline_hashes: Set[str] = None,
    repo_dir: Path = None
) -> List[Dict[str, Any]]:
    """
    Asynchronously scan a single file for secrets.
    
    Args:
        file_path: Absolute path to file
        repo_name: Repository name for reporting
        relative_path: Relative path within repo
        custom_patterns: Optional list of custom patterns to check
        baseline_hashes: Optional set of baseline hashes to skip
        repo_dir: Repository directory for git blame
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    custom_patterns = custom_patterns or []
    baseline_hashes = baseline_hashes or set()
    
    try:
        # Quick binary check by extension
        file_extension = file_path.suffix.lower()
        if file_extension in BINARY_FILE_EXTENSIONS:
            logger.debug(f"Skipping binary file (extension): {relative_path}")
            return findings
        
        # Check file size BEFORE reading
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            logger.debug(f"Skipping large file: {relative_path} ({file_size} bytes)")
            return findings
        
        # Binary content detection (reads first 8KB only)
        if is_binary_file(file_path):
            logger.debug(f"Skipping binary file (content): {relative_path}")
            return findings
        
        # Read file content
        try:
            async with aiofiles.open(file_path, 'r', errors='ignore') as f:
                content = await f.read()
        except UnicodeDecodeError:
            logger.debug(f"Skipping file with encoding issues: {relative_path}")
            return findings
        except Exception as e:
            logger.warning(f"Failed to read {relative_path}: {e}")
            return findings
        
        if not content:
            return findings
        
        # Run all pattern detectors (built-in + custom)
        patterns_to_check = [            
            # AI/ML Services
            (SecretPatterns.OPENAI_API_KEY, "OPENAI_API_KEY"),
            (SecretPatterns.ANTHROPIC_API_KEY, "ANTHROPIC_API_KEY"),
            (SecretPatterns.HUGGINGFACE_TOKEN, "HUGGINGFACE_TOKEN"),
            (SecretPatterns.COHERE_API_KEY, "COHERE_API_KEY"),
            (SecretPatterns.REPLICATE_API_TOKEN, "REPLICATE_API_TOKEN"),
            (SecretPatterns.GROQ_API_KEY, "GROQ_API_KEY"),
            (SecretPatterns.PERPLEXITY_API_KEY, "PERPLEXITY_API_KEY"),
            (SecretPatterns.LANGCHAIN_API_KEY, "LANGCHAIN_API_KEY"),
            (SecretPatterns.PINECONE_API_KEY, "PINECONE_API_KEY"),

            # Cryptographic Keys & Certificates
            (SecretPatterns.PEM_PRIVATE_KEY, "PEM_PRIVATE_KEY"),
            (SecretPatterns.SSH_PRIVATE_KEY, "SSH_PRIVATE_KEY"),
            (SecretPatterns.CERTIFICATE, "CERTIFICATE"),
            (SecretPatterns.PKCS12_INDICATOR, "PKCS12_CERTIFICATE"),
            (SecretPatterns.SSH_PUBLIC_KEY, "SSH_PUBLIC_KEY"),
            (SecretPatterns.PGP_PRIVATE_KEY, "PGP_PRIVATE_KEY"),
            (SecretPatterns.AGE_PRIVATE_KEY, "AGE_PRIVATE_KEY"),
            
            # Cloud Providers - AWS
            (SecretPatterns.AWS_ACCESS_KEY_ID, "AWS_ACCESS_KEY_ID"),
            (SecretPatterns.AWS_SECRET_ACCESS_KEY, "AWS_SECRET_ACCESS_KEY"),
            
            # Cloud Providers - GCP
            (SecretPatterns.GCP_PRIVATE_KEY_JSON, "GCP_PRIVATE_KEY_JSON"),
            
            # Cloud Providers - Azure
            (SecretPatterns.AZURE_CLIENT_SECRET, "AZURE_CLIENT_SECRET"),
            
            # Cloud Providers - Others
            (SecretPatterns.ALIBABA_ACCESS_KEY, "ALIBABA_ACCESS_KEY"),
            (SecretPatterns.DIGITALOCEAN_TOKEN, "DIGITALOCEAN_TOKEN"),
            (SecretPatterns.HEROKU_API_KEY, "HEROKU_API_KEY"),
            (SecretPatterns.CLOUDFLARE_API_KEY, "CLOUDFLARE_API_KEY"),
            (SecretPatterns.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN"),
            
            # Infrastructure as Code
            (SecretPatterns.TERRAFORM_TOKEN, "TERRAFORM_TOKEN"),
            (SecretPatterns.PULUMI_ACCESS_TOKEN, "PULUMI_ACCESS_TOKEN"),
            
            # Version Control & CI/CD
            (SecretPatterns.GITHUB_TOKEN_PATTERN, "GITHUB_TOKEN"),
            (SecretPatterns.GITLAB_PAT, "GITLAB_PAT"),
            (SecretPatterns.BITBUCKET_APP_PASSWORD, "BITBUCKET_APP_PASSWORD"),
            (SecretPatterns.CIRCLECI_TOKEN, "CIRCLECI_TOKEN"),
            (SecretPatterns.TRAVIS_CI_TOKEN, "TRAVIS_CI_TOKEN"),
            
            # Package Registries
            (SecretPatterns.NPM_TOKEN, "NPM_TOKEN"),
            (SecretPatterns.PYPI_TOKEN, "PYPI_TOKEN"),
            (SecretPatterns.DOCKERHUB_TOKEN, "DOCKERHUB_TOKEN"),
            (SecretPatterns.ARTIFACTORY_API_KEY, "ARTIFACTORY_API_KEY"),
            
            # Communication & Messaging
            (SecretPatterns.SLACK_TOKEN, "SLACK_TOKEN"),
            (SecretPatterns.DISCORD_BOT_TOKEN, "DISCORD_BOT_TOKEN"),
            (SecretPatterns.DISCORD_WEBHOOK, "DISCORD_WEBHOOK"),
            (SecretPatterns.TELEGRAM_BOT_TOKEN, "TELEGRAM_BOT_TOKEN"),
            (SecretPatterns.TEAMS_WEBHOOK, "TEAMS_WEBHOOK"),
            (SecretPatterns.WHATSAPP_TOKEN, "WHATSAPP_TOKEN"),
            
            # Payment & Financial
            (SecretPatterns.STRIPE_KEY, "STRIPE_KEY"),
            (SecretPatterns.PAYPAL_CLIENT_ID, "PAYPAL_CLIENT_ID"),
            (SecretPatterns.SQUARE_ACCESS_TOKEN, "SQUARE_ACCESS_TOKEN"),
            (SecretPatterns.SQUARE_SECRET, "SQUARE_SECRET"),
            (SecretPatterns.BRAINTREE_ACCESS_TOKEN, "BRAINTREE_ACCESS_TOKEN"),
            (SecretPatterns.PLAID_CLIENT_ID, "PLAID_CLIENT_ID"),
            (SecretPatterns.PLAID_SECRET, "PLAID_SECRET"),
            
            # Databases
            (SecretPatterns.MONGODB_URI, "MONGODB_URI"),
            (SecretPatterns.DATABASE_URI, "DATABASE_URI"),
            (SecretPatterns.REDIS_URI, "REDIS_URI"),
            (SecretPatterns.GENERIC_CONNECTION_STRING, "GENERIC_CONNECTION_STRING"),
            (SecretPatterns.SUPABASE_SERVICE_KEY, "SUPABASE_SERVICE_KEY"),
            (SecretPatterns.PLANETSCALE_PASSWORD, "PLANETSCALE_PASSWORD"),
            
            # Email Services
            (SecretPatterns.SENDGRID_KEY, "SENDGRID_KEY"),
            (SecretPatterns.MAILGUN_KEY, "MAILGUN_KEY"),
            (SecretPatterns.TWILIO_KEY, "TWILIO_KEY"),
            
            # Monitoring & Observability
            (SecretPatterns.SENTRY_AUTH_TOKEN, "SENTRY_AUTH_TOKEN"),
            (SecretPatterns.NEW_RELIC_API_KEY, "NEW_RELIC_API_KEY"),
            (SecretPatterns.NEW_RELIC_INSIGHTS_KEY, "NEW_RELIC_INSIGHTS_KEY"),
            (SecretPatterns.DATADOG_API_KEY, "DATADOG_API_KEY"),
            (SecretPatterns.DATADOG_APP_KEY, "DATADOG_APP_KEY"),
            (SecretPatterns.PAGERDUTY_API_KEY, "PAGERDUTY_API_KEY"),
            (SecretPatterns.ELASTIC_API_KEY, "ELASTIC_API_KEY"),
            (SecretPatterns.GRAFANA_API_KEY, "GRAFANA_API_KEY"),
            
            # Analytics & Marketing
            (SecretPatterns.GA4_API_SECRET, "GA4_API_SECRET"),
            (SecretPatterns.SEGMENT_WRITE_KEY, "SEGMENT_WRITE_KEY"),
            (SecretPatterns.MIXPANEL_API_SECRET, "MIXPANEL_API_SECRET"),
            (SecretPatterns.AMPLITUDE_API_KEY, "AMPLITUDE_API_KEY"),
            
            # Productivity & Collaboration
            (SecretPatterns.AIRTABLE_API_KEY, "AIRTABLE_API_KEY"),
            (SecretPatterns.NOTION_TOKEN, "NOTION_TOKEN"),
            
            # Auth & Identity
            (SecretPatterns.AUTH0_CLIENT_SECRET, "AUTH0_CLIENT_SECRET"),
            (SecretPatterns.OKTA_API_TOKEN, "OKTA_API_TOKEN"),
            (SecretPatterns.KEYCLOAK_CLIENT_SECRET, "KEYCLOAK_CLIENT_SECRET"),
            
            # Other Services
            (SecretPatterns.FIREBASE_KEY, "FIREBASE_KEY"),
            (SecretPatterns.JWT_TOKEN, "JWT_TOKEN"),
            (SecretPatterns.BEARER_TOKEN, "BEARER_TOKEN"),
            
            # Generic Patterns (should be last for specificity)
            (SecretPatterns.ASSIGNMENT_SECRET, "ASSIGNMENT_SECRET"),
            (SecretPatterns.QUOTED_LONG_BASE64, "QUOTED_LONG_BASE64"),
        ] + custom_patterns

        
        for pattern, pattern_name in patterns_to_check:
            try:
                for match in pattern.finditer(content):
                    # Extract value
                    if 'val' in match.groupdict():
                        raw_value = match.group('val')
                    else:
                        raw_value = match.group(0)
                    
                    # Clean value
                    value = raw_value.strip().strip('\'"')
                    
                    if len(value) < 8:
                        continue
                    
                    # Calculate entropy
                    entropy = shannon_entropy(value)
                    
                    # Skip low-entropy matches for certain patterns
                    if pattern_name in ["QUOTED_LONG_BASE64", "ASSIGNMENT_SECRET", "AWS_SECRET_ACCESS_KEY"]:
                        if entropy < 3.5:
                            continue
                    
                    # Score finding
                    score, classification = score_finding(
                        value, entropy, pattern_name, relative_path
                    )
                    
                    # Skip very low confidence findings
                    if score < 20:
                        continue
                    
                    # Extract context
                    start_pos = max(0, match.start() - 200)
                    end_pos = min(len(content), match.end() + 200)
                    context = content[start_pos:end_pos]
                    
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Calculate unique hash for deduplication
                    secret_hash = calculate_secret_hash(value)
                    
                    # Skip if in baseline
                    if DEDUPLICATION_ENABLED and secret_hash in baseline_hashes:
                        logger.debug(f"Skipping baseline finding: {secret_hash[:8]}")
                        continue
                    
                    # Get git blame if enabled
                    blame_info = None
                    if ENABLE_GIT_BLAME and repo_dir:
                        blame_info = await get_git_blame_async(repo_dir, relative_path, line_num)
                    
                    finding = {
                        "repo": repo_name,
                        "path": relative_path,
                        "line": line_num,
                        "pattern": pattern_name,
                        "classification": classification,
                        "score": score,
                        "entropy": round(entropy, 3),
                        "value_length": len(value),
                        "hash": secret_hash,
                        "match_preview": value[:80] + ("..." if len(value) > 80 else ""),
                        "context": context.replace("\n", "\\n")[:500],
                        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                    }
                    
                    # Add blame info if available
                    if blame_info:
                        finding['git_blame'] = blame_info
                    
                    findings.append(finding)
                    
            except Exception as e:
                logger.warning(f"Pattern {pattern_name} failed on {relative_path}: {e}")
                continue
        
    except Exception as e:
        logger.error(f"Error scanning file {relative_path}: {e}")
    
    return findings


async def scan_repo_async(
    repo_full_name: str,
    repo_dir: Path,
    custom_patterns: List[Tuple[re.Pattern, str]] = None,
    baseline_hashes: Set[str] = None
) -> List[Dict[str, Any]]:
    """
    Asynchronously scan all files in a repository.
    
    Args:
        repo_full_name: Full repository name
        repo_dir: Path to cloned repository
        custom_patterns: Optional list of custom patterns
        baseline_hashes: Optional set of baseline hashes
        
    Returns:
        List of all findings in the repository
    """
    all_findings = []
    scan_tasks = []
    
    try:
        # Walk directory tree
        for root, dirs, files in os.walk(repo_dir):
            # Filter directories in-place to skip unwanted paths
            dirs[:] = [d for d in dirs if not should_skip_path(d)]
            
            for filename in files:
                file_path = Path(root) / filename
                relative_path = str(file_path.relative_to(repo_dir))
                
                # Skip unwanted files
                if should_skip_path(relative_path):
                    continue
                
                # Create scan task
                task = scan_file_async(
                    file_path, 
                    repo_full_name, 
                    relative_path,
                    custom_patterns,
                    baseline_hashes,
                    repo_dir
                )
                scan_tasks.append(task)
        
        # Execute all scan tasks with timeout
        if scan_tasks:
            logger.info(f"Scanning {len(scan_tasks)} files in {repo_full_name}")
            
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*scan_tasks, return_exceptions=True),
                    timeout=SCAN_TIMEOUT_SECONDS
                )
                
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Scan task failed: {result}")
                    elif isinstance(result, list):
                        all_findings.extend(result)
                        
            except asyncio.TimeoutError:
                logger.error(f"Scan timeout for {repo_full_name}")
        
    except Exception as e:
        logger.error(f"Error scanning repo {repo_full_name}: {e}")
    
    return all_findings


# ===================================================================
# MAIN ORCHESTRATION
# ===================================================================

async def scan_organization_async(org_name: str, token: str) -> List[Dict[str, Any]]:
    """
    Main async orchestrator for scanning an entire organization or user.
    
    Args:
        org_name: GitHub organization or user name
        token: GitHub authentication token
        
    Returns:
        List of all findings across all repositories
    """
    all_findings = []
    clone_base = Path(tempfile.mkdtemp(prefix=f"orgscan_{org_name}_"))
    
    # Load custom patterns if specified
    custom_patterns = []
    if CUSTOM_PATTERNS_FILE:
        custom_patterns = load_custom_patterns(CUSTOM_PATTERNS_FILE)
    
    # Load baseline for incremental scanning
    baseline_hashes = set()
    if SCAN_MODE == "incremental":
        baseline_hashes = load_baseline(BASELINE_FILE)
    
    try:
        logger.info(f"Starting scan of organization: {org_name}")
        logger.info(f"Scan mode: {SCAN_MODE}")
        logger.info(f"Clone directory: {clone_base}")
        logger.info(f"Custom patterns: {len(custom_patterns)}")
        logger.info(f"Rate limit: {GITHUB_API_RATE_LIMIT} requests/hour")
        if baseline_hashes:
            logger.info(f"Baseline findings to skip: {len(baseline_hashes)}")
        
        # Initialize GitHub client with rate limiting
        try:
            # Modern authentication
            auth = Auth.Token(token)
            github_client = Github(auth=auth)
            
            # Try to get target as organization first, then fall back to user
            repos = []
            target_type = None
            
            try:
                logger.info(f"Attempting to access {org_name} as organization...")
                org = await github_api_call_with_backoff(github_client.get_organization, org_name)
                repos = await github_api_call_with_backoff(lambda: list(org.get_repos()))
                target_type = "organization"
                logger.info(f"✓ Found {len(repos)} repositories in organization {org_name}")
                
            except GithubException as e:
                if e.status == 404:
                    # Not an organization, try as user
                    logger.info(f"Not an organization, trying {org_name} as user...")
                    org = await github_api_call_with_backoff(github_client.get_user, org_name)
                    repos = await github_api_call_with_backoff(lambda: list(org.get_repos()))
                    target_type = "user"
                    logger.info(f"✓ Found {len(repos)} repositories for user {org_name}")
                else:
                    raise
            
            if not repos:
                logger.warning(f"No repositories found for {org_name}")
                return all_findings
            
        except Exception as e:
            logger.error(f"Failed to access {org_name}: {e}")
            return all_findings
        
        finally:
            # Close the GitHub client connection
            if 'github_client' in locals():
                github_client.close()
        
        # Filter non-archived repos
        active_repos = [repo for repo in repos if not repo.archived]
        logger.info(f"Active (non-archived) repositories: {len(active_repos)}")
        
        if not active_repos:
            logger.warning(f"No active repositories to scan for {org_name}")
            return all_findings
        
        # Create semaphore for controlled concurrency
        clone_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REPOS)
        
        # Clone all repos concurrently with progress bar
        clone_tasks = [
            clone_repo_async(repo.full_name, clone_base, token, clone_semaphore)
            for repo in active_repos
        ]
        
        logger.info(f"Cloning {len(clone_tasks)} repositories...")
        
        cloned_repos = []
        with tqdm(total=len(clone_tasks), desc="Cloning repos", unit="repo") as pbar:
            for coro in asyncio.as_completed(clone_tasks):
                result = await coro
                cloned_repos.append(result)
                pbar.update(1)
        
        # Map results back to repo names
        successful_clones = [
            (active_repos[i].full_name, repo_dir)
            for i, repo_dir in enumerate(cloned_repos)
            if repo_dir is not None and isinstance(repo_dir, Path)
        ]
        
        logger.info(f"Successfully cloned {len(successful_clones)}/{len(clone_tasks)} repositories")
        
        # Scan all cloned repos with progress bar
        scan_tasks = [
            scan_repo_async(repo_name, repo_dir, custom_patterns, baseline_hashes)
            for repo_name, repo_dir in successful_clones
        ]
        
        logger.info(f"Scanning {len(scan_tasks)} repositories for secrets...")
        
        scan_results = []
        with tqdm(total=len(scan_tasks), desc="Scanning repos", unit="repo") as pbar:
            for coro in asyncio.as_completed(scan_tasks):
                result = await coro
                scan_results.append(result)
                pbar.update(1)
        
        # Aggregate findings
        for result in scan_results:
            if isinstance(result, Exception):
                logger.error(f"Scan failed: {result}")
            elif isinstance(result, list):
                all_findings.extend(result)
        
        logger.info(f"Scan complete. Found {len(all_findings)} potential secrets")
        logger.info(f"Rate limiter stats: {rate_limiter.get_stats()}")
        
    except Exception as e:
        logger.error(f"Fatal error during organization scan: {e}")
    
    finally:
        # Cleanup clone directory
        try:
            logger.info(f"Cleaning up clone directory: {clone_base}")
            shutil.rmtree(clone_base, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup clone directory: {e}")
    
    return all_findings


# ===================================================================
# REPORT GENERATION
# ===================================================================

def generate_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """
    Generate reports in requested formats with remediation advice.
    
    Args:
        findings: List of all findings
        output_path: Base path for output files
    """
    try:
        # Add remediation advice to findings
        for finding in findings:
            pattern_type = finding.get("pattern", "GENERIC")
            finding["remediation"] = RemediationAdvice.get_remediation(pattern_type)
        
        # Determine formats to generate
        formats_to_generate = []
        if OUTPUT_FORMAT == "all":
            formats_to_generate = ["json", "csv", "sarif"]
        else:
            formats_to_generate = [OUTPUT_FORMAT]
        
        # Generate each format
        for fmt in formats_to_generate:
            if fmt == "json":
                output_file = output_path.with_suffix(".json")
                generate_json_report(findings, output_file)
                
            elif fmt == "csv":
                output_file = output_path.with_suffix(".csv")
                generate_csv_report(findings, output_file)
                
            elif fmt == "sarif":
                output_file = output_path.with_suffix(".sarif")
                generate_sarif_report(findings, output_file)
        
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")


def generate_json_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Generate JSON report with statistics."""
    try:
        total_findings = len(findings)
        by_classification = Counter(f["classification"] for f in findings)
        by_pattern = Counter(f["pattern"] for f in findings)
        by_repo = Counter(f["repo"] for f in findings)
        
        high_risk = sum(1 for f in findings if f["score"] >= 80)
        medium_risk = sum(1 for f in findings if 50 <= f["score"] < 80)
        low_risk = sum(1 for f in findings if f["score"] < 50)
        
        sorted_findings = sorted(findings, key=lambda x: x["score"], reverse=True)
        
        report = {
            "scan_metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "organization": TARGET_ORG or "local",
                "total_findings": total_findings,
                "scanner_version": "2.5.0",
                "rate_limiter_stats": rate_limiter.get_stats() if TARGET_ORG else None
            },
            "summary": {
                "by_risk_level": {
                    "high_risk": high_risk,
                    "medium_risk": medium_risk,
                    "low_risk": low_risk
                },
                "by_classification": dict(by_classification),
                "by_pattern": dict(by_pattern),
                "top_repos": dict(by_repo.most_common(10))
            },
            "git_history_cleanup": RemediationAdvice.get_git_history_removal_guide(),
            "findings": sorted_findings
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report written to {output_path}")
        logger.info(f"Summary: {high_risk} high-risk, {medium_risk} medium-risk, {low_risk} low-risk")
        
    except Exception as e:
        logger.error(f"Failed to generate JSON report: {e}")


def generate_csv_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Generate CSV report for spreadsheet analysis."""
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'severity', 'score', 'classification', 'pattern', 'repo', 'path', 'line',
                'entropy', 'value_length', 'match_preview', 'timestamp',
                'remediation_summary', 'rotation_command', 'docs_url'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in findings:
                remediation = finding.get('remediation', {})
                
                severity = "CRITICAL" if finding['score'] >= 80 else \
                          "HIGH" if finding['score'] >= 50 else \
                          "MEDIUM" if finding['score'] >= 30 else "LOW"
                
                row = {
                    'severity': severity,
                    'score': finding.get('score', 0),
                    'classification': finding.get('classification', ''),
                    'pattern': finding.get('pattern', ''),
                    'repo': finding.get('repo', ''),
                    'path': finding.get('path', ''),
                    'line': finding.get('line', ''),
                    'entropy': finding.get('entropy', 0),
                    'value_length': finding.get('value_length', 0),
                    'match_preview': finding.get('match_preview', '')[:100],
                    'timestamp': finding.get('timestamp', ''),
                    'remediation_summary': ' | '.join(remediation.get('immediate_actions', [])[:2]),
                    'rotation_command': remediation.get('rotation_command', ''),
                    'docs_url': remediation.get('docs_url', '')
                }
                
                writer.writerow(row)
        
        logger.info(f"CSV report written to {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to generate CSV report: {e}")


def generate_sarif_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Generate SARIF report for GitHub Advanced Security."""
    try:
        # Build rules
        rules = []
        pattern_to_rule_id = {}
        unique_patterns = set(f.get('pattern', 'UNKNOWN') for f in findings)
        
        for idx, pattern in enumerate(sorted(unique_patterns)):
            rule_id = f"secret-scanner/{pattern.lower().replace('_', '-')}"
            pattern_to_rule_id[pattern] = rule_id
            
            remediation = RemediationAdvice.get_remediation(pattern)
            
            rule = {
                "id": rule_id,
                "name": pattern,
                "shortDescription": {
                    "text": f"Potential {pattern.replace('_', ' ')} detected"
                },
                "fullDescription": {
                    "text": f"A potential hardcoded {pattern.replace('_', ' ')} was found in the codebase."
                },
                "defaultConfiguration": {
                    "level": "error" if remediation.get('severity') == 'CRITICAL' else "warning"
                },
                "help": {
                    "text": "\n".join(remediation.get('immediate_actions', [])),
                    "markdown": "## Remediation\n\n" + 
                               "\n".join(f"- {action}" for action in remediation.get('immediate_actions', [])) +
                               f"\n\n[Documentation]({remediation.get('docs_url', '')})"
                },
                "properties": {
                    "tags": ["security", "secrets"],
                    "precision": "high"
                }
            }
            rules.append(rule)
        
        # Build results
        results = []
        for finding in findings:
            pattern = finding.get('pattern', 'UNKNOWN')
            rule_id = pattern_to_rule_id.get(pattern, 'secret-scanner/unknown')
            
            level = "error" if finding['score'] >= 80 else \
                   "warning" if finding['score'] >= 50 else "note"
            
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Potential secret: {pattern} (score: {finding.get('score', 0)}, entropy: {finding.get('entropy', 0):.2f})"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get('path', 'unknown')
                        },
                        "region": {
                            "startLine": finding.get('line', 1),
                            "snippet": {
                                "text": finding.get('context', '')[:200]
                            }
                        }
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": finding.get('hash', '')[:16]
                },
                "properties": {
                    "score": finding.get('score', 0),
                    "entropy": finding.get('entropy', 0),
                    "classification": finding.get('classification', ''),
                    "remediation_command": finding.get('remediation', {}).get('rotation_command', '')
                }
            }
            
            # Add git blame if available
            if 'git_blame' in finding:
                result['properties']['git_author'] = finding['git_blame'].get('author', '')
                result['properties']['git_email'] = finding['git_blame'].get('email', '')
                result['properties']['git_commit'] = finding['git_blame'].get('commit_hash', '')
            
            results.append(result)
        
        # Build SARIF document
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Secret Scanner",
                        "semanticVersion": "2.5.0",
                        "informationUri": "https://github.com/your-org/secret-scanner",
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                }]
            }]
        }
        
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)
        
        logger.info(f"SARIF report written to {output_path}")
        logger.info("Upload to GitHub: gh api repos/:owner/:repo/code-scanning/sarifs -F sarif=@scan_report.sarif")
        
    except Exception as e:
        logger.error(f"Failed to generate SARIF report: {e}")


# ===================================================================
# COMMAND LINE INTERFACE
# ===================================================================

def parse_arguments():
    """Parse command-line arguments and display help information."""
    parser = argparse.ArgumentParser(
        description='Production-grade Git secret scanner for GitHub organizations and local filesystems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
ENVIRONMENT VARIABLES (For GitHub Org Scanning):
  GITHUB_TOKEN          GitHub personal access token
  TARGET_ORG            GitHub organization name to scan

ENVIRONMENT VARIABLES (Optional):
  MAX_CONCURRENT_REPOS  Number of repos to scan in parallel (default: 5)
  MAX_CONCURRENT_FILES  Number of files to scan in parallel (default: 50)
  CLONE_DEPTH           Git shallow clone depth (default: 1)
  MAX_FILE_SIZE_MB      Skip files larger than this in MB (default: 10)
  OUTPUT_FILE           Report output path (default: scan_report.json)
  ENABLE_GIT_BLAME      Enable git blame analysis (default: false)
  LOCAL_SCAN_MAX_DEPTH  Max directory depth for local scans (default: 10)

USAGE EXAMPLES:
  Scan GitHub organization:
    export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    export TARGET_ORG="myorganization"
    python org_secret_scanner.py

  Scan local filesystem:
    python org_secret_scanner.py --local /path/to/projects
    python org_secret_scanner.py --local ~ --max-depth 5
    python org_secret_scanner.py --local . --output-format all

SECURITY NOTICE:
  This scanner NEVER attempts to use discovered credentials.
  Report findings to your security team immediately.

EXIT CODES:
  0   Success
  1   Error (missing config, API failure, etc.)
  130 Interrupted by user (Ctrl+C)
        '''
    )
    
    parser.add_argument(
        '--local',
        type=str,
        metavar='PATH',
        help='Scan local filesystem path instead of GitHub org'
    )
    
    parser.add_argument(
        '--max-depth',
        type=int,
        default=LOCAL_SCAN_MAX_DEPTH,
        help=f'Maximum directory depth for local scans (default: {LOCAL_SCAN_MAX_DEPTH})'
    )
    
    parser.add_argument(
        '--follow-symlinks',
        action='store_true',
        help='Follow symbolic links during local scanning'
    )
    
    parser.add_argument(
        '--custom-patterns',
        type=str,
        metavar='FILE',
        help='Path to custom regex patterns JSON file'
    )
    
    parser.add_argument(
        '--output-format',
        type=str,
        choices=['json', 'csv', 'sarif', 'all'],
        default=OUTPUT_FORMAT,
        help=f'Output format (default: {OUTPUT_FORMAT})'
    )
    
    parser.add_argument(
        '--log-format',
        type=str,
        choices=['text', 'json'],
        default=LOG_FORMAT,
        help=f'Logging format (default: {LOG_FORMAT})'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose debug logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 2.5.0'
    )
    
    return parser.parse_args()


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================

def main():
    """Main entry point with validation and error handling."""
    
    # Parse arguments
    args = parse_arguments()
    
    # Override config from CLI args
    global OUTPUT_FORMAT, LOG_FORMAT, CUSTOM_PATTERNS_FILE, logger
    if hasattr(args, 'output_format') and args.output_format:
        OUTPUT_FORMAT = args.output_format
    if hasattr(args, 'log_format') and args.log_format:
        LOG_FORMAT = args.log_format
        logger = setup_logging(LOG_FORMAT)
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Override custom patterns file if provided via CLI
    if args.custom_patterns:
        CUSTOM_PATTERNS_FILE = args.custom_patterns
    
    # Determine scan mode
    if args.local:
        # LOCAL FILESYSTEM SCANNING
        scan_path = Path(args.local).expanduser().resolve()
        
        if not scan_path.exists():
            logger.error(f"Path does not exist: {scan_path}")
            return 1
        
        if not scan_path.is_dir():
            logger.error(f"Path is not a directory: {scan_path}")
            return 1
        
        logger.info("=" * 70)
        logger.info("LOCAL FILESYSTEM SECRET SCANNER")
        logger.info("=" * 70)
        logger.info(f"Scan path: {scan_path}")
        logger.info(f"Max depth: {args.max_depth}")
        logger.info(f"Follow symlinks: {args.follow_symlinks}")
        logger.info(f"Max file size: {MAX_FILE_SIZE_MB} MB")
        logger.info(f"Output format: {OUTPUT_FORMAT}")
        logger.info(f"Platform: {platform.system()}")
        logger.info("=" * 70)
        
        try:
            # Load custom patterns
            custom_patterns = []
            if CUSTOM_PATTERNS_FILE:
                custom_patterns = load_custom_patterns(CUSTOM_PATTERNS_FILE)
            
            # Load baseline
            baseline_hashes = set()
            if SCAN_MODE == "incremental":
                baseline_hashes = load_baseline(BASELINE_FILE)
            
            # Run local scan
            findings = asyncio.run(
                LocalFilesystemScanner.scan_local_path(
                    scan_path,
                    args.max_depth,
                    custom_patterns,
                    baseline_hashes,
                    args.follow_symlinks
                )
            )
            
            # Generate report
            generate_report(findings, OUTPUT_FILE)
            
            logger.info("=" * 70)
            logger.info("LOCAL SCAN COMPLETED SUCCESSFULLY")
            logger.info("=" * 70)
            
            return 0
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            return 130
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            return 1
    
    else:
        # GITHUB ORGANIZATION SCANNING
        if not GITHUB_TOKEN:
            logger.error("=" * 70)
            logger.error("ERROR: GITHUB_TOKEN environment variable not set")
            logger.error("=" * 70)
            logger.error("")
            logger.error("Please set your GitHub token:")
            logger.error("  export GITHUB_TOKEN=\"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"")
            logger.error("")
            logger.error("Create a token at: https://github.com/settings/tokens")
            logger.error("For help: python org_secret_scanner.py --help")
            logger.error("=" * 70)
            return 1
        
        if not TARGET_ORG:
            logger.error("=" * 70)
            logger.error("ERROR: TARGET_ORG environment variable not set")
            logger.error("=" * 70)
            logger.error("")
            logger.error("Please set the organization to scan:")
            logger.error("  export TARGET_ORG=\"myorganization\"")
            logger.error("")
            logger.error("For help: python org_secret_scanner.py --help")
            logger.error("=" * 70)
            return 1
        
        logger.info("="*70)
        logger.info("PRODUCTION GIT SECRET SCANNER")
        logger.info("="*70)
        logger.info(f"Organization: {TARGET_ORG}")
        logger.info(f"Max concurrent repos: {MAX_CONCURRENT_REPOS}")
        logger.info(f"Clone depth: {CLONE_DEPTH}")
        logger.info(f"Output format: {OUTPUT_FORMAT}")
        logger.info(f"Git blame enabled: {ENABLE_GIT_BLAME}")
        logger.info("="*70)
        
        try:
            # Run async scan
            findings = asyncio.run(scan_organization_async(TARGET_ORG, GITHUB_TOKEN))
            
            # Generate report
            generate_report(findings, OUTPUT_FILE)
            
            logger.info("="*70)
            logger.info("SCAN COMPLETED SUCCESSFULLY")
            logger.info("="*70)
            
            return 0
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            return 130
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            return 1


if __name__ == "__main__":
    exit(main())
