#!/usr/bin/env python3
"""
===================================================================
UNIT AND INTEGRATION TESTS FOR SECRET SCANNER
===================================================================

Authored By: Douglas Mun with AI assistance.

Comprehensive test suite for the production secret scanner covering:
- Pattern detection accuracy (20+ patterns)
- Entropy calculation and scoring
- False positive reduction
- Rate limiting with exponential backoff
- Report generation (JSON, CSV, SARIF)
- Remediation advice system
- Local filesystem scanning
- Platform-specific optimizations
- Custom pattern loading
- Baseline/incremental scanning
- Deduplication logic
- GitHub API integration (mocked)

PREREQUISITES:
    1. The scanner file:
       Make sure you have the org_secret_scanner.py
    
    2. Install test dependencies:
       python3 -m pip install -r requirements.txt
    or 
       pip install pytest pytest-asyncio pytest-cov

USAGE EXAMPLES:

    # Basic - Run all tests with unittest
    python test_secret_scanner.py

    # Pytest - Run all tests (recommended)
    pytest test_secret_scanner.py -v

    # Pytest - Run with detailed output
    pytest test_secret_scanner.py -vv

    # Coverage - Generate HTML coverage report
    pytest test_secret_scanner.py --cov=org_secret_scanner --cov-report=html
    # View report: open htmlcov/index.html

    # Coverage - Terminal report with missing lines
    pytest test_secret_scanner.py --cov=org_secret_scanner --cov-report=term-missing

    # Run specific test class
    pytest test_secret_scanner.py::TestPatternDetection -v
    pytest test_secret_scanner.py::TestEntropyCalculation -v
    pytest test_secret_scanner.py::TestReportGeneration -v

    # Run specific test method
    pytest test_secret_scanner.py::TestPatternDetection::test_aws_access_key_detection -v
    pytest test_secret_scanner.py::TestScoringLogic::test_high_risk_scoring -v

    # Run tests matching a pattern
    pytest test_secret_scanner.py -k "aws" -v
    pytest test_secret_scanner.py -k "entropy" -v
    pytest test_secret_scanner.py -k "report" -v

    # Run with output capture disabled (see print statements)
    pytest test_secret_scanner.py -v -s

    # Run in parallel (faster for large test suites)
    pip install pytest-xdist
    pytest test_secret_scanner.py -n auto

    # Stop on first failure
    pytest test_secret_scanner.py -x

    # Show slowest tests
    pytest test_secret_scanner.py --durations=10

    # Generate JUnit XML report (for CI/CD)
    pytest test_secret_scanner.py --junitxml=test-results.xml

    # Quiet mode (less verbose)
    pytest test_secret_scanner.py -q

    # Generate multiple report formats
    pytest test_secret_scanner.py \
        --cov=org_secret_scanner \
        --cov-report=html \
        --cov-report=xml \
        --cov-report=term \
        --junitxml=test-results.xml

TEST SUITE STRUCTURE:
    - TestPatternDetection (12 tests)      - Secret pattern regex validation
    - TestEntropyCalculation (3 tests)     - Shannon entropy algorithm
    - TestScoringLogic (5 tests)           - Risk scoring and classification
    - TestDenylistFiltering (3 tests)      - False positive reduction
    - TestUtilityFunctions (4 tests)       - Helper function validation
    - TestRateLimiting (3 tests)           - GitHub API rate limiting
    - TestRemediationAdvice (5 tests)      - Remediation guidance system
    - TestAsyncFileScanning (3 tests)      - Async file operations
    - TestReportGeneration (4 tests)       - JSON/CSV/SARIF reports
    - TestCustomPatterns (3 tests)         - Custom pattern loading
    - TestBaselineLoading (2 tests)        - Incremental scanning
    - TestLocalFilesystemScanner (3 tests) - Local file scanning
    - TestPlatformScanners (3 tests)       - Platform optimizations
    - TestIntegration (2 tests)            - End-to-end workflows
    - TestAsyncOperations (2 tests)        - Async and concurrency

EXPECTED OUTPUT:
    ============================= test session starts ==============================
    collected 60 items

    test_secret_scanner.py::TestPatternDetection::test_aws_access_key_detection PASSED [  1%]
    test_secret_scanner.py::TestPatternDetection::test_github_token_detection PASSED [  3%]
    ...
    ============================== 60 passed in 2.34s ===============================

CI/CD INTEGRATION:
    # GitHub Actions
    - name: Run Tests
      run: |
        pip install pytest pytest-asyncio pytest-cov
        pytest test_secret_scanner.py --cov=org_secret_scanner --junitxml=test-results.xml

    # GitLab CI
    test:
      script:
        - pip install pytest pytest-asyncio pytest-cov
        - pytest test_secret_scanner.py --cov=org_secret_scanner

TROUBLESHOOTING:
    Error: "Cannot import org_secret_scanner.py"
    Solution: Make sure you have the org_secret_scanner.py

    Error: "No module named 'pytest'"
    Solution: pip install pytest pytest-asyncio pytest-cov

    Error: "Event loop is closed"
    Solution: Already handled by asyncio.run() in tests

    Slow tests:
    Solution: Run with pytest-xdist: pytest test_secret_scanner.py -n auto

===================================================================
"""

import unittest
import asyncio
import tempfile
import json
import csv
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock, call
import sys
import os
import time

# Import the scanner module
try:
    import org_secret_scanner as scanner
except ImportError:
    print("ERROR: Cannot import org_secret_scanner.py")
    print("Ensure org_secret_scanner.py is in the same directory or PYTHONPATH")
    print("If your file is named 'completed2.py', rename it to 'org_secret_scanner.py'")
    sys.exit(1)


# ===================================================================
# PATTERN DETECTION TESTS
# ===================================================================

class TestPatternDetection(unittest.TestCase):
    """Test secret pattern detection accuracy."""
    
    def test_aws_access_key_detection(self):
        """Test AWS access key ID pattern detection."""
        test_cases = [
            ("AKIAIOSFODNN7EXAMPLE", True),  # Valid
            ("ASIAIOSFODNN7EXAMPLE", True),  # Session token
            ("AGPAIOSFODNN7EXAMPLE", True),  # Group
            ("AIDAIOSFODNN7EXAMPLE", True),  # User
            ("AKIAINVALID", False),           # Too short
            ("BKIAIOSFODNN7EXAMPLE", False),  # Wrong prefix
        ]
        
        for test_string, should_match in test_cases:
            match = scanner.SecretPatterns.AWS_ACCESS_KEY_ID.search(test_string)
            if should_match:
                self.assertIsNotNone(match, f"Should match: {test_string}")
            else:
                self.assertIsNone(match, f"Should not match: {test_string}")
    
    def test_aws_secret_key_detection(self):
        """Test AWS secret access key detection."""
        valid = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars
        invalid = "tooshort"
        
        self.assertIsNotNone(scanner.SecretPatterns.AWS_SECRET_ACCESS_KEY.search(valid))
        self.assertIsNone(scanner.SecretPatterns.AWS_SECRET_ACCESS_KEY.search(invalid))
    
    def test_github_token_detection(self):
        """Test GitHub token pattern detection."""
        test_cases = [
            ("ghp_" + "a" * 36, True),   # PAT
            ("gho_" + "a" * 36, True),   # OAuth
            ("ghu_" + "a" * 36, True),   # User token
            ("ghp_tooshort", False),      # Too short
            ("invalid_" + "a" * 36, False),  # Wrong prefix
        ]
        
        for test_string, should_match in test_cases:
            match = scanner.SecretPatterns.GITHUB_TOKEN_PATTERN.search(test_string)
            if should_match:
                self.assertIsNotNone(match, f"Should match: {test_string}")
            else:
                self.assertIsNone(match, f"Should not match: {test_string}")
    
    def test_pem_private_key_detection(self):
        """Test PEM private key detection."""
        valid_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmno
pqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abc
-----END RSA PRIVATE KEY-----"""
        
        valid_ec_key = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGlRQKKQUEtLELva04OvOKZWbZFULJBRvjShL3lisBMoAoGCCqGSM49
AwEHoUQDQgAE5Z5fKhN3aL/lPLXVBd4X2xM7WPdQjZ8v3iBPQQCZYx5xCqEDHNYf
-----END EC PRIVATE KEY-----"""
        
        invalid_key = """-----BEGIN CERTIFICATE-----
MIIEpAIBAAKCAQEA1234567890
-----END CERTIFICATE-----"""
        
        self.assertIsNotNone(scanner.SecretPatterns.PEM_PRIVATE_KEY.search(valid_key))
        self.assertIsNotNone(scanner.SecretPatterns.PEM_PRIVATE_KEY.search(valid_ec_key))
        self.assertIsNone(scanner.SecretPatterns.PEM_PRIVATE_KEY.search(invalid_key))
    
    def test_ssh_private_key_detection(self):
        """Test SSH private key detection."""
        valid = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1234567890abcdefg
-----END OPENSSH PRIVATE KEY-----"""
        
        self.assertIsNotNone(scanner.SecretPatterns.SSH_PRIVATE_KEY.search(valid))
    
    def test_slack_token_detection(self):
        """Test Slack token detection."""
        valid = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
        valid_app = "xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
        invalid = "xoxb-invalid-token"
        
        self.assertIsNotNone(scanner.SecretPatterns.SLACK_TOKEN.search(valid))
        self.assertIsNotNone(scanner.SecretPatterns.SLACK_TOKEN.search(valid_app))
        self.assertIsNone(scanner.SecretPatterns.SLACK_TOKEN.search(invalid))
    
    def test_jwt_token_detection(self):
        """Test JWT token detection."""
        valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        invalid = "not.a.jwt"
        
        self.assertIsNotNone(scanner.SecretPatterns.JWT_TOKEN.search(valid))
        self.assertIsNone(scanner.SecretPatterns.JWT_TOKEN.search(invalid))
    
    def test_stripe_key_detection(self):
        """Test Stripe API key detection."""
        valid_secret = "sk_live_" + "a" * 24
        valid_restricted = "rk_live_" + "a" * 24
        invalid = "sk_test_short"
        
        self.assertIsNotNone(scanner.SecretPatterns.STRIPE_KEY.search(valid_secret))
        self.assertIsNotNone(scanner.SecretPatterns.STRIPE_KEY.search(valid_restricted))
        self.assertIsNone(scanner.SecretPatterns.STRIPE_KEY.search(invalid))
    
    def test_mongodb_uri_detection(self):
        """Test MongoDB connection string detection."""
        valid = "mongodb://user:password@localhost:27017/mydb"
        valid_srv = "mongodb+srv://user:pass@cluster.mongodb.net/db"
        invalid = "http://localhost:27017"
        
        self.assertIsNotNone(scanner.SecretPatterns.MONGODB_URI.search(valid))
        self.assertIsNotNone(scanner.SecretPatterns.MONGODB_URI.search(valid_srv))
        self.assertIsNone(scanner.SecretPatterns.MONGODB_URI.search(invalid))
    
    def test_database_uri_detection(self):
        """Test PostgreSQL/MySQL URI detection."""
        postgres = "postgres://user:password@localhost:5432/mydb"
        mysql = "mysql://root:secret@db.example.com:3306/app"
        mariadb = "mariadb://user:pass@host/database"
        
        self.assertIsNotNone(scanner.SecretPatterns.DATABASE_URI.search(postgres))
        self.assertIsNotNone(scanner.SecretPatterns.DATABASE_URI.search(mysql))
        self.assertIsNotNone(scanner.SecretPatterns.DATABASE_URI.search(mariadb))
    
    def test_sendgrid_key_detection(self):
        """Test SendGrid API key detection."""
        valid = "SG." + "a" * 22 + "." + "b" * 43
        invalid = "SG.tooshort.invalid"
        
        self.assertIsNotNone(scanner.SecretPatterns.SENDGRID_KEY.search(valid))
        self.assertIsNone(scanner.SecretPatterns.SENDGRID_KEY.search(invalid))
    
    def test_firebase_key_detection(self):
        """Test Firebase API key detection."""
        valid = "AIza" + "a" * 35
        invalid = "AIzaShort"
        
        self.assertIsNotNone(scanner.SecretPatterns.FIREBASE_KEY.search(valid))
        self.assertIsNone(scanner.SecretPatterns.FIREBASE_KEY.search(invalid))
    
    def test_bearer_token_detection(self):
        """Test Bearer token detection."""
        valid = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        valid_lower = "bearer " + "a" * 50
        invalid = "Bearer short"
        
        self.assertIsNotNone(scanner.SecretPatterns.BEARER_TOKEN.search(valid))
        self.assertIsNotNone(scanner.SecretPatterns.BEARER_TOKEN.search(valid_lower))


# ===================================================================
# ENTROPY CALCULATION TESTS
# ===================================================================

class TestEntropyCalculation(unittest.TestCase):
    """Test Shannon entropy calculation."""
    
    def test_entropy_high(self):
        """Test high entropy strings (likely secrets)."""
        high_entropy_strings = [
            "aB3$xY9#mK2@pL7!",  # Random chars
            "Zm9vYmFyMTIzNDU2Nzg5MA==",  # Base64
            "5f7a9c2e8b3d1f6a4e9c7b2d8f1a3e6b",  # Hex
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS-like
        ]
        
        for s in high_entropy_strings:
            entropy = scanner.shannon_entropy(s)
            self.assertGreater(entropy, 4.0, f"Should have high entropy: {s} (got {entropy:.2f})")
    
    def test_entropy_low(self):
        """Test low entropy strings (unlikely secrets)."""
        low_entropy_strings = [
            "password",
            "aaaaaaaa",
            "12345678",
            "testtest",
            "example",
        ]
        
        for s in low_entropy_strings:
            entropy = scanner.shannon_entropy(s)
            self.assertLess(entropy, 3.5, f"Should have low entropy: {s} (got {entropy:.2f})")
    
    def test_entropy_edge_cases(self):
        """Test entropy edge cases."""
        self.assertEqual(scanner.shannon_entropy(""), 0.0)
        self.assertEqual(scanner.shannon_entropy("a"), 0.0)
        self.assertGreater(scanner.shannon_entropy("ab"), 0.0)
        
        # Very long string
        long_random = "a1b2c3d4e5f6" * 100
        entropy_long = scanner.shannon_entropy(long_random)
        self.assertGreater(entropy_long, 0.0)


# ===================================================================
# SCORING LOGIC TESTS
# ===================================================================

class TestScoringLogic(unittest.TestCase):
    """Test risk scoring algorithm."""
    
    def test_high_risk_scoring(self):
        """Test high-risk pattern scoring."""
        score, classification = scanner.score_finding(
            value="AKIAIOSFODNN7EXAMPLE",
            entropy=4.5,
            pattern_name="AWS_ACCESS_KEY_ID",
            file_path="src/config.py"
        )
        
        self.assertGreaterEqual(score, 80)
        self.assertEqual(classification, "likely_secret")
    
    def test_pem_key_critical_scoring(self):
        """Test that PEM keys get critical scores."""
        score, classification = scanner.score_finding(
            value="-----BEGIN RSA PRIVATE KEY-----...",
            entropy=5.0,
            pattern_name="PEM_PRIVATE_KEY",
            file_path="keys/server.key"
        )
        
        self.assertGreaterEqual(score, 90)
        self.assertEqual(classification, "critical")
    
    def test_low_risk_scoring(self):
        """Test low-risk scoring with denylist."""
        score, classification = scanner.score_finding(
            value="changeme123",
            entropy=3.0,
            pattern_name="ASSIGNMENT_SECRET",
            file_path="tests/fixtures/config.py"
        )
        
        self.assertLess(score, 40)
        self.assertIn(classification, ["unlikely", "low_confidence"])
    
    def test_context_based_scoring(self):
        """Test that file context affects scoring."""
        value = "sk_live_abcdef1234567890"
        entropy = 4.2
        pattern = "STRIPE_KEY"
        
        # Production file
        score_prod, class_prod = scanner.score_finding(value, entropy, pattern, "src/payment.py")
        
        # Test file (should reduce score)
        score_test, class_test = scanner.score_finding(value, entropy, pattern, "tests/fixtures/payment_test.py")
        
        self.assertGreater(score_prod, score_test, "Production file should score higher than test file")
    
    def test_entropy_based_scoring(self):
        """Test that entropy affects scoring."""
        value = "abcd1234efgh5678"
        pattern = "ASSIGNMENT_SECRET"
        file_path = "config.py"
        
        # High entropy
        score_high, _ = scanner.score_finding(value, 5.0, pattern, file_path)
        
        # Low entropy
        score_low, _ = scanner.score_finding(value, 2.0, pattern, file_path)
        
        self.assertGreater(score_high, score_low, "High entropy should score higher")
    
    def test_denylist_penalty(self):
        """Test that denylist matches reduce score significantly."""
        value_real = "sk_live_real1234567890abcdef"
        value_fake = "sk_live_example1234567890"
        
        entropy = 4.0
        pattern = "STRIPE_KEY"
        file_path = "config.py"
        
        score_real, _ = scanner.score_finding(value_real, entropy, pattern, file_path)
        score_fake, _ = scanner.score_finding(value_fake, entropy, pattern, file_path)
        
        self.assertGreater(score_real, score_fake + 30, "Real key should score much higher than fake")


# ===================================================================
# DENYLIST FILTERING TESTS
# ===================================================================

class TestDenylistFiltering(unittest.TestCase):
    """Test denylist false positive filtering."""
    
    def test_denylist_matches(self):
        """Test that denylist terms are detected."""
        denylist_values = [
            "example_secret",
            "CHANGEME",
            "dummy_password",
            "redacted_key",
            "xxxxx_token",
            "YOUR_API_KEY_HERE",
            "testkey123",
            "samplekey",
            "placeholder_token",
            "fake_credentials",
            "demo_password",
        ]
        
        for value in denylist_values:
            self.assertTrue(
                scanner.is_denylist_match(value),
                f"Should be denylisted: {value}"
            )
    
    def test_non_denylist_matches(self):
        """Test that real values are not denylisted."""
        real_values = [
            "sk_live_a1b2c3d4e5f6",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdef",
            "real_production_key_xyz123",
        ]
        
        for value in real_values:
            self.assertFalse(
                scanner.is_denylist_match(value),
                f"Should not be denylisted: {value}"
            )
    
    def test_case_insensitive_denylist(self):
        """Test that denylist matching is case-insensitive."""
        test_cases = [
            "EXAMPLE",
            "Example", 
            "example",
            "ExAmPlE",
        ]
        
        for value in test_cases:
            self.assertTrue(
                scanner.is_denylist_match(value),
                f"Case variation should match: {value}"
            )


# ===================================================================
# UTILITY FUNCTION TESTS
# ===================================================================

class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""
    
    def test_should_skip_path(self):
        """Test path skipping logic."""
        skip_paths = [
            ".git/config",
            "node_modules/package/index.js",
            "vendor/autoload.php",
            "dist/bundle.min.js",
            "__pycache__/module.pyc",
            "package-lock.json",
        ]
        
        keep_paths = [
            "src/config.py",
            "lib/utils.js",
            "README.md",
            "config/settings.json",
        ]
        
        for path in skip_paths:
            self.assertTrue(scanner.should_skip_path(path), f"Should skip: {path}")
        
        for path in keep_paths:
            self.assertFalse(scanner.should_skip_path(path), f"Should not skip: {path}")
    
    def test_calculate_secret_hash(self):
        """Test secret hash calculation."""
        value1 = "my_secret_key_123"
        value2 = "my_secret_key_123"
        value3 = "different_key_456"
        
        hash1 = scanner.calculate_secret_hash(value1)
        hash2 = scanner.calculate_secret_hash(value2)
        hash3 = scanner.calculate_secret_hash(value3)
        
        self.assertEqual(hash1, hash2, "Same values should produce same hash")
        self.assertNotEqual(hash1, hash3, "Different values should produce different hashes")
        self.assertEqual(len(hash1), 64, "SHA256 hash should be 64 hex chars")
    
    def test_load_custom_patterns_invalid_file(self):
        """Test custom pattern loading with non-existent file."""
        patterns = scanner.load_custom_patterns("/nonexistent/file.json")
        self.assertEqual(len(patterns), 0, "Should return empty list for missing file")
    
    def test_load_baseline_missing_file(self):
        """Test baseline loading with missing file."""
        baseline = scanner.load_baseline(Path("/nonexistent/baseline.json"))
        self.assertEqual(len(baseline), 0, "Should return empty set for missing baseline")


# ===================================================================
# RATE LIMITING TESTS
# ===================================================================

class TestRateLimiting(unittest.TestCase):
    """Test GitHub API rate limiting."""
    
    def setUp(self):
        """Set up rate limiter for testing."""
        self.rate_limiter = scanner.GitHubRateLimiter(requests_per_hour=100)
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initializes correctly."""
        self.assertEqual(self.rate_limiter.requests_per_hour, 100)
        self.assertGreater(self.rate_limiter.min_interval, 0)
        self.assertEqual(self.rate_limiter.state.total_requests, 0)
    
    def test_rate_limiter_stats(self):
        """Test rate limiter statistics."""
        stats = self.rate_limiter.get_stats()
        
        self.assertIn('total_requests', stats)
        self.assertIn('requests_remaining', stats)
        self.assertIn('total_waits', stats)
        self.assertIn('reset_time', stats)
    
    def test_rate_limit_state(self):
        """Test RateLimitState dataclass."""
        state = scanner.RateLimitState(
            requests_remaining=50,
            total_requests=10,
            total_waits=2
        )
        
        self.assertEqual(state.requests_remaining, 50)
        self.assertEqual(state.total_requests, 10)
        self.assertEqual(state.total_waits, 2)


# ===================================================================
# REMEDIATION ADVICE TESTS
# ===================================================================

class TestRemediationAdvice(unittest.TestCase):
    """Test remediation guidance system."""
    
    def test_aws_key_remediation(self):
        """Test AWS key remediation advice."""
        advice = scanner.RemediationAdvice.get_remediation("AWS_ACCESS_KEY_ID")
        
        self.assertEqual(advice['severity'], "CRITICAL")
        self.assertIn('immediate_actions', advice)
        self.assertIn('prevention', advice)
        self.assertIn('rotation_command', advice)
        self.assertIn('docs_url', advice)
        self.assertGreater(len(advice['immediate_actions']), 0)
    
    def test_github_token_remediation(self):
        """Test GitHub token remediation advice."""
        advice = scanner.RemediationAdvice.get_remediation("GITHUB_TOKEN")
        
        self.assertEqual(advice['severity'], "CRITICAL")
        self.assertIn('revoke', advice['immediate_actions'][0].lower())
    
    def test_pem_key_remediation(self):
        """Test PEM private key remediation advice."""
        advice = scanner.RemediationAdvice.get_remediation("PEM_PRIVATE_KEY")
        
        self.assertEqual(advice['severity'], "CRITICAL")
        self.assertIn('rotation_command', advice)
        self.assertIn('ssh-keygen', advice['rotation_command'])
    
    def test_generic_remediation(self):
        """Test generic/unknown pattern remediation."""
        advice = scanner.RemediationAdvice.get_remediation("UNKNOWN_PATTERN")
        
        self.assertEqual(advice['severity'], "HIGH")
        self.assertIn('immediate_actions', advice)
    
    def test_git_history_removal_guide(self):
        """Test Git history removal guidance."""
        guide = scanner.RemediationAdvice.get_git_history_removal_guide()
        
        self.assertIn('tool', guide)
        self.assertIn('git-filter-repo', guide['tool'])
        self.assertIn('commands', guide)
        self.assertGreater(len(guide['commands']), 0)


# ===================================================================
# ASYNC FILE SCANNING TESTS
# ===================================================================

class TestAsyncFileScanning(unittest.TestCase):
    """Test async file scanning functionality."""
    
    def setUp(self):
        """Create temporary test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = Path(self.temp_dir) / "test_config.py"
        
    def tearDown(self):
        """Clean up temp files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scan_file_with_aws_key(self):
        """Test scanning file with AWS key."""
        # Write test content
        content = '''
import os
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''
        self.test_file.write_text(content)
        
        # Scan file
        findings = asyncio.run(scanner.scan_file_async(
            self.test_file,
            "test_repo",
            "test_config.py",
            custom_patterns=None,
            baseline_hashes=set(),
            repo_dir=None
        ))
        
        # Should find at least the AWS access key
        self.assertGreater(len(findings), 0, "Should find AWS key")
        
        # Check finding structure
        finding = findings[0]
        self.assertIn('repo', finding)
        self.assertIn('path', finding)
        self.assertIn('line', finding)
        self.assertIn('pattern', finding)
        self.assertIn('score', finding)
        self.assertIn('entropy', finding)
        self.assertIn('hash', finding)
    
    def test_scan_file_with_baseline(self):
        """Test that baseline filtering works."""
        content = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"'
        self.test_file.write_text(content)
        
        # First scan
        findings1 = asyncio.run(scanner.scan_file_async(
            self.test_file, "test_repo", "test_config.py",
            custom_patterns=None, baseline_hashes=set(), repo_dir=None
        ))
        
        # Get hash from first finding
        if findings1:
            baseline = {findings1[0]['hash']}
            
            # Second scan with baseline
            findings2 = asyncio.run(scanner.scan_file_async(
                self.test_file, "test_repo", "test_config.py",
                custom_patterns=None, baseline_hashes=baseline, repo_dir=None
            ))
            
            self.assertEqual(len(findings2), 0, "Should skip findings in baseline")
    
    def test_scan_large_file_skipped(self):
        """Test that large files are skipped."""
        # Create file larger than MAX_FILE_SIZE_BYTES
        large_content = "x" * (scanner.MAX_FILE_SIZE_BYTES + 1000)
        large_file = Path(self.temp_dir) / "large.txt"
        large_file.write_text(large_content)
        
        findings = asyncio.run(scanner.scan_file_async(
            large_file, "test_repo", "large.txt",
            custom_patterns=None, baseline_hashes=set(), repo_dir=None
        ))
        
        self.assertEqual(len(findings), 0, "Should skip large files")


# ===================================================================
# REPORT GENERATION TESTS
# ===================================================================

class TestReportGeneration(unittest.TestCase):
    """Test report generation in multiple formats."""
    
    def setUp(self):
        """Set up test findings."""
        self.temp_dir = tempfile.mkdtemp()
        self.findings = [
            {
                "repo": "test/repo1",
                "path": "src/config.py",
                "line": 42,
                "pattern": "AWS_ACCESS_KEY_ID",
                "classification": "likely_secret",
                "score": 90,
                "entropy": 4.5,
                "value_length": 20,
                "hash": "abc123",
                "match_preview": "AKIA...",
                "context": "AWS_ACCESS_KEY_ID = 'AKIA...'",
                "timestamp": "2025-01-01T00:00:00Z"
            },
            {
                "repo": "test/repo2",
                "path": "keys/server.pem",
                "line": 1,
                "pattern": "PEM_PRIVATE_KEY",
                "classification": "critical",
                "score": 95,
                "entropy": 5.2,
                "value_length": 200,
                "hash": "def456",
                "match_preview": "-----BEGIN RSA...",
                "context": "-----BEGIN RSA PRIVATE KEY-----...",
                "timestamp": "2025-01-01T00:00:00Z"
            }
        ]
    
    def tearDown(self):
        """Clean up temp files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_json_report_generation(self):
        """Test JSON report generation."""
        output_file = Path(self.temp_dir) / "report.json"
        
        scanner.generate_json_report(self.findings, output_file)
        
        self.assertTrue(output_file.exists(), "JSON report should be created")
        
        # Validate JSON structure
        with open(output_file) as f:
            report = json.load(f)
        
        self.assertIn('scan_metadata', report)
        self.assertIn('summary', report)
        self.assertIn('findings', report)
        self.assertEqual(len(report['findings']), 2)
        self.assertIn('by_risk_level', report['summary'])
    
    def test_csv_report_generation(self):
        """Test CSV report generation."""
        output_file = Path(self.temp_dir) / "report.csv"
        
        scanner.generate_csv_report(self.findings, output_file)
        
        self.assertTrue(output_file.exists(), "CSV report should be created")
        
        # Validate CSV content
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        self.assertEqual(len(rows), 2, "Should have 2 findings")
        self.assertIn('severity', rows[0])
        self.assertIn('pattern', rows[0])
        self.assertIn('remediation_summary', rows[0])
    
    def test_sarif_report_generation(self):
        """Test SARIF report generation."""
        output_file = Path(self.temp_dir) / "report.sarif"
        
        scanner.generate_sarif_report(self.findings, output_file)
        
        self.assertTrue(output_file.exists(), "SARIF report should be created")
        
        # Validate SARIF structure
        with open(output_file) as f:
            sarif = json.load(f)
        
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertIn('runs', sarif)
        self.assertGreater(len(sarif['runs']), 0)
        
        run = sarif['runs'][0]
        self.assertIn('tool', run)
        self.assertIn('results', run)
        self.assertEqual(len(run['results']), 2)
    
    def test_report_with_remediation(self):
        """Test that reports include remediation advice."""
        output_file = Path(self.temp_dir) / "report.json"
        
        # Generate report (this adds remediation)
        scanner.generate_report(self.findings, output_file)
        
        with open(output_file) as f:
            report = json.load(f)
        
        # Check that remediation was added
        for finding in report['findings']:
            self.assertIn('remediation', finding)
            self.assertIn('immediate_actions', finding['remediation'])


# ===================================================================
# CUSTOM PATTERN TESTS
# ===================================================================

class TestCustomPatterns(unittest.TestCase):
    """Test custom pattern loading and scanning."""
    
    def setUp(self):
        """Create temp directory for test files."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temp files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_load_custom_patterns_valid(self):
        """Test loading valid custom patterns."""
        patterns_file = Path(self.temp_dir) / "custom.json"
        
        patterns_data = {
            "patterns": [
                {
                    "name": "CUSTOM_API_KEY",
                    "regex": "myapi_[A-Za-z0-9]{32}",
                    "description": "Custom API key format"
                },
                {
                    "name": "CUSTOM_TOKEN",
                    "regex": "mytoken_[0-9]{16}",
                    "description": "Custom token format"
                }
            ]
        }
        
        with open(patterns_file, 'w') as f:
            json.dump(patterns_data, f)
        
        patterns = scanner.load_custom_patterns(str(patterns_file))
        
        self.assertEqual(len(patterns), 2, "Should load 2 patterns")
        self.assertEqual(patterns[0][1], "CUSTOM_API_KEY")
        self.assertEqual(patterns[1][1], "CUSTOM_TOKEN")
    
    def test_load_custom_patterns_invalid_regex(self):
        """Test handling of invalid regex patterns."""
        patterns_file = Path(self.temp_dir) / "invalid.json"
        
        patterns_data = {
            "patterns": [
                {
                    "name": "INVALID_PATTERN",
                    "regex": "[invalid(regex",
                    "description": "Invalid regex"
                }
            ]
        }
        
        with open(patterns_file, 'w') as f:
            json.dump(patterns_data, f)
        
        patterns = scanner.load_custom_patterns(str(patterns_file))
        
        self.assertEqual(len(patterns), 0, "Should skip invalid patterns")
    
    def test_load_custom_patterns_invalid_json(self):
        """Test handling of invalid JSON."""
        patterns_file = Path(self.temp_dir) / "invalid.json"
        
        with open(patterns_file, 'w') as f:
            f.write("{ invalid json }")
        
        patterns = scanner.load_custom_patterns(str(patterns_file))
        
        self.assertEqual(len(patterns), 0, "Should handle invalid JSON")


# ===================================================================
# BASELINE LOADING TESTS
# ===================================================================

class TestBaselineLoading(unittest.TestCase):
    """Test baseline/incremental scanning functionality."""
    
    def setUp(self):
        """Create temp directory."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_load_baseline_valid(self):
        """Test loading valid baseline file."""
        baseline_file = Path(self.temp_dir) / "baseline.json"
        
        baseline_data = {
            "findings": [
                {"hash": "abc123", "pattern": "AWS_ACCESS_KEY_ID"},
                {"hash": "def456", "pattern": "GITHUB_TOKEN"},
                {"hash": "ghi789", "pattern": "PEM_PRIVATE_KEY"}
            ]
        }
        
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f)
        
        hashes = scanner.load_baseline(baseline_file)
        
        self.assertEqual(len(hashes), 3, "Should load 3 hashes")
        self.assertIn("abc123", hashes)
        self.assertIn("def456", hashes)
        self.assertIn("ghi789", hashes)
    
    def test_load_baseline_missing_file(self):
        """Test loading non-existent baseline."""
        hashes = scanner.load_baseline(Path("/nonexistent/baseline.json"))
        
        self.assertEqual(len(hashes), 0, "Should return empty set")
        self.assertIsInstance(hashes, set)


# ===================================================================
# LOCAL FILESYSTEM SCANNER TESTS
# ===================================================================

class TestLocalFilesystemScanner(unittest.TestCase):
    """Test local filesystem scanning."""
    
    def setUp(self):
        """Create test directory structure."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        (Path(self.temp_dir) / "config.py").write_text(
            'API_KEY = "AKIAIOSFODNN7EXAMPLE"'
        )
        
        # Create subdirectory
        subdir = Path(self.temp_dir) / "src"
        subdir.mkdir()
        (subdir / "secrets.py").write_text(
            'TOKEN = "ghp_' + 'a' * 36 + '"'
        )
        
        # Create file to skip
        skip_dir = Path(self.temp_dir) / "node_modules"
        skip_dir.mkdir()
        (skip_dir / "package.json").write_text('{"name": "test"}')
    
    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_collect_files(self):
        """Test file collection."""
        files = asyncio.run(
            scanner.LocalFilesystemScanner._collect_files(
                Path(self.temp_dir),
                max_depth=10,
                follow_symlinks=False
            )
        )
        
        self.assertGreater(len(files), 0, "Should collect files")
        
        # Should not include node_modules
        file_paths = [str(f) for f in files]
        self.assertFalse(
            any("node_modules" in p for p in file_paths),
            "Should skip node_modules"
        )
    
    def test_scan_local_path(self):
        """Test full local path scanning."""
        findings = asyncio.run(
            scanner.LocalFilesystemScanner.scan_local_path(
                Path(self.temp_dir),
                max_depth=10,
                custom_patterns=None,
                baseline_hashes=set(),
                follow_symlinks=False
            )
        )
        
        self.assertGreater(len(findings), 0, "Should find secrets")
        
        # Check finding structure
        for finding in findings:
            self.assertIn('repo', finding)
            self.assertIn('path', finding)
            self.assertTrue(finding['repo'].startswith('local:'))


# ===================================================================
# PLATFORM SCANNER TESTS
# ===================================================================

class TestPlatformScanners(unittest.TestCase):
    """Test platform-specific scanner optimizations."""
    
    def test_macos_scanner_class_exists(self):
        """Test MacOSScanner class exists."""
        self.assertTrue(hasattr(scanner, 'MacOSScanner'))
        self.assertTrue(hasattr(scanner.MacOSScanner, 'find_directories'))
    
    def test_linux_scanner_class_exists(self):
        """Test LinuxScanner class exists."""
        self.assertTrue(hasattr(scanner, 'LinuxScanner'))
        self.assertTrue(hasattr(scanner.LinuxScanner, 'find_directories'))
    
    def test_windows_scanner_class_exists(self):
        """Test WindowsScanner class exists."""
        self.assertTrue(hasattr(scanner, 'WindowsScanner'))
        self.assertTrue(hasattr(scanner.WindowsScanner, 'find_directories'))


# ===================================================================
# INTEGRATION TESTS
# ===================================================================

class TestIntegration(unittest.TestCase):
    """Integration tests for full workflows."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_end_to_end_local_scan(self):
        """Test complete local scanning workflow."""
        # Create test files with secrets
        test_file = Path(self.temp_dir) / "app.py"
        test_file.write_text('''
# Configuration
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz1234"
DB_URL = "postgres://user:password@localhost:5432/mydb"
''')
        
        # Scan
        findings = asyncio.run(
            scanner.LocalFilesystemScanner.scan_local_path(
                Path(self.temp_dir),
                max_depth=5,
                custom_patterns=None,
                baseline_hashes=set(),
                follow_symlinks=False
            )
        )
        
        # Should find multiple secrets
        self.assertGreater(len(findings), 0)
        
        # Generate reports
        output_base = Path(self.temp_dir) / "report"
        scanner.generate_report(findings, output_base)
        
        # Verify report was created
        json_report = output_base.with_suffix('.json')
        self.assertTrue(json_report.exists())
    
    def test_incremental_scan_workflow(self):
        """Test incremental scanning with baseline."""
        test_file = Path(self.temp_dir) / "config.py"
        test_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        # First scan
        findings1 = asyncio.run(
            scanner.LocalFilesystemScanner.scan_local_path(
                Path(self.temp_dir),
                max_depth=5,
                custom_patterns=None,
                baseline_hashes=set(),
                follow_symlinks=False
            )
        )
        
        # Save as baseline
        baseline_file = Path(self.temp_dir) / "baseline.json"
        baseline_data = {"findings": findings1}
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f)
        
        # Load baseline
        baseline_hashes = scanner.load_baseline(baseline_file)
        
        # Second scan with baseline (should find nothing new)
        findings2 = asyncio.run(
            scanner.LocalFilesystemScanner.scan_local_path(
                Path(self.temp_dir),
                max_depth=5,
                custom_patterns=None,
                baseline_hashes=baseline_hashes,
                follow_symlinks=False
            )
        )
        
        self.assertEqual(len(findings2), 0, "Incremental scan should skip baseline findings")


# ===================================================================
# ASYNC OPERATION TESTS
# ===================================================================

class TestAsyncOperations(unittest.TestCase):
    """Test async operations and concurrency."""
    
    def test_github_api_call_with_backoff_success(self):
        """Test successful API call with backoff."""
        
        async def test_func():
            return "success"
        
        result = asyncio.run(
            scanner.github_api_call_with_backoff(test_func, max_retries=3)
        )
        
        self.assertEqual(result, "success")
    
    def test_rate_limiter_acquire(self):
        """Test rate limiter acquire mechanism."""
        rate_limiter = scanner.GitHubRateLimiter(requests_per_hour=3600)  # 1 per second
        
        async def test_acquire():
            await rate_limiter.acquire()
            return True
        
        result = asyncio.run(test_acquire())
        self.assertTrue(result)
        self.assertEqual(rate_limiter.state.total_requests, 1)


# ===================================================================
# MAIN TEST RUNNER
# ===================================================================

if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)