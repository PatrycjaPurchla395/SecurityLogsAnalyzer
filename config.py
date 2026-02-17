# Configuration file for Security Log Analyzer
# Modify these values to customize detection rules

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 3  # Minimum number of failed login attempts to trigger alert

# Suspicious patterns for web attacks
SUSPICIOUS_WEB_PATTERNS = [
    "../",           # Path traversal
    "UNION",         # SQL injection
    "DROP",          # SQL injection
    "SELECT",        # SQL injection
    "/admin",        # Admin panel access
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/.env",         # Sensitive files
    "/config",
    ".php~",         # Backup files
    ".git",          # Version control
]

# Time window for correlation (seconds)
CORRELATION_TIME_WINDOW = 1  # Events within this window are considered correlated

# Report settings
REPORT_FORMAT = "json"  # json or text
INCLUDE_RAW_LOGS = False  # Include raw log lines in report

# Severity levels
SEVERITY_CRITICAL_THRESHOLD = 3  # Number of correlations to mark as CRITICAL
SEVERITY_HIGH_THRESHOLD = 1      # Number of correlations to mark as HIGH
