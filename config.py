"""
Configuration and Constants for Phishing Detector

This module centralizes configuration constants to avoid magic numbers
scattered throughout the codebase.
"""

from pathlib import Path

# ── Project Paths ──
PROJECT_ROOT = Path(__file__).parent.absolute()
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"
ASSETS_DIR = PROJECT_ROOT / "assets"
NOTEBOOKS_DIR = PROJECT_ROOT / "notebooks"

# ── Model Configuration ──
MODEL_FILE = MODELS_DIR / "phishing_model.pkl"

# ── URL Analysis Thresholds ──
# URL Length thresholds (characters)
URL_LENGTH_SHORT = 54      # URLs shorter than this are normal (1)
URL_LENGTH_MEDIUM = 75     # URLs between SHORT and MEDIUM are suspicious (0)
#  URLs longer than MEDIUM are very suspicious (-1)

# ── Feature Extraction Thresholds ──
# External link ratio thresholds
EXTERNAL_RATIO_NORMAL = 0.3       # 0-30% external links = normal (1)
EXTERNAL_RATIO_SUSPICIOUS = 0.7   # 30-70% = suspicious (0)
#  70%+ = phishing (-1)

# ── Domain Features ──
DOMAIN_AGE_NORMAL_DAYS = 365      # Domain older than 1 year = legitimate (1)
DOMAIN_AGE_RECHECK_DAYS = 180     # Domain age feature threshold

# ── Timeout Settings ──
HTTP_TIMEOUT_SECONDS = 5
WHOIS_TIMEOUT_SECONDS = 4
VIRUSTOTAL_TIMEOUT_SECONDS = 10
HTML_PARSE_TIMEOUT_SECONDS = 5

# ── Feature Limits ──
HTML_CONTENT_MAX_BYTES = 100000  # Max HTML to parse (100 KB)
URL_PREVIEW_MAX_CHARS = 50        # Max chars to show in logs

# ── URL Shortener Services ──
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'bl.ink', 'tiny.cc'
]

# ── Suspicious Keywords ──
# URLs or page titles containing these words are flagged as suspicious
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update',
    'confirm', 'bank', 'ebay', 'paypal', 'signin', 'security'
]

# ── API Configuration ──
VIRUSTOTAL_API_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_MALICIOUS_THRESHOLD = 5  # Flag as malicious if N+ engines detect it

# ── Logging Configuration ──
LOG_LEVEL = "INFO"
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_MAX_SIZE_MB = 10
LOG_BACKUP_COUNT = 3

# ── Model Feature Order ──
# IMPORTANT: This must match the order used during model training
# Any change here requires retraining the model
MODEL_FEATURE_ORDER = [
    'Having_IP_Address', 'URL_Length', 'Shortining_Service',
    'Having_At_Symbol', 'Double_Slash_Redirect', 'Prefix_Suffix',
    'Having_Sub_Domain', 'SSLfinal_State', 'Domain_Reg_Length',
    'Favicon', 'Port', 'HTTPS_Token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_Tags', 'SFH',
    'Submitting_to_Email', 'Abnormal_URL', 'Redirect',
    'On_Mouseover', 'RightClick', 'PopUpWindow', 'Iframe',
    'Age_of_Domain', 'DNS_Record', 'Web_Traffic',
    'Page_Rank', 'Google_Index', 'Links_Pointing_to_Page',
    'Statistical_Report'
]

# ── Feature Default Values ──
# Default values when features cannot be determined
FEATURE_DEFAULTS = {
    'Having_IP_Address': 1,
    'URL_Length': 1,
    'Shortining_Service': 1,
    'Having_At_Symbol': 1,
    'Double_Slash_Redirect': 1,
    'Prefix_Suffix': 1,
    'Having_Sub_Domain': 1,
    'SSLfinal_State': 1,
    'Domain_Reg_Length': 1,
    'Favicon': 1,
    'Port': 1,
    'HTTPS_Token': 1,
    'Request_URL': 1,
    'URL_of_Anchor': 1,
    'Links_in_Tags': 1,
    'SFH': 1,
    'Submitting_to_Email': 1,
    'Abnormal_URL': 1,
    'Redirect': 0,
    'On_Mouseover': 1,
    'RightClick': 1,
    'PopUpWindow': 1,
    'Iframe': 1,
    'Age_of_Domain': 1,
    'DNS_Record': 1,
    'Web_Traffic': 1,
    'Page_Rank': 1,
    'Google_Index': 1,
    'Links_Pointing_to_Page': 1,
    'Statistical_Report': 1,
}
