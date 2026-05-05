import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, "scans")
DB_PATH = os.path.join(BASE_DIR, "openclaw.db")

DEFAULT_SQLMAP_PATH = "/usr/bin/sqlmap"
DEFAULT_LEVEL = 2
DEFAULT_RISK = 2
DEFAULT_TIMEOUT_MIN = 15

# Basic Auth — 留空则不开启认证
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "")
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")

os.makedirs(SCANS_DIR, exist_ok=True)
