import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, "scans")
DB_PATH = os.path.join(BASE_DIR, "openclaw.db")

DEFAULT_SQLMAP_PATH = "/usr/bin/sqlmap"
DEFAULT_LEVEL = 2
DEFAULT_RISK = 2
DEFAULT_TIMEOUT_MIN = 15

os.makedirs(SCANS_DIR, exist_ok=True)
