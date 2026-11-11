from pathlib import Path
import os
import secrets

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("VULNSCAN_DB", DATA_DIR / "vulnscan.db"))
SECRET_KEY = os.environ.get("VULNSCAN_SECRET") or secrets.token_hex(32)
USER_AGENT = "VulnScan/1.0 (+authorized defensive security assessment)"
DEFAULT_TIMEOUT = 5
DEFAULT_MAX_PAGES = 10
DEFAULT_DELAY = 0.15
MAX_BODY_BYTES = 256_000
