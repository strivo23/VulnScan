from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("VULNSCAN_DB", DATA_DIR / "vulnscan.db"))
SECRET_KEY = os.environ.get("VULNSCAN_SECRET", "local-development-key-change-me")
USER_AGENT = "VulnScan/1.0 (+authorized defensive security assessment)"
DEFAULT_TIMEOUT = 5
DEFAULT_MAX_PAGES = 10
DEFAULT_DELAY = 0.15
MAX_BODY_BYTES = 256_000
