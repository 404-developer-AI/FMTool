import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    DATABASE_PATH = os.path.join(BASE_DIR, "instance", "fmtool.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "instance", "uploads")
    BRANDING_FOLDER = os.path.join(BASE_DIR, "instance", "branding")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload

    # Sophos XGS API (override in config.local.py)
    SOPHOS_HOST = None
    SOPHOS_USERNAME = None
    SOPHOS_PASSWORD = None
    SOPHOS_PORT = 4444
