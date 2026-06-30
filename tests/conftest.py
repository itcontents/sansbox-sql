import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("SANDBOX_API_KEY", "test-api-key")
os.environ.setdefault("SANDBOX_WEBHOOK_SECRET", "test-webhook-secret")
os.environ.setdefault("SANDBOX_CF_ACCESS_AUD", "test-aud")
os.environ.setdefault("SANDBOX_CF_ACCESS_CERTS_URL", "https://example.test/certs")
os.environ.setdefault("SANDBOX_FERNET_KEY", "ZmRldnRlc3RrZXktZmRldnRlc3RrZXktZmRldnRlc3RrZXkxMjM0NTY3OA==")
os.environ.setdefault("SANDBOX_PUBLIC_HOST", "api.test.local")
os.environ.setdefault("SANDBOX_MYSQL_HOST", "127.0.0.1")
os.environ.setdefault("PROD_SSH_HOST", "prod.test")
os.environ.setdefault("PROD_SSH_USER", "sandbox")
os.environ.setdefault("PROD_SSH_KEY", "/tmp/nonexistent")
os.environ.setdefault("PROD_MYSQL_HOST", "prod-mysql.test")
os.environ.setdefault("PROD_MYSQL_PORT", "3306")
os.environ.setdefault("PROD_MYSQL_USER", "dumper")
os.environ.setdefault("PROD_MYSQL_PASSWORD", "x")