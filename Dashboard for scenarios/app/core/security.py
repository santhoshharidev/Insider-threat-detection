from datetime import datetime, timedelta
from jose import jwt
import os

SECRET_KEY = os.environ.get("MOCKTIVATE_SECRET", "dev-secret-key")
ALGORITHM = "HS256"


def create_access_token(subject: str, expires_delta: int = 60 * 24 * 7):
    expire = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode = {"sub": subject, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
