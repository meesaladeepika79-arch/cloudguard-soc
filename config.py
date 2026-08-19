import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-cloud-security-mca-2026")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///cloud_security.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEMO_MODE = os.getenv("DEMO_MODE", "False").lower() in ("true", "1", "t")
    
    # AWS configuration defaults (read from env or AWS provider chain)
    AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
