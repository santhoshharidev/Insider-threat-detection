from sqlalchemy import Table, Column, Integer, String, MetaData, DateTime, JSON
from datetime import datetime

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String, unique=True, nullable=False),
    Column("password_hash", String, nullable=True),
    Column("created_at", DateTime, default=datetime.utcnow),
)

interviews = Table(
    "interviews",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, nullable=False),
    Column("kind", String),
    Column("company", String, nullable=True),
    Column("questions", JSON),
    Column("result", JSON),
    Column("created_at", DateTime, default=datetime.utcnow),
)
