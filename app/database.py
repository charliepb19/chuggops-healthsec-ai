# app/database.py

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Defaults to SQLite for local dev; set DATABASE_URL in .env for PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./chuggops.db")

# SQLite needs check_same_thread=False; PostgreSQL does not
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args   = connect_args,
    pool_pre_ping  = True,   # re-tests stale connections (important for long-running prod)
    pool_recycle   = 1800,   # recycle connections every 30 min
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
