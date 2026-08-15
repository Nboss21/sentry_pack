"""
SQLAlchemy engine and session maker setup for local SQLite database.
"""

import logging
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from api.db.models import Base

logger = logging.getLogger("sentrypack.db.session")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "sentrypack.db"

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def ensure_exploits_fts(engine) -> None:
    """
    Create (if not exists) the exploits_fts FTS5 external-content virtual table,
    three sync triggers (INSERT / UPDATE / DELETE), and backfill the index.

    Must be called after Base.metadata.create_all() so the 'exploits' table
    already exists.

    Raises on FTS5 unavailability after logging a clear warning.
    """
    try:
        with engine.connect() as conn:
            # ----------------------------------------------------------------
            # (a) Create the FTS5 external-content virtual table
            # ----------------------------------------------------------------
            conn.execute(text(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts USING fts5(
                    title,
                    description,
                    service_name,
                    cve_id,
                    platform,
                    author,
                    content='exploits',
                    content_rowid='id'
                )
                """
            ))

            # ----------------------------------------------------------------
            # (b) Sync triggers — standard external-content FTS5 pattern.
            #     After INSERT  : insert new content into FTS.
            #     Before UPDATE : delete old FTS row (using old values).
            #     After  UPDATE : insert new FTS row (using new values).
            #     Before DELETE : delete old FTS row (using old values).
            # ----------------------------------------------------------------
            conn.execute(text(
                """
                CREATE TRIGGER IF NOT EXISTS exploits_fts_ai
                AFTER INSERT ON exploits BEGIN
                    INSERT INTO exploits_fts(rowid, title, description,
                        service_name, cve_id, platform, author)
                    VALUES (new.id, new.title, new.description,
                        new.service_name, new.cve_id, new.platform, new.author);
                END
                """
            ))

            conn.execute(text(
                """
                CREATE TRIGGER IF NOT EXISTS exploits_fts_bu
                BEFORE UPDATE ON exploits BEGIN
                    INSERT INTO exploits_fts(exploits_fts, rowid, title, description,
                        service_name, cve_id, platform, author)
                    VALUES ('delete', old.id, old.title, old.description,
                        old.service_name, old.cve_id, old.platform, old.author);
                END
                """
            ))

            conn.execute(text(
                """
                CREATE TRIGGER IF NOT EXISTS exploits_fts_au
                AFTER UPDATE ON exploits BEGIN
                    INSERT INTO exploits_fts(rowid, title, description,
                        service_name, cve_id, platform, author)
                    VALUES (new.id, new.title, new.description,
                        new.service_name, new.cve_id, new.platform, new.author);
                END
                """
            ))

            conn.execute(text(
                """
                CREATE TRIGGER IF NOT EXISTS exploits_fts_bd
                BEFORE DELETE ON exploits BEGIN
                    INSERT INTO exploits_fts(exploits_fts, rowid, title, description,
                        service_name, cve_id, platform, author)
                    VALUES ('delete', old.id, old.title, old.description,
                        old.service_name, old.cve_id, old.platform, old.author);
                END
                """
            ))

            # ----------------------------------------------------------------
            # (c) Backfill — rebuilds the FTS index from all current rows in
            #     the exploits table.  Safe to run repeatedly; rebuild is
            #     idempotent.
            # ----------------------------------------------------------------
            conn.execute(text(
                "INSERT INTO exploits_fts(exploits_fts) VALUES('rebuild')"
            ))

            conn.commit()

        logger.info("exploits_fts FTS5 virtual table and triggers ensured.")

    except Exception as exc:
        logger.warning(
            "Failed to create exploits_fts FTS5 virtual table. "
            "FTS5 may be unavailable in this SQLite build. Error: %s",
            exc,
        )
        raise


def init_db():
    Base.metadata.create_all(bind=engine)
    ensure_exploits_fts(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
