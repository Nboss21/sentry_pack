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


def ensure_seed_exploits(session) -> None:
    """Auto-seed core high-profile exploit CVEs if exploits table is currently empty."""
    from api.db.models import ExploitModel
    try:
        if session.query(ExploitModel).count() == 0:
            core_seeds = [
                {
                    "service_name": "apache",
                    "cve_id": "CVE-2021-44228",
                    "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                    "description": "Apache Log4j2 JNDI LDAP lookup command injection allowing full remote code execution.",
                    "author": "Chen Zhaojun",
                    "exploit_type": "remote",
                    "platform": "multi",
                    "port": 80,
                    "cvss_score": 10.0,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.log4shell_jndi",
                    "published_date": "2021-12-10",
                    "cpe_prefix": "cpe:/a:apache:log4j",
                },
                {
                    "service_name": "smb",
                    "cve_id": "CVE-2017-0144",
                    "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
                    "description": "SMBv1 buffer overflow in srv.sys allows unauthenticated remote attackers to execute arbitrary code with SYSTEM privileges.",
                    "author": "Equation Group / Shadow Brokers",
                    "exploit_type": "remote",
                    "platform": "windows",
                    "port": 445,
                    "cvss_score": 9.8,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.smb_ms17_010",
                    "published_date": "2017-03-14",
                    "cpe_prefix": "cpe:/o:microsoft:windows",
                },
                {
                    "service_name": "rdp",
                    "cve_id": "CVE-2019-0708",
                    "title": "Microsoft Remote Desktop Services RCE (BlueKeep)",
                    "description": "Pre-authentication remote code execution vulnerability in Windows Remote Desktop Services.",
                    "author": "Sean Dillon",
                    "exploit_type": "remote",
                    "platform": "windows",
                    "port": 3389,
                    "cvss_score": 9.8,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.rdp_bluekeep",
                    "published_date": "2019-05-14",
                },
                {
                    "service_name": "postgresql",
                    "cve_id": "CVE-2019-9193",
                    "title": "PostgreSQL COPY TO/FROM PROGRAM Command Execution",
                    "description": "Authenticated PostgreSQL superuser can execute arbitrary shell commands via COPY FROM PROGRAM clause.",
                    "author": "Daniel Gustafsson",
                    "exploit_type": "remote",
                    "platform": "linux",
                    "port": 5432,
                    "cvss_score": 9.0,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.postgres_copy_exec",
                    "published_date": "2019-03-05",
                },
                {
                    "service_name": "redis",
                    "cve_id": "CVE-2022-0543",
                    "title": "Redis Lua Sandbox Escape Remote Code Execution",
                    "description": "Improper package initialization in Debian/Ubuntu packages of Redis allows remote Lua sandbox escape.",
                    "author": "Reginaldo Silva",
                    "exploit_type": "remote",
                    "platform": "linux",
                    "port": 6379,
                    "cvss_score": 10.0,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.redis_lua_sandbox_escape",
                    "published_date": "2022-02-18",
                },
                {
                    "service_name": "ssh",
                    "cve_id": "CVE-2023-38408",
                    "title": "OpenSSH PKCS11 Remote Code Execution",
                    "description": "OpenSSH agent forwarding PKCS#11 provider loading vulnerability leading to RCE.",
                    "author": "Qualys",
                    "exploit_type": "remote",
                    "platform": "linux",
                    "port": 22,
                    "cvss_score": 9.8,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.ssh_pkcs11",
                    "published_date": "2023-07-20",
                },
                {
                    "service_name": "ftp",
                    "cve_id": "CVE-2011-0762",
                    "title": "vsftpd 2.3.4 Backdoor Command Execution",
                    "description": "vsftpd 2.3.4 contains a backdoor on port 6200 triggered by smiley face in username.",
                    "author": "Anonymous",
                    "exploit_type": "remote",
                    "platform": "unix",
                    "port": 21,
                    "cvss_score": 9.8,
                    "severity": "Critical",
                    "has_public_exploit": True,
                    "module_id": "exploit.vsftpd_backdoor",
                    "published_date": "2011-07-04",
                },
                {
                    "service_name": "apache",
                    "cve_id": "CVE-2021-41773",
                    "title": "Apache HTTP Server Path Traversal & RCE",
                    "description": "Path traversal flaw in Apache HTTP Server 2.4.49 allows mapping URLs to files outside expected document root.",
                    "author": "Ash Daulton",
                    "exploit_type": "remote",
                    "platform": "unix",
                    "port": 80,
                    "cvss_score": 8.5,
                    "severity": "High",
                    "has_public_exploit": True,
                    "module_id": "exploit.apache_path_traversal",
                    "published_date": "2021-10-05",
                },
            ]
            for data in core_seeds:
                session.add(ExploitModel(**data))
            session.commit()
    except Exception as exc:
        logger.warning("Could not auto-seed exploits: %s", exc)


def init_db():
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE c2_sessions ADD COLUMN transport VARCHAR(64) DEFAULT 'unknown' NOT NULL"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE projects ADD COLUMN auth_token VARCHAR(255)"))
            conn.commit()
        except Exception:
            pass
    ensure_exploits_fts(engine)
    db = SessionLocal()
    try:
        ensure_seed_exploits(db)
    finally:
        db.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
