"""
SQLAlchemy database models for SentryPack.
"""

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Table, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    auth_token = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)
    status = Column(String(50), default="idle")
    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="targets")
    runs = relationship("ModuleRun", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="target", cascade="all, delete-orphan")


class ModuleRun(Base):
    __tablename__ = "module_runs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    module_id = Column(String(255), nullable=False)
    status = Column(String(50), default="pending")
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    logs = Column(Text, nullable=True)

    target = relationship("Target", back_populates="runs")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    cve = Column(String(100), nullable=True)
    cpe = Column(String(255), nullable=True)
    remediation = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("Target", back_populates="findings")


class C2Session(Base):
    __tablename__ = "c2_sessions"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    session_key = Column(String(255), unique=True, nullable=False)
    transport = Column(String(64), nullable=False)
    status = Column(String(50), default="active")
    last_seen = Column(DateTime, default=datetime.utcnow)

    tasks = relationship("SessionTask", back_populates="session", cascade="all, delete-orphan")
    target = relationship("Target")


class SessionTask(Base):
    __tablename__ = "session_tasks"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("c2_sessions.id"), nullable=False)
    command = Column(Text, nullable=False)
    status = Column(String(50), default="queued")
    output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    session = relationship("C2Session", back_populates="tasks")


class SessionEvent(Base):
    __tablename__ = "session_events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("c2_sessions.id"), nullable=True)
    session_key = Column(String(255), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    data = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    session = relationship("C2Session")


# ---------------------------------------------------------------------------
# Exploit DB Relational Schema Junction Tables
# ---------------------------------------------------------------------------

exploit_cves = Table(
    "exploit_cves",
    Base.metadata,
    Column("exploit_id", Integer, ForeignKey("exploits.id"), primary_key=True),
    Column("cve_id", Integer, ForeignKey("cves.id"), primary_key=True),
)

exploit_platforms = Table(
    "exploit_platforms",
    Base.metadata,
    Column("exploit_id", Integer, ForeignKey("exploits.id"), primary_key=True),
    Column("platform_id", Integer, ForeignKey("platforms.id"), primary_key=True),
)

exploit_software = Table(
    "exploit_software",
    Base.metadata,
    Column("exploit_id", Integer, ForeignKey("exploits.id"), primary_key=True),
    Column("software_id", Integer, ForeignKey("software.id"), primary_key=True),
)


# ---------------------------------------------------------------------------
# Exploit DB Relational Schema Models
# ---------------------------------------------------------------------------

class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    published_date = Column(String(50), nullable=True)
    source = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    exploits = relationship("ExploitModel", secondary=exploit_cves, back_populates="cves")


class Platform(Base):
    __tablename__ = "platforms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    exploits = relationship("ExploitModel", secondary=exploit_platforms, back_populates="platforms")


class Software(Base):
    __tablename__ = "software"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    vendor = Column(String(255), nullable=True)
    cpe_prefix = Column(String(255), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    exploits = relationship("ExploitModel", secondary=exploit_software, back_populates="software")


class ExploitReference(Base):
    __tablename__ = "references"

    id = Column(Integer, primary_key=True, index=True)
    exploit_id = Column(Integer, ForeignKey("exploits.id"), nullable=False)
    url = Column(String(1000), nullable=False)
    source_type = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    exploit = relationship("ExploitModel", back_populates="references")

    def __eq__(self, other):
        if isinstance(other, str):
            return self.url == other
        if isinstance(other, ExploitReference):
            return (self.id == other.id if (self.id is not None and other.id is not None) else True) and self.url == other.url
        return super().__eq__(other)

    def __repr__(self):
        return f"<ExploitReference id={self.id} url={self.url!r}>"


class ExploitModel(Base):
    __tablename__ = "exploits"

    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String(255), nullable=False, index=True)
    cve_id = Column(String(100), nullable=True, index=True)
    title = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    exploit_type = Column(String(50), nullable=True)
    platform = Column(String(50), nullable=True)
    port = Column(Integer, nullable=True)
    cpe_prefix = Column(String(255), nullable=True, index=True)
    version_start_including = Column(String(100), nullable=True)
    version_start_excluding = Column(String(100), nullable=True)
    version_end_including = Column(String(100), nullable=True)
    version_end_excluding = Column(String(100), nullable=True)
    has_public_exploit = Column(Boolean, default=True)
    module_id = Column(String(255), nullable=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(50), default="Medium")
    published_date = Column(String(50), nullable=True)
    references_data = Column("references", JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    cves = relationship("CVE", secondary=exploit_cves, back_populates="exploits")
    platforms = relationship("Platform", secondary=exploit_platforms, back_populates="exploits")
    software = relationship("Software", secondary=exploit_software, back_populates="exploits")
    references = relationship(
        "ExploitReference",
        back_populates="exploit",
        cascade="all, delete-orphan",
    )

    def __init__(self, **kwargs):
        if "references" in kwargs and kwargs["references"] is not None:
            refs = kwargs["references"]
            if isinstance(refs, list):
                coerced_refs = []
                for r in refs:
                    if isinstance(r, str):
                        coerced_refs.append(ExploitReference(url=r))
                    else:
                        coerced_refs.append(r)
                kwargs["references"] = coerced_refs
        super().__init__(**kwargs)


class ExploitDBEntry(Base):
    __tablename__ = "exploitdb_entries"

    id = Column(Integer, primary_key=True, autoincrement=False)
    file = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    date_published = Column(String(50), nullable=True)
    author = Column(String(255), nullable=True)
    type = Column(String(100), nullable=True)
    platform = Column(String(100), nullable=True)
    port = Column(Integer, nullable=True)
    imported_at = Column(DateTime, default=datetime.utcnow)
