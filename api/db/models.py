"""
SQLAlchemy database models for SentryPack.
"""

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
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
    status = Column(String(50), default="active")
    last_seen = Column(DateTime, default=datetime.utcnow)


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
    references = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

