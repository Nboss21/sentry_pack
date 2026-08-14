"""
Integration tests for RecommendationEngine with database and target findings.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.db.models import Base, ExploitModel, FindingModel, Project, Target
from core.recommendation.engine import RecommendationEngine, recommendation_engine
from core.recommendation.models import ExploitRecord


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_recommendation_engine_db_query(db_session: Session):
    # Setup test project and target
    proj = Project(name="Test Project")
    db_session.add(proj)
    db_session.commit()

    target = Target(project_id=proj.id, name="Target 1", ip_address="10.0.0.1", status="scanned")
    db_session.add(target)
    db_session.commit()

    # Add findings with evidence
    finding1 = FindingModel(
        target_id=target.id,
        title="Open SSH Port",
        severity="Info",
        evidence={
            "host": "10.0.0.1",
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "cpe": "cpe:/a:openbsd:openssh:8.9p1",
        },
    )
    db_session.add(finding1)

    # Add Exploit DB entries
    ex1 = ExploitModel(
        service_name="ssh",
        cve_id="CVE-2023-38408",
        description="OpenSSH PKCS11 Remote Code Execution",
        severity="Critical",
        cvss_score=9.8,
        has_public_exploit=True,
        module_id="exploit.ssh_pkcs11",
        published_date="2023-07-20",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    )
    ex2 = ExploitModel(
        service_name="openssh",
        cve_id="CVE-2021-41617",
        description="OpenSSH Privilege Escalation",
        severity="High",
        cvss_score=7.0,
        has_public_exploit=False,
        published_date="2021-10-01",
    )
    db_session.add_all([ex1, ex2])
    db_session.commit()

    engine = RecommendationEngine()
    recs = engine.recommend_for_target(target.id, db_session)

    assert len(recs) == 2
    # Verify ranked order: ex1 (direct match, module_id present, CVSS 9.8) before ex2
    assert recs[0]["cve_id"] == "CVE-2023-38408"
    assert recs[0]["is_direct_match"] is True
    assert recs[0]["cvss_score"] == 9.8
    assert recs[0]["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]

    assert recs[1]["cve_id"] == "CVE-2021-41617"


def test_recommendation_engine_empty_target(db_session: Session):
    engine = RecommendationEngine()
    recs = engine.recommend_for_target(999, db_session)
    assert recs == []
