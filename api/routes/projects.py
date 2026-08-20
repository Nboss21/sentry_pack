"""
Project CRUD API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.models import Project
from api.db.session import get_db


router = APIRouter()


class ProjectCreate(BaseModel):
    """Data required to create a project."""

    name: str
    description: str | None = None


class ProjectUpdate(BaseModel):
    """Data that can be changed on a project."""

    name: str | None = None
    description: str | None = None


def project_to_dict(project: Project) -> dict:
    """Convert a Project database object to an API response."""
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": (
            project.created_at.isoformat()
            if project.created_at
            else None
        ),
    }


@router.get("/")
def list_projects(db: Session = Depends(get_db)):
    """Return all projects."""
    projects = db.query(Project).order_by(Project.id).all()

    return {
        "projects": [
            project_to_dict(project)
            for project in projects
        ]
    }


@router.post("/", status_code=201)
def create_project(
    project_data: ProjectCreate,
    db: Session = Depends(get_db),
):
    """Create a new project."""
    project = Project(
        name=project_data.name,
        description=project_data.description,
    )

    db.add(project)
    db.commit()
    db.refresh(project)

    return project_to_dict(project)


@router.get("/{project_id}")
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Return one project."""
    project = (
        db.query(Project)
        .filter(Project.id == project_id)
        .first()
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail=f"Project {project_id} not found",
        )

    return project_to_dict(project)


@router.put("/{project_id}")
def update_project(
    project_id: int,
    project_data: ProjectUpdate,
    db: Session = Depends(get_db),
):
    """Update an existing project."""
    project = (
        db.query(Project)
        .filter(Project.id == project_id)
        .first()
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail=f"Project {project_id} not found",
        )

    if project_data.name is not None:
        project.name = project_data.name

    if project_data.description is not None:
        project.description = project_data.description

    db.commit()
    db.refresh(project)

    return project_to_dict(project)


@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Delete an existing project."""
    project = (
        db.query(Project)
        .filter(Project.id == project_id)
        .first()
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail=f"Project {project_id} not found",
        )

    db.delete(project)
    db.commit()

    return {
        "id": project_id,
        "message": f"Project {project_id} deleted",
    }