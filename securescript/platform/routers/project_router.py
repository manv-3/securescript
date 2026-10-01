"""
SecureScript Platform — Project Management API Router.

Endpoints:
- POST   /platform/projects                  : Create a new project (connect a site)
- GET    /platform/projects                  : List all projects for the current user
- GET    /platform/projects/{id}             : Get a single project by ID
- DELETE /platform/projects/{id}             : Soft-delete a project (sets is_active=False)
- PUT    /platform/projects/{id}/alerts      : Configure webhook + email alert settings
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from securescript.platform.auth import get_current_user
from securescript.platform.database import get_db
from securescript.platform.models import Project, User

project_router = APIRouter(prefix="/platform/projects", tags=["Projects"])


# ---------------------------------------------------------------------------
# Slug helper
# ---------------------------------------------------------------------------
def _generate_slug(name: str) -> str:
    """
    Converts a project name to a URL-safe slug with a 4-char hex suffix.

    Example:
        "My Cool App!" → "my-cool-app-3f9a"

    Args:
        name: Human-readable project name.

    Returns:
        A lowercase, hyphen-separated slug with a 4-character random hex suffix.
    """
    # Lowercase, replace non-alphanumeric with hyphens, collapse multiple hyphens
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    slug = slug[:60]  # cap length before suffix
    suffix = uuid.uuid4().hex[:4]
    return f"{slug}-{suffix}"


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------
class ProjectCreateRequest(BaseModel):
    name: str
    frontend_url: str
    backend_url: str

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Project name cannot be empty")
        return v.strip()

    @field_validator("frontend_url", "backend_url")
    @classmethod
    def url_must_start_with_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")


class AlertConfigRequest(BaseModel):
    webhook_url: Optional[str] = None
    alert_email: Optional[str] = None

    @field_validator("webhook_url")
    @classmethod
    def webhook_must_be_http(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("Webhook URL must start with http:// or https://")
        return v


class ProjectResponse(BaseModel):
    id: str
    name: str
    slug: str
    proxy_path: str
    frontend_url: str
    backend_url: str
    is_active: bool
    frontend_reachable: Optional[bool]
    backend_reachable: Optional[bool]
    webhook_url: Optional[str]
    alert_email: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_project(cls, p: Project) -> "ProjectResponse":
        return cls(
            id=p.id,
            name=p.name,
            slug=p.slug,
            proxy_path=f"/proxy/{p.slug}/",
            frontend_url=p.frontend_url,
            backend_url=p.backend_url,
            is_active=p.is_active,
            frontend_reachable=p.frontend_reachable,
            backend_reachable=p.backend_reachable,
            webhook_url=p.webhook_url,
            alert_email=p.alert_email,
            created_at=p.created_at,
        )


# ---------------------------------------------------------------------------
# Background task — URL reachability check
# ---------------------------------------------------------------------------
async def _check_url_reachability(project_id: str, frontend_url: str, backend_url: str) -> None:
    """
    Pings the project's frontend and backend URLs and updates the
    ``frontend_reachable`` / ``backend_reachable`` fields in the DB.

    This runs as a FastAPI BackgroundTask — failures are silently logged.
    """
    from securescript.platform.database import AsyncSessionLocal  # avoid circular import

    frontend_ok: bool = False
    backend_ok: bool = False

    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
        try:
            resp = await client.head(frontend_url)
            frontend_ok = resp.status_code < 500
        except Exception:
            frontend_ok = False

        try:
            resp = await client.head(backend_url)
            backend_ok = resp.status_code < 500
        except Exception:
            backend_ok = False

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project:
            project.frontend_reachable = frontend_ok
            project.backend_reachable = backend_ok
            await session.commit()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@project_router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Connect a new website to SecureScript",
)
async def create_project(
    body: ProjectCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProjectResponse:
    """
    Register a new project (frontend URL + backend URL).

    Returns the project record including the unique ``proxy_path`` to use.
    Immediately activates the proxy. URL reachability is checked asynchronously.
    """
    slug = _generate_slug(body.name)

    # Ensure slug uniqueness — retry once on collision (extremely rare)
    existing = await db.execute(select(Project).where(Project.slug == slug))
    if existing.scalar_one_or_none():
        slug = _generate_slug(body.name)

    project = Project(
        user_id=current_user.id,
        name=body.name,
        slug=slug,
        frontend_url=body.frontend_url,
        backend_url=body.backend_url,
        is_active=True,
        alert_email=current_user.email,  # default to owner's email
    )
    db.add(project)
    await db.flush()

    # Fire async URL reachability ping
    background_tasks.add_task(
        _check_url_reachability, project.id, project.frontend_url, project.backend_url
    )

    return ProjectResponse.from_orm_project(project)


@project_router.get(
    "",
    response_model=list[ProjectResponse],
    summary="List all projects for the authenticated user",
)
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ProjectResponse]:
    """Returns all projects owned by the current user (active and inactive)."""
    result = await db.execute(
        select(Project)
        .where(Project.user_id == current_user.id)
        .order_by(Project.created_at.desc())
    )
    projects = result.scalars().all()
    return [ProjectResponse.from_orm_project(p) for p in projects]


@project_router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Get a single project by ID",
)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProjectResponse:
    """
    Returns project details for the given ID.

    Returns **403** if the project belongs to a different user.
    Returns **404** if the project does not exist or is deactivated.
    """
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.is_active == True)  # noqa: E712
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return ProjectResponse.from_orm_project(project)


@project_router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a project (soft delete)",
)
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Soft-deletes a project by setting ``is_active=False``.

    The proxy path is immediately deactivated. Project data is retained for audit purposes.
    """
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.is_active == True)  # noqa: E712
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    project.is_active = False
    await db.flush()


@project_router.put(
    "/{project_id}/alerts",
    response_model=ProjectResponse,
    summary="Configure webhook and email alert settings",
)
async def update_alert_config(
    project_id: str,
    body: AlertConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProjectResponse:
    """
    Update the webhook URL and/or alert email for a project.

    Set either field to ``null`` to disable that alert channel.
    """
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.is_active == True)  # noqa: E712
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    if body.webhook_url is not None:
        project.webhook_url = body.webhook_url or None
    if body.alert_email is not None:
        project.alert_email = body.alert_email or None

    await db.flush()
    return ProjectResponse.from_orm_project(project)
