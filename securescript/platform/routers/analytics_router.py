"""
SecureScript Platform — Analytics & Reporting API Router.

Endpoints:
- GET /platform/projects/{id}/stats      : Aggregated security statistics
- GET /platform/projects/{id}/incidents  : Paginated incident log with filters
- GET /platform/projects/{id}/report     : Full downloadable JSON security report
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescript.platform.auth import get_current_user
from securescript.platform.database import get_db
from securescript.platform.incident_store import (
    get_incident_count,
    get_incidents,
    incident_to_dict,
)
from securescript.platform.models import Incident, Project, User

analytics_router = APIRouter(prefix="/platform/projects", tags=["Analytics"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _get_project_or_403(
    project_id: str, current_user: User, db: AsyncSession
) -> Project:
    """Fetches a project and verifies ownership. Raises 404/403 as appropriate."""
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.is_active == True)  # noqa: E712
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return project


async def _compute_stats(db: AsyncSession, project_id: str) -> dict[str, Any]:
    """Computes all dashboard stats for a project using SQL aggregates."""

    # --- Totals ---
    total_blocked = await get_incident_count(db, project_id=project_id, action_filter="BLOCKED")
    total_passed = await get_incident_count(db, project_id=project_id, action_filter="PASSED")
    total_audited = await get_incident_count(db, project_id=project_id, action_filter="AUDITED")
    total_inspected = total_blocked + total_passed + total_audited
    block_rate_pct = round((total_blocked / total_inspected * 100), 2) if total_inspected else 0.0

    # --- Average confidence (on BLOCKED only) ---
    avg_conf_result = await db.execute(
        select(func.avg(Incident.confidence_score)).where(
            Incident.project_id == project_id, Incident.action == "BLOCKED"
        )
    )
    avg_confidence = round(avg_conf_result.scalar_one() or 0.0, 4)

    # --- Top 5 attacked paths ---
    top_paths_result = await db.execute(
        select(Incident.url_path, func.count(Incident.id).label("count"))
        .where(Incident.project_id == project_id, Incident.action == "BLOCKED")
        .group_by(Incident.url_path)
        .order_by(func.count(Incident.id).desc())
        .limit(5)
    )
    top_attacked_paths = [
        {"path": row.url_path, "count": row.count} for row in top_paths_result
    ]

    # --- Requests in last 24 hours, bucketed by hour ---
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_result = await db.execute(
        select(Incident.timestamp).where(
            Incident.project_id == project_id,
            Incident.timestamp >= since,
        )
    )
    timestamps = [row.timestamp for row in recent_result]

    # Build 24-bucket histogram
    hour_buckets: dict[str, int] = {}
    for ts in timestamps:
        bucket = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        hour_buckets[bucket] = hour_buckets.get(bucket, 0) + 1
    requests_last_24h = [
        {"hour": k, "count": v} for k, v in sorted(hour_buckets.items())
    ]

    return {
        "total_inspected": total_inspected,
        "blocked": total_blocked,
        "passed": total_passed,
        "audited": total_audited,
        "block_rate_pct": block_rate_pct,
        "avg_confidence": avg_confidence,
        "top_attacked_paths": top_attacked_paths,
        "requests_last_24h": requests_last_24h,
    }


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------
class IncidentResponse(BaseModel):
    id: str
    project_id: str
    event_id: str
    timestamp: datetime
    action: str
    client_ip: str
    http_method: str
    url_path: str
    detection_stage: str
    confidence_score: float
    trigger_tokens: list
    raw_payload: str
    normalized_payload: str
    latency_ms: float
    attack_category: str
    severity: str
    created_at: datetime

    model_config = {"from_attributes": True}


class PaginatedIncidents(BaseModel):
    total: int
    page: int
    page_size: int
    incidents: list[IncidentResponse]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@analytics_router.get(
    "/{project_id}/stats",
    summary="Get aggregated security statistics for a project",
)
async def get_project_stats(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Returns aggregated security stats:
    - Total inspected, blocked, passed, audited
    - Block rate percentage
    - Average confidence score on blocked requests
    - Top 5 attacked URL paths
    - Hourly request histogram for the last 24 hours
    """
    await _get_project_or_403(project_id, current_user, db)
    return await _compute_stats(db, project_id)


@analytics_router.get(
    "/{project_id}/incidents",
    response_model=PaginatedIncidents,
    summary="Get paginated incident log for a project",
)
async def list_project_incidents(
    project_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    action: Optional[str] = Query(default=None, description="Filter: BLOCKED, PASSED, AUDITED"),
    severity: Optional[str] = Query(default=None, description="Filter: LOW, MEDIUM, HIGH, CRITICAL"),
    from_date: Optional[datetime] = Query(default=None),
    to_date: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedIncidents:
    """
    Returns a paginated list of incidents for a project.

    Supports filtering by action, severity, and date range.
    """
    await _get_project_or_403(project_id, current_user, db)

    offset = (page - 1) * page_size
    incidents = await get_incidents(
        db,
        project_id=project_id,
        limit=page_size,
        offset=offset,
        action_filter=action,
        severity_filter=severity,
        from_date=from_date,
        to_date=to_date,
    )

    # Get total count for this filter combination
    total = await get_incident_count(db, project_id=project_id, action_filter=action)

    return PaginatedIncidents(
        total=total,
        page=page,
        page_size=page_size,
        incidents=[IncidentResponse.model_validate(i, from_attributes=True) for i in incidents],
    )


@analytics_router.get(
    "/{project_id}/report",
    summary="Download a full security report for a project",
)
async def get_project_report(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Returns a complete JSON security report for a project, including:
    - All aggregated statistics
    - Last 100 incidents in full detail
    - Project metadata

    The browser can trigger a download of this JSON response.
    """
    project = await _get_project_or_403(project_id, current_user, db)
    stats = await _compute_stats(db, project_id)
    recent_incidents = await get_incidents(db, project_id=project_id, limit=100)

    return {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "project": {
            "id": project.id,
            "name": project.name,
            "slug": project.slug,
            "proxy_path": f"/proxy/{project.slug}/",
            "frontend_url": project.frontend_url,
            "backend_url": project.backend_url,
            "created_at": project.created_at.isoformat(),
        },
        "stats": stats,
        "recent_incidents": [incident_to_dict(i) for i in recent_incidents],
    }
