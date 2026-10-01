"""
SecureScript Platform — PostgreSQL Incident Store.

Provides async CRUD operations for the ``incidents`` table, scoped by project_id.

Multi-tenancy invariant: every function here requires a ``project_id`` argument.
Never query incidents without project scope.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from securescript.platform.models import Incident


def _new_event_id() -> str:
    """Generates a human-readable WAF ray ID (e.g. ``RAY-9A82F104BC``)."""
    return f"RAY-{uuid.uuid4().hex[:10].upper()}"


async def record_incident(
    db: AsyncSession,
    *,
    project_id: str,
    action: str,
    client_ip: str,
    http_method: str,
    url_path: str,
    detection_stage: str,
    confidence_score: float,
    trigger_tokens: list[str],
    raw_payload: str,
    normalized_payload: str,
    latency_ms: float,
    attack_category: str = "Cross-Site Scripting (XSS)",
    severity: str = "HIGH",
    event_id: Optional[str] = None,
) -> Incident:
    """
    Inserts a new incident record into PostgreSQL, scoped to ``project_id``.

    Args:
        db: Active async DB session.
        project_id: The project this incident belongs to (enforces tenant isolation).
        action: ``BLOCKED``, ``AUDITED``, or ``PASSED``.
        client_ip: Requesting client IP.
        http_method: HTTP method (GET, POST, …).
        url_path: Request path where the attack was detected.
        detection_stage: Which WAF tier caught it.
        confidence_score: DL model confidence (0.0–1.0).
        trigger_tokens: List of token strings that triggered detection.
        raw_payload: Original untouched payload.
        normalized_payload: Payload after recursive normalization.
        latency_ms: Total WAF inspection time in milliseconds.
        attack_category: Human-readable attack type label.
        severity: ``LOW``, ``MEDIUM``, ``HIGH``, or ``CRITICAL``.
        event_id: Optional custom event ID; auto-generated if not provided.

    Returns:
        The persisted ``Incident`` ORM instance.
    """
    incident = Incident(
        project_id=project_id,
        event_id=event_id or _new_event_id(),
        timestamp=datetime.now(timezone.utc),
        action=action,
        client_ip=client_ip,
        http_method=http_method,
        url_path=url_path,
        detection_stage=detection_stage,
        confidence_score=round(confidence_score, 4),
        trigger_tokens=trigger_tokens or [],
        raw_payload=raw_payload or "",
        normalized_payload=normalized_payload or "",
        latency_ms=round(latency_ms, 3),
        attack_category=attack_category,
        severity=severity,
    )
    db.add(incident)
    await db.flush()  # populate id without committing — caller's session commits
    return incident


async def get_incidents(
    db: AsyncSession,
    *,
    project_id: str,
    limit: int = 50,
    offset: int = 0,
    action_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
) -> list[Incident]:
    """
    Returns a paginated list of incidents for a given project.

    Args:
        db: Active async DB session.
        project_id: Tenant scope filter — REQUIRED.
        limit: Maximum number of results (default 50, max 200).
        offset: Number of records to skip for pagination.
        action_filter: Filter by action (``BLOCKED``, ``AUDITED``, ``PASSED``).
        severity_filter: Filter by severity (``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``).
        from_date: Inclusive lower bound for incident timestamp.
        to_date: Inclusive upper bound for incident timestamp.

    Returns:
        List of ``Incident`` ORM instances ordered newest-first.
    """
    limit = min(limit, 200)  # hard cap

    stmt = (
        select(Incident)
        .where(Incident.project_id == project_id)
        .order_by(Incident.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )

    if action_filter:
        stmt = stmt.where(Incident.action == action_filter.upper())
    if severity_filter:
        stmt = stmt.where(Incident.severity == severity_filter.upper())
    if from_date:
        stmt = stmt.where(Incident.timestamp >= from_date)
    if to_date:
        stmt = stmt.where(Incident.timestamp <= to_date)

    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_incident_count(
    db: AsyncSession,
    *,
    project_id: str,
    action_filter: Optional[str] = None,
) -> int:
    """
    Returns the total count of incidents for a project, with optional action filter.

    Args:
        db: Active async DB session.
        project_id: Tenant scope filter — REQUIRED.
        action_filter: Optional filter by action string.

    Returns:
        Integer count of matching incident rows.
    """
    stmt = select(func.count(Incident.id)).where(Incident.project_id == project_id)
    if action_filter:
        stmt = stmt.where(Incident.action == action_filter.upper())

    result = await db.execute(stmt)
    return result.scalar_one() or 0


def incident_to_dict(incident: Incident) -> dict[str, Any]:
    """
    Converts an Incident ORM object to a plain dict suitable for JSON serialization
    or ECS/CEF export formatting.

    Args:
        incident: An ``Incident`` ORM instance.

    Returns:
        Dictionary with all incident fields.
    """
    return {
        "id": incident.id,
        "project_id": incident.project_id,
        "event_id": incident.event_id,
        "timestamp": incident.timestamp.isoformat() if incident.timestamp else None,
        "action": incident.action,
        "client_ip": incident.client_ip,
        "http_method": incident.http_method,
        "url_path": incident.url_path,
        "detection_stage": incident.detection_stage,
        "confidence_score": incident.confidence_score,
        "trigger_tokens": incident.trigger_tokens,
        "raw_payload": incident.raw_payload,
        "normalized_payload": incident.normalized_payload,
        "latency_ms": incident.latency_ms,
        "attack_category": incident.attack_category,
        "severity": incident.severity,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
    }
