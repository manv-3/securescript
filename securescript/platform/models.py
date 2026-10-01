"""
SecureScript Platform — SQLAlchemy ORM Models.

Tables:
- users      : Platform accounts (email + hashed password).
- projects   : Protected websites registered by users (slug, frontend_url, backend_url).
- incidents  : Blocked/audited XSS attack records, scoped per project.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from securescript.platform.database import Base


def _now() -> datetime:
    """Returns the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    """Generates a new UUID4 string."""
    return str(uuid.uuid4())


# ==============================================================================
# User
# ==============================================================================
class User(Base):
    """
    Platform account.

    Attributes:
        id: UUID primary key.
        email: Unique login email address.
        hashed_password: bcrypt hash of the user's password.
        created_at: Account creation timestamp (UTC).
        projects: Back-reference to all projects owned by this user.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid, index=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    # Relationships
    projects: Mapped[list["Project"]] = relationship(
        "Project", back_populates="owner", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id!r} email={self.email!r}>"


# ==============================================================================
# Project
# ==============================================================================
class Project(Base):
    """
    A protected website registered by a user.

    Each project gets a unique slug used in the proxy path:
    ``/proxy/{slug}/{path}``

    Attributes:
        id: UUID primary key.
        user_id: FK to the owning user.
        name: Human-readable project name.
        slug: URL-safe unique identifier (e.g. ``my-app-a3f2``).
        frontend_url: The origin frontend URL to proxy traffic to.
        backend_url: The origin backend/API URL to proxy API calls to.
        is_active: Whether the proxy is live. Soft-delete by setting False.
        frontend_reachable: Result of the async reachability ping on creation.
        backend_reachable: Result of the async reachability ping on creation.
        webhook_url: Optional URL to POST attack alerts to.
        alert_email: Optional email address to send attack alert emails to.
        created_at: Project creation timestamp (UTC).
    """

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    frontend_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    backend_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    frontend_reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    backend_reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    alert_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="projects")
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="project", cascade="all, delete-orphan"
    )

    # Ensure slug is globally unique
    __table_args__ = (
        UniqueConstraint("slug", name="uq_projects_slug"),
        Index("ix_projects_user_id_is_active", "user_id", "is_active"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Project id={self.id!r} slug={self.slug!r} active={self.is_active}>"


# ==============================================================================
# Incident
# ==============================================================================
class Incident(Base):
    """
    An XSS attack incident recorded by the WAF — scoped to a project.

    Attributes:
        id: UUID primary key.
        project_id: FK to the project that was under attack.
        event_id: Human-readable ray ID (e.g. ``RAY-9A82F104BC``).
        timestamp: When the attack was detected (UTC).
        action: ``BLOCKED``, ``AUDITED``, or ``PASSED``.
        client_ip: Attacking client IP address.
        http_method: HTTP method of the request (GET, POST, …).
        url_path: Request path that triggered the detection.
        detection_stage: ``Fast-Path Lexical Analyzer`` or ``PyTorch Bi-LSTM Neural Network``.
        confidence_score: DL model confidence (0.0–1.0).
        trigger_tokens: JSON list of tokens that triggered detection.
        raw_payload: Original untouched payload string.
        normalized_payload: Payload after recursive normalization.
        latency_ms: Total WAF inspection latency in milliseconds.
        attack_category: Attack classification (e.g. ``Reflected XSS``).
        severity: ``LOW``, ``MEDIUM``, ``HIGH``, or ``CRITICAL``.
        created_at: DB insertion timestamp (UTC).
    """

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid, index=True
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, index=True
    )
    action: Mapped[str] = mapped_column(String(20), nullable=False)       # BLOCKED / AUDITED / PASSED
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)    # supports IPv6
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    url_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    detection_stage: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    trigger_tokens: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False, default="")
    normalized_payload: Mapped[str] = mapped_column(Text, nullable=False, default="")
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    attack_category: Mapped[str] = mapped_column(
        String(100), nullable=False, default="Cross-Site Scripting (XSS)"
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="HIGH")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="incidents")

    # Composite index for fast per-project filtered queries
    __table_args__ = (
        Index("ix_incidents_project_id_action", "project_id", "action"),
        Index("ix_incidents_project_id_timestamp", "project_id", "timestamp"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Incident id={self.id!r} event_id={self.event_id!r} "
            f"action={self.action!r} project_id={self.project_id!r}>"
        )
