"""
Unit tests for SecureScript Platform endpoint logic.

Tests router logic without HTTP client complexity.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from securescript.platform.database import Base
from securescript.platform.models import User, Project, Incident
from securescript.platform.routers.project_router import _generate_slug
from securescript.platform.incident_store import (
    record_incident,
    get_incidents,
    get_incident_count,
    incident_to_dict,
)


@pytest.fixture
async def test_engine():
    """Create an in-memory SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def test_db_session_factory(test_engine):
    """Create test DB session factory."""
    async_session = async_sessionmaker(
        bind=test_engine, class_=AsyncSession, autocommit=False, autoflush=False
    )
    return async_session


@pytest.mark.asyncio
class TestSlugGeneration:
    """Tests for project slug generation."""

    async def test_generate_slug_simple(self):
        """Test slug generation from a simple project name."""
        slug = _generate_slug("My App")
        assert slug.startswith("my-app-")
        assert len(slug) > 7  # name + dash + 4-char suffix

    async def test_generate_slug_special_chars(self):
        """Test slug generation with special characters."""
        slug = _generate_slug("My Cool App!!!")
        assert slug.startswith("my-cool-app-")
        parts = slug.split("-")
        assert len(parts[-1]) == 4  # suffix is 4 chars

    async def test_generate_slug_unique(self):
        """Test that multiple slug generations produce different suffixes."""
        slug1 = _generate_slug("Same Name")
        slug2 = _generate_slug("Same Name")
        # They should be different due to random suffix
        assert slug1 != slug2
        assert slug1.startswith("same-name-")
        assert slug2.startswith("same-name-")


@pytest.mark.asyncio
class TestIncidentRecording:
    """Tests for incident recording and querying."""

    async def test_record_incident_success(self, test_db_session_factory):
        """Test recording a single incident."""
        async with test_db_session_factory() as session:
            user = User(email="owner@example.com", hashed_password="hash")
            session.add(user)
            await session.flush()

            project = Project(
                user_id=user.id,
                name="Test App",
                slug="test-app-xyz",
                frontend_url="https://test.example.com",
                backend_url="https://api.example.com",
            )
            session.add(project)
            await session.flush()

            incident = await record_incident(
                session,
                project_id=project.id,
                action="BLOCKED",
                client_ip="192.168.1.1",
                http_method="POST",
                url_path="/api/form",
                detection_stage="Fast-Path Lexical Analyzer",
                confidence_score=0.98,
                trigger_tokens=["<script>"],
                raw_payload="<script>alert('xss')</script>",
                normalized_payload="<script>alert('xss')</script>",
                latency_ms=1.2,
            )

            assert incident.id is not None
            assert incident.project_id == project.id
            assert incident.action == "BLOCKED"
            assert incident.confidence_score == 0.98

    async def test_get_incidents_paging(self, test_db_session_factory):
        """Test paginated incident retrieval."""
        async with test_db_session_factory() as session:
            user = User(email="owner@example.com", hashed_password="hash")
            session.add(user)
            await session.flush()

            project = Project(
                user_id=user.id,
                name="Test App",
                slug="test-app-xyz",
                frontend_url="https://test.example.com",
                backend_url="https://api.example.com",
            )
            session.add(project)
            await session.flush()

            # Add 10 incidents
            for i in range(10):
                await record_incident(
                    session,
                    project_id=project.id,
                    action="BLOCKED",
                    client_ip=f"192.168.1.{i}",
                    http_method="POST",
                    url_path="/api/endpoint",
                    detection_stage="Fast-Path Lexical Analyzer",
                    confidence_score=0.90 + (i * 0.01),
                    trigger_tokens=["token"],
                    raw_payload="payload",
                    normalized_payload="payload",
                    latency_ms=1.0,
                )

            # Test pagination
            page1 = await get_incidents(session, project_id=project.id, limit=5, offset=0)
            assert len(page1) == 5

            page2 = await get_incidents(session, project_id=project.id, limit=5, offset=5)
            assert len(page2) == 5

            # Pages should have different incidents
            assert page1[0].id != page2[0].id

    async def test_get_incident_count(self, test_db_session_factory):
        """Test incident counting with filters."""
        async with test_db_session_factory() as session:
            user = User(email="owner@example.com", hashed_password="hash")
            session.add(user)
            await session.flush()

            project = Project(
                user_id=user.id,
                name="Test App",
                slug="test-app-xyz",
                frontend_url="https://test.example.com",
                backend_url="https://api.example.com",
            )
            session.add(project)
            await session.flush()

            # Add 5 blocked, 3 passed
            for i in range(5):
                await record_incident(
                    session,
                    project_id=project.id,
                    action="BLOCKED",
                    client_ip="192.168.1.1",
                    http_method="POST",
                    url_path="/api/endpoint",
                    detection_stage="Fast-Path",
                    confidence_score=0.95,
                    trigger_tokens=["token"],
                    raw_payload="payload",
                    normalized_payload="payload",
                    latency_ms=1.0,
                )

            for i in range(3):
                await record_incident(
                    session,
                    project_id=project.id,
                    action="PASSED",
                    client_ip="192.168.1.2",
                    http_method="GET",
                    url_path="/api/data",
                    detection_stage="Fast-Path",
                    confidence_score=0.10,
                    trigger_tokens=[],
                    raw_payload="clean",
                    normalized_payload="clean",
                    latency_ms=0.5,
                )

            # Test total count
            total = await get_incident_count(session, project_id=project.id)
            assert total == 8

            # Test filtered count
            blocked_count = await get_incident_count(
                session, project_id=project.id, action_filter="BLOCKED"
            )
            assert blocked_count == 5

            passed_count = await get_incident_count(
                session, project_id=project.id, action_filter="PASSED"
            )
            assert passed_count == 3

    async def test_incident_to_dict(self, test_db_session_factory):
        """Test incident serialization to dictionary."""
        async with test_db_session_factory() as session:
            user = User(email="owner@example.com", hashed_password="hash")
            session.add(user)
            await session.flush()

            project = Project(
                user_id=user.id,
                name="Test App",
                slug="test-app-xyz",
                frontend_url="https://test.example.com",
                backend_url="https://api.example.com",
            )
            session.add(project)
            await session.flush()

            incident = await record_incident(
                session,
                project_id=project.id,
                action="BLOCKED",
                client_ip="192.168.1.100",
                http_method="POST",
                url_path="/api/submit",
                detection_stage="PyTorch Bi-LSTM",
                confidence_score=0.98,
                trigger_tokens=["<script>", "alert"],
                raw_payload="<script>alert('xss')</script>",
                normalized_payload="<script>alert('xss')</script>",
                latency_ms=15.5,
                severity="CRITICAL",
                event_id="RAY-CUSTOMID123",
            )

            incident_dict = incident_to_dict(incident)

            assert incident_dict["project_id"] == project.id
            assert incident_dict["action"] == "BLOCKED"
            assert incident_dict["client_ip"] == "192.168.1.100"
            assert incident_dict["confidence_score"] == 0.98
            assert incident_dict["severity"] == "CRITICAL"
            assert incident_dict["event_id"] == "RAY-CUSTOMID123"
            assert "timestamp" in incident_dict
            assert "id" in incident_dict


@pytest.mark.asyncio
class TestMultiTenancyIncidents:
    """Tests for multi-tenant incident isolation."""

    async def test_incidents_scoped_by_project(self, test_db_session_factory):
        """Test that incidents are strictly scoped by project_id."""
        async with test_db_session_factory() as session:
            user1 = User(email="user1@example.com", hashed_password="hash")
            user2 = User(email="user2@example.com", hashed_password="hash")
            session.add(user1)
            session.add(user2)
            await session.flush()

            proj1 = Project(
                user_id=user1.id,
                name="App 1",
                slug="app-1-xyz",
                frontend_url="https://app1.example.com",
                backend_url="https://api1.example.com",
            )
            proj2 = Project(
                user_id=user2.id,
                name="App 2",
                slug="app-2-xyz",
                frontend_url="https://app2.example.com",
                backend_url="https://api2.example.com",
            )
            session.add(proj1)
            session.add(proj2)
            await session.flush()

            # Record incidents in each project
            await record_incident(
                session,
                project_id=proj1.id,
                action="BLOCKED",
                client_ip="10.0.0.1",
                http_method="POST",
                url_path="/path1",
                detection_stage="Fast-Path",
                confidence_score=0.95,
                trigger_tokens=["token1"],
                raw_payload="payload1",
                normalized_payload="payload1",
                latency_ms=1.0,
                event_id="RAY-PROJ1-001",
            )

            await record_incident(
                session,
                project_id=proj2.id,
                action="BLOCKED",
                client_ip="10.0.0.2",
                http_method="POST",
                url_path="/path2",
                detection_stage="Fast-Path",
                confidence_score=0.92,
                trigger_tokens=["token2"],
                raw_payload="payload2",
                normalized_payload="payload2",
                latency_ms=1.0,
                event_id="RAY-PROJ2-001",
            )

            # Query incidents for each project
            incidents1 = await get_incidents(session, project_id=proj1.id)
            incidents2 = await get_incidents(session, project_id=proj2.id)

            assert len(incidents1) == 1
            assert len(incidents2) == 1
            assert incidents1[0].project_id == proj1.id
            assert incidents2[0].project_id == proj2.id
            assert incidents1[0].event_id == "RAY-PROJ1-001"
            assert incidents2[0].event_id == "RAY-PROJ2-001"
