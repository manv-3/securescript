"""
Test suite for SecureScript Platform Database Models and Async Setup.

Tests:
- ORM model creation and relationships
- Async database session factory
- Multi-tenancy isolation invariants
"""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from securescript.platform.models import User, Project, Incident
from securescript.platform.database import Base


@pytest_asyncio.fixture
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


@pytest_asyncio.fixture
async def test_db(test_engine):
    """Create a test database session."""
    async_session = async_sessionmaker(
        bind=test_engine, class_=AsyncSession, autocommit=False, autoflush=False
    )
    async with async_session() as session:
        yield session


class TestUserModel:
    """Tests for User ORM model."""

    @pytest.mark.asyncio
    async def test_create_user(self, test_db: AsyncSession):
        """Test creating a user."""
        user = User(email="test@example.com", hashed_password="hashed_pwd_123")
        test_db.add(user)
        await test_db.flush()

        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.created_at is not None

    @pytest.mark.asyncio
    async def test_user_email_unique(self, test_db: AsyncSession):
        """Test that user emails are unique."""
        user1 = User(email="duplicate@example.com", hashed_password="pwd1")
        user2 = User(email="duplicate@example.com", hashed_password="pwd2")

        test_db.add(user1)
        await test_db.flush()

        test_db.add(user2)
        with pytest.raises(Exception):  # IntegrityError
            await test_db.flush()


class TestProjectModel:
    """Tests for Project ORM model."""

    @pytest.mark.asyncio
    async def test_create_project(self, test_db: AsyncSession):
        """Test creating a project."""
        user = User(email="owner@example.com", hashed_password="pwd")
        test_db.add(user)
        await test_db.flush()

        project = Project(
            user_id=user.id,
            name="My App",
            slug="my-app-a3f2",
            frontend_url="https://myapp.vercel.app",
            backend_url="https://myapp.onrender.com",
        )
        test_db.add(project)
        await test_db.flush()

        assert project.id is not None
        assert project.slug == "my-app-a3f2"
        assert project.is_active is True

    @pytest.mark.asyncio
    async def test_project_slug_unique(self, test_db: AsyncSession):
        """Test that project slugs are globally unique."""
        user = User(email="owner@example.com", hashed_password="pwd")
        test_db.add(user)
        await test_db.flush()

        proj1 = Project(
            user_id=user.id,
            name="App 1",
            slug="duplicate-slug",
            frontend_url="https://app1.example.com",
            backend_url="https://api1.example.com",
        )
        test_db.add(proj1)
        await test_db.flush()

        proj2 = Project(
            user_id=user.id,
            name="App 2",
            slug="duplicate-slug",
            frontend_url="https://app2.example.com",
            backend_url="https://api2.example.com",
        )
        test_db.add(proj2)
        with pytest.raises(Exception):  # IntegrityError
            await test_db.flush()

    @pytest.mark.asyncio
    async def test_project_soft_delete(self, test_db: AsyncSession):
        """Test soft-deleting a project."""
        user = User(email="owner@example.com", hashed_password="pwd")
        test_db.add(user)
        await test_db.flush()

        project = Project(
            user_id=user.id,
            name="Deletable App",
            slug="deletable-app-xyz",
            frontend_url="https://delete.example.com",
            backend_url="https://api-delete.example.com",
        )
        test_db.add(project)
        await test_db.flush()

        project.is_active = False
        await test_db.flush()

        assert project.is_active is False


class TestIncidentModel:
    """Tests for Incident ORM model."""

    @pytest.mark.asyncio
    async def test_create_incident(self, test_db: AsyncSession):
        """Test creating an incident record."""
        user = User(email="owner@example.com", hashed_password="pwd")
        test_db.add(user)
        await test_db.flush()

        project = Project(
            user_id=user.id,
            name="My App",
            slug="my-app-a3f2",
            frontend_url="https://myapp.vercel.app",
            backend_url="https://myapp.onrender.com",
        )
        test_db.add(project)
        await test_db.flush()

        incident = Incident(
            project_id=project.id,
            event_id="RAY-ABC123DEF",
            action="BLOCKED",
            client_ip="192.168.1.100",
            http_method="POST",
            url_path="/api/submit",
            detection_stage="Fast-Path Lexical Analyzer",
            confidence_score=0.98,
            trigger_tokens=["<script>", "alert"],
            raw_payload="<script>alert('xss')</script>",
            normalized_payload="<script>alert('xss')</script>",
            latency_ms=1.2,
            severity="HIGH",
        )
        test_db.add(incident)
        await test_db.flush()

        assert incident.id is not None
        assert incident.project_id == project.id
        assert incident.action == "BLOCKED"

    @pytest.mark.asyncio
    async def test_incident_multi_tenancy_isolation(self, test_db: AsyncSession):
        """Test that incidents are scoped to their project."""
        user1 = User(email="user1@example.com", hashed_password="pwd1")
        user2 = User(email="user2@example.com", hashed_password="pwd2")
        test_db.add(user1)
        test_db.add(user2)
        await test_db.flush()

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
        test_db.add(proj1)
        test_db.add(proj2)
        await test_db.flush()

        incident1 = Incident(
            project_id=proj1.id,
            event_id="RAY-111111111",
            action="BLOCKED",
            client_ip="10.0.0.1",
            http_method="GET",
            url_path="/path1",
            detection_stage="Fast-Path Lexical Analyzer",
            confidence_score=0.95,
            trigger_tokens=["token1"],
            raw_payload="payload1",
            normalized_payload="payload1",
            latency_ms=1.0,
        )
        incident2 = Incident(
            project_id=proj2.id,
            event_id="RAY-222222222",
            action="BLOCKED",
            client_ip="10.0.0.2",
            http_method="POST",
            url_path="/path2",
            detection_stage="PyTorch Bi-LSTM",
            confidence_score=0.92,
            trigger_tokens=["token2"],
            raw_payload="payload2",
            normalized_payload="payload2",
            latency_ms=2.0,
        )
        test_db.add(incident1)
        test_db.add(incident2)
        await test_db.flush()

        # Verify incidents belong to correct projects
        from sqlalchemy import select

        result1 = await test_db.execute(
            select(Incident).where(Incident.project_id == proj1.id)
        )
        incidents_proj1 = result1.scalars().all()
        assert len(incidents_proj1) == 1
        assert incidents_proj1[0].event_id == "RAY-111111111"

        result2 = await test_db.execute(
            select(Incident).where(Incident.project_id == proj2.id)
        )
        incidents_proj2 = result2.scalars().all()
        assert len(incidents_proj2) == 1
        assert incidents_proj2[0].event_id == "RAY-222222222"


class TestDatabaseRelationships:
    """Tests for ORM relationships and cascading deletes."""

    @pytest.mark.asyncio
    async def test_user_to_projects_relationship(self, test_db: AsyncSession):
        """Test user→projects relationship."""
        user = User(email="owner@example.com", hashed_password="pwd")
        proj1 = Project(
            user_id=None,  # Will be set via relationship
            name="App 1",
            slug="app-1",
            frontend_url="https://app1.example.com",
            backend_url="https://api1.example.com",
        )
        proj2 = Project(
            user_id=None,
            name="App 2",
            slug="app-2",
            frontend_url="https://app2.example.com",
            backend_url="https://api2.example.com",
        )
        user.projects = [proj1, proj2]
        test_db.add(user)
        await test_db.flush()

        assert len(user.projects) == 2

    @pytest.mark.asyncio
    async def test_cascade_delete_user_deletes_projects(self, test_db: AsyncSession):
        """Test that deleting a user cascades to delete their projects."""
        from sqlalchemy import select

        user = User(email="deleteme@example.com", hashed_password="pwd")
        project = Project(
            user_id=None,
            name="To Delete",
            slug="to-delete-xyz",
            frontend_url="https://delete.example.com",
            backend_url="https://api-delete.example.com",
        )
        user.projects = [project]
        test_db.add(user)
        await test_db.flush()

        user_id = user.id
        project_id = project.id

        await test_db.delete(user)
        await test_db.flush()

        # Verify project is deleted
        result = await test_db.execute(select(Project).where(Project.id == project_id))
        assert result.scalar_one_or_none() is None
