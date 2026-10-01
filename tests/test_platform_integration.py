"""
Integration tests for SecureScript Platform APIs.

Tests:
- End-to-end project CRUD operations
- Multi-tenant isolation
- Analytics and reporting
- Incident storage and retrieval
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from securescript.platform.database import Base, get_db
from securescript.platform.models import User, Project, Incident
from securescript.platform.routers.auth_router import auth_router
from securescript.platform.routers.project_router import project_router
from securescript.platform.routers.analytics_router import analytics_router
from securescript.platform.auth import create_access_token

# Use a placeholder hash for tests to avoid bcrypt Python 3.14 compatibility issues
TEST_PASSWORD_HASH = "$2b$12$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jKMUW"


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
        bind=test_engine, class_=AsyncSession, autocommit=False, autoflush=False, expire_on_commit=False
    )
    return async_session


@pytest.fixture
def test_app(test_db_session_factory):
    """Create FastAPI app with all routers."""
    app = FastAPI()

    async def get_db_override():
        async with test_db_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = get_db_override
    app.include_router(auth_router)
    app.include_router(project_router)
    app.include_router(analytics_router)
    return app


@pytest.fixture
async def authenticated_client(test_app, test_db_session_factory):
    """Create an authenticated client with a test user."""
    # Create user in DB
    async with test_db_session_factory() as session:
        user = User(
            email="testuser@example.com",
            hashed_password=TEST_PASSWORD_HASH,
        )
        session.add(user)
        await session.flush()
        user_id = user.id
        await session.commit()

    # Generate token
    token = create_access_token(data={"sub": user_id})

    client = AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test")
    client.headers["Authorization"] = f"Bearer {token}"
    return client, user_id


@pytest.mark.asyncio
class TestProjectCRUD:
    """Tests for project CRUD operations."""

    async def test_create_project(self, authenticated_client):
        """Test creating a new project."""
        client, _ = authenticated_client

        response = await client.post(
            "/platform/projects",
            json={
                "name": "My Awesome App",
                "frontend_url": "https://myapp.vercel.app",
                "backend_url": "https://myapp.onrender.com",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "My Awesome App"
        assert "slug" in data
        assert data["proxy_path"].startswith("/proxy/")
        assert data["is_active"] is True

    async def test_list_projects(self, authenticated_client, test_db_session_factory):
        """Test listing all projects for a user."""
        client, user_id = authenticated_client

        # Create a project
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="Test App",
                slug="test-app-xyz",
                frontend_url="https://test.example.com",
                backend_url="https://api-test.example.com",
            )
            session.add(project)
            await session.commit()

        response = await client.get("/platform/projects")

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(p["slug"] == "test-app-xyz" for p in data)

    async def test_get_project(self, authenticated_client, test_db_session_factory):
        """Test getting a single project."""
        client, user_id = authenticated_client

        # Create a project
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="My App",
                slug="my-app-abc",
                frontend_url="https://myapp.example.com",
                backend_url="https://api.example.com",
            )
            session.add(project)
            await session.commit()
            project_id = project.id

        response = await client.get(f"/platform/projects/{project_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["slug"] == "my-app-abc"
        assert data["id"] == project_id

    async def test_get_project_not_found(self, authenticated_client):
        """Test getting a non-existent project returns 404."""
        client, _ = authenticated_client

        response = await client.get("/platform/projects/nonexistent-id")

        assert response.status_code == 404

    async def test_delete_project(self, authenticated_client, test_db_session_factory):
        """Test soft-deleting a project."""
        client, user_id = authenticated_client

        # Create a project
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="Deletable App",
                slug="deletable-app-xyz",
                frontend_url="https://delete.example.com",
                backend_url="https://api-delete.example.com",
            )
            session.add(project)
            await session.commit()
            project_id = project.id

        response = await client.delete(f"/platform/projects/{project_id}")

        assert response.status_code == 204

        # Verify it's deleted
        get_response = await client.get(f"/platform/projects/{project_id}")
        assert get_response.status_code == 404

    async def test_update_alert_config(self, authenticated_client, test_db_session_factory):
        """Test updating webhook/email alert config."""
        client, user_id = authenticated_client

        # Create a project
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="Alert Test",
                slug="alert-test-xyz",
                frontend_url="https://alert.example.com",
                backend_url="https://api-alert.example.com",
            )
            session.add(project)
            await session.commit()
            project_id = project.id

        response = await client.put(
            f"/platform/projects/{project_id}/alerts",
            json={
                "webhook_url": "https://webhook.site/abc123",
                "alert_email": "alerts@mycompany.com",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["webhook_url"] == "https://webhook.site/abc123"
        assert data["alert_email"] == "alerts@mycompany.com"


@pytest.mark.asyncio
class TestMultiTenancyIsolation:
    """Tests for multi-tenant isolation."""

    async def test_cannot_access_other_users_project(
        self, test_app, test_db_session_factory
    ):
        """Test that users cannot access other users' projects."""
        # Create two users
        async with test_db_session_factory() as session:
            user1 = User(
                email="user1@example.com",
                hashed_password=TEST_PASSWORD_HASH,
            )
            user2 = User(
                email="user2@example.com",
                hashed_password=TEST_PASSWORD_HASH,
            )
            session.add(user1)
            session.add(user2)
            await session.commit()
            user1_id = user1.id
            user2_id = user2.id

        # User 1 creates a project
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user1_id,
                name="User 1's App",
                slug="user1-app-xyz",
                frontend_url="https://user1.example.com",
                backend_url="https://api-user1.example.com",
            )
            session.add(project)
            await session.commit()
            project_id = project.id

        # User 2 tries to access User 1's project
        token2 = create_access_token(data={"sub": user2_id})
        client2 = AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test")
        client2.headers["Authorization"] = f"Bearer {token2}"

        response = await client2.get(f"/platform/projects/{project_id}")

        assert response.status_code == 403


@pytest.mark.asyncio
class TestAnalytics:
    """Tests for analytics and reporting."""

    async def test_get_project_stats(
        self, authenticated_client, test_db_session_factory
    ):
        """Test getting project statistics."""
        client, user_id = authenticated_client

        # Create project with incidents
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="Stats App",
                slug="stats-app-xyz",
                frontend_url="https://stats.example.com",
                backend_url="https://api-stats.example.com",
            )
            session.add(project)
            await session.flush()

            # Add some incidents
            for i in range(3):
                incident = Incident(
                    project_id=project.id,
                    event_id=f"RAY-{i:010d}",
                    action="BLOCKED" if i < 2 else "PASSED",
                    client_ip=f"192.168.1.{i}",
                    http_method="POST",
                    url_path="/api/submit",
                    detection_stage="Fast-Path Lexical Analyzer",
                    confidence_score=0.95,
                    trigger_tokens=["<script>"],
                    raw_payload="<script>alert('xss')</script>",
                    normalized_payload="<script>alert('xss')</script>",
                    latency_ms=1.5,
                )
                session.add(incident)
            await session.commit()
            project_id = project.id

        response = await client.get(f"/platform/projects/{project_id}/stats")

        assert response.status_code == 200
        data = response.json()
        assert data["total_inspected"] == 3
        assert data["blocked"] == 2
        assert data["passed"] == 1
        assert data["block_rate_pct"] == 66.67

    async def test_list_incidents(self, authenticated_client, test_db_session_factory):
        """Test listing incidents for a project."""
        client, user_id = authenticated_client

        # Create project with incidents
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="Incident App",
                slug="incident-app-xyz",
                frontend_url="https://incident.example.com",
                backend_url="https://api-incident.example.com",
            )
            session.add(project)
            await session.flush()

            for i in range(5):
                incident = Incident(
                    project_id=project.id,
                    event_id=f"RAY-{i:010d}",
                    action="BLOCKED",
                    client_ip="192.168.1.100",
                    http_method="POST",
                    url_path="/api/endpoint",
                    detection_stage="PyTorch Bi-LSTM",
                    confidence_score=0.92 + (i * 0.01),
                    trigger_tokens=["token"],
                    raw_payload="payload",
                    normalized_payload="payload",
                    latency_ms=2.0,
                )
                session.add(incident)
            await session.commit()
            project_id = project.id

        response = await client.get(f"/platform/projects/{project_id}/incidents")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 5
        assert len(data["incidents"]) <= data["page_size"]

    async def test_get_full_report(
        self, authenticated_client, test_db_session_factory
    ):
        """Test downloading full security report."""
        client, user_id = authenticated_client

        # Create project
        async with test_db_session_factory() as session:
            project = Project(
                user_id=user_id,
                name="Report App",
                slug="report-app-xyz",
                frontend_url="https://report.example.com",
                backend_url="https://api-report.example.com",
            )
            session.add(project)
            await session.flush()

            incident = Incident(
                project_id=project.id,
                event_id="RAY-0000000001",
                action="BLOCKED",
                client_ip="192.168.1.100",
                http_method="POST",
                url_path="/api/form",
                detection_stage="Fast-Path Lexical Analyzer",
                confidence_score=0.98,
                trigger_tokens=["<script>"],
                raw_payload="<script>alert('xss')</script>",
                normalized_payload="<script>alert('xss')</script>",
                latency_ms=1.2,
            )
            session.add(incident)
            await session.commit()
            project_id = project.id

        response = await client.get(f"/platform/projects/{project_id}/report")

        assert response.status_code == 200
        data = response.json()
        assert "report_generated_at" in data
        assert "project" in data
        assert "stats" in data
        assert "recent_incidents" in data
        assert data["project"]["slug"] == "report-app-xyz"
