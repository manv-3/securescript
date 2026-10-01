"""
Test suite for SecureScript Platform Authentication API.

Tests:
- User registration with validation
- User login with JWT generation
- Password hashing and verification
- Authentication error handling
"""

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from securescript.platform.database import Base
from securescript.platform.models import User
from securescript.platform.routers.auth_router import auth_router
from securescript.platform.auth import verify_password


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


@pytest.fixture
def app_with_auth(test_db_session_factory):
    """Create FastAPI app with auth router."""
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

    from securescript.platform.database import get_db

    app.dependency_overrides[get_db] = get_db_override
    app.include_router(auth_router)
    return app


@pytest.mark.asyncio
class TestAuthRegister:
    """Tests for user registration endpoint."""

    async def test_register_success(self, app_with_auth):
        """Test successful user registration."""
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/register",
                json={"email": "newuser@example.com", "password": "SecurePassword123"},
            )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert "id" in data
        assert "created_at" in data

    async def test_register_duplicate_email(self, app_with_auth, test_db_session_factory):
        """Test that duplicate emails are rejected."""
        # Create first user directly in DB
        async with test_db_session_factory() as session:
            user = User(email="duplicate@example.com", hashed_password="some_hash")
            session.add(user)
            await session.commit()

        # Try to register same email via API
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/register",
                json={"email": "duplicate@example.com", "password": "Password123"},
            )

        assert response.status_code == 409
        data = response.json()
        assert "already exists" in data["detail"]

    async def test_register_weak_password(self, app_with_auth):
        """Test that weak passwords (< 8 chars) are rejected."""
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/register",
                json={"email": "weakpwd@example.com", "password": "short"},
            )

        assert response.status_code == 422  # Validation error

    async def test_register_invalid_email(self, app_with_auth):
        """Test that invalid emails are rejected."""
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/register",
                json={"email": "not-an-email", "password": "ValidPassword123"},
            )

        assert response.status_code == 422


@pytest.mark.asyncio
class TestAuthLogin:
    """Tests for user login endpoint."""

    async def test_login_success(self, app_with_auth, test_db_session_factory):
        """Test successful user login."""
        # Create user in DB
        async with test_db_session_factory() as session:
            from securescript.platform.auth import hash_password

            user = User(
                email="existing@example.com",
                hashed_password=hash_password("CorrectPassword123"),
            )
            session.add(user)
            await session.commit()

        # Login
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/login",
                json={"email": "existing@example.com", "password": "CorrectPassword123"},
            )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 10  # Should be a JWT token

    async def test_login_wrong_password(self, app_with_auth, test_db_session_factory):
        """Test login fails with wrong password."""
        # Create user in DB
        async with test_db_session_factory() as session:
            from securescript.platform.auth import hash_password

            user = User(
                email="existing@example.com",
                hashed_password=hash_password("CorrectPassword123"),
            )
            session.add(user)
            await session.commit()

        # Try login with wrong password
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/login",
                json={"email": "existing@example.com", "password": "WrongPassword"},
            )

        assert response.status_code == 401

    async def test_login_nonexistent_user(self, app_with_auth):
        """Test login fails for non-existent user."""
        async with AsyncClient(transport=ASGITransport(app=app_with_auth), base_url="http://test") as client:
            response = await client.post(
                "/auth/login",
                json={"email": "nonexistent@example.com", "password": "AnyPassword123"},
            )

        assert response.status_code == 401


@pytest.mark.asyncio
class TestPasswordHashing:
    """Tests for password hashing utilities."""

    async def test_hash_password_creates_different_hashes(self):
        """Test that same password produces different hashes (bcrypt salt)."""
        from securescript.platform.auth import hash_password

        pwd = "MyPassword123"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)

        # Hashes should be different due to different salts
        assert hash1 != hash2

    async def test_verify_password_succeeds(self):
        """Test that correct password verifies."""
        from securescript.platform.auth import hash_password, verify_password

        pwd = "MyPassword123"
        hashed = hash_password(pwd)

        assert verify_password(pwd, hashed) is True

    async def test_verify_password_fails_with_wrong_pwd(self):
        """Test that wrong password fails verification."""
        from securescript.platform.auth import hash_password, verify_password

        pwd = "CorrectPassword"
        hashed = hash_password(pwd)

        assert verify_password("WrongPassword", hashed) is False
