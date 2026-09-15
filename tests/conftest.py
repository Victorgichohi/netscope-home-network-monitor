import os

os.environ.update(
    {
        "HNM_ENVIRONMENT": "test",
        "HNM_SECRET_KEY": "test-secret-key-that-is-long-enough",
        "HNM_ADMIN_USERNAME": "admin",
        "HNM_ADMIN_PASSWORD": "correct horse battery staple",
        "HNM_DATABASE_URL": "sqlite:///./test_home_net_monitor.db",
        "HNM_DISCOVERY_ENABLED": "false",
        "HNM_TRAFFIC_CAPTURE_ENABLED": "false",
        "HNM_DIAGNOSTICS_ENABLED": "false",
        "HNM_ROUTER_ADAPTER": "disabled",
        "HNM_LOGIN_RATE_LIMIT": "100",
    }
)

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return client
