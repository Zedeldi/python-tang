"""Shared testing configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient

from tang.app import app
from tang.peers import Client, Server


@pytest.fixture
def client() -> Client:
    """Return Client instance for testing."""
    return Client()


@pytest.fixture
def server() -> Server:
    """Return Server instance for testing."""
    return Server()


@pytest.fixture
def api() -> TestClient:
    """Return FastAPI TestClient instance."""
    return TestClient(app)
