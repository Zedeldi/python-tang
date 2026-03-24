"""Shared testing configuration and fixtures."""

import pytest

from tang.client import Client
from tang.server import Server


@pytest.fixture
def client() -> Client:
    """Return Client instance for testing."""
    return Client()


@pytest.fixture
def server() -> Server:
    """Return Server instance for testing."""
    return Server()
