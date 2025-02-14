import pytest
from app import app

@pytest.fixture
def client():
    """Sets up the test client for Flask."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_home(client):
    """Tests that the root path '/' returns the expected response."""
    response = client.get("/")
    pytest.assume(response.status_code == 200)  # ✅ Uses pytest.assume correctly
    pytest.assume(response.data.decode("utf-8") == "Hello from Cloud Run with Python 3!")
