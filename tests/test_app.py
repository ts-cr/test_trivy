import pytest
from app import app

@pytest.fixture
def client():
    """Sets up the test client for Flask."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

@pytest.mark.benchmark
def test_home(client, benchmark):
    """Tests and benchmarks the root path '/'."""
    response = benchmark(lambda: client.get("/"))  # ✅ Measures execution time
    print("Response received:", response.data.decode("utf-8"))
    pytest.assume(response.status_code == 200)
    pytest.assume(response.data.decode("utf-8") == "Hello from Cloud Run with Python 3!")
