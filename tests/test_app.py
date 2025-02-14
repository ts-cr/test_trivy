import pytest
import pytest_assume # You should use pytest, and if a test fails, the workflow should stop immediately.

from app import app

@pytest.fixture
def client():
    """Configura el cliente de pruebas para Flask."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_home(client):
    """Prueba que la ruta raíz '/' responde correctamente."""
    response = client.get("/")
    pytest_assume.assume(response.status_code == 200)
    pytest_assume.assume(response.data.decode("utf-8") == "¡Hola desde Cloud Run con Python 3!")
