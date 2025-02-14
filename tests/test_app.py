import pytest
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
    pytest.assume(response.status_code == 200)
    pytest.assume(response.data.decode("utf-8") == "¡Hola desde Cloud Run con Python 3!")
