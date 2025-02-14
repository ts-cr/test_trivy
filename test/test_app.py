import pytest
from app import app

@pytest.fixture
def client():
    """Configuración del cliente de pruebas para Flask."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_home(client):
    """Prueba que la ruta raíz '/' responde correctamente."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.data == b"¡Hola desde Cloud Run con Python 3!"
