"""
Fixtures compartidas por las pruebas unitarias del Ejercicio 2 (XSS).

Las pruebas no necesitan Docker ni un servidor levantado: se usa el cliente de
prueba de Flask y cada test recibe una base SQLite nueva en un directorio
temporal, cargada con los datos de init_db.py (no se toca cine2.db).
"""
import sqlite3
from types import SimpleNamespace

import pytest

import init_db as init_db_module
from app import app as flask_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Aplicación Flask apuntando a una base de datos temporal recién creada."""
    db_path = tmp_path / "cine2_test.db"

    # init_db() siempre escribe en Ejercicio2/cine2.db; se redirige su conexión
    # a la base temporal sin modificar el código de la aplicación.
    real_connect = sqlite3.connect
    monkeypatch.setattr(
        init_db_module,
        "sqlite3",
        SimpleNamespace(connect=lambda _ruta: real_connect(db_path)),
    )
    init_db_module.init_db()

    flask_app.config.update(TESTING=True, DATABASE=str(db_path))
    yield flask_app


@pytest.fixture
def client(app):
    """Cliente HTTP de prueba de Flask (no levanta ningún servidor real)."""
    return app.test_client()


@pytest.fixture
def guardar_pelicula(client):
    """Guarda la película 1 (Dune) con los campos indicados vía POST /edit/1."""

    def _guardar(**campos):
        datos = {
            "nombre": "Dune: Parte Dos",
            "genero": "Ciencia Ficción",
            "director": "Denis Villeneuve",
            "descripcion": "Descripción de prueba",
        }
        datos.update(campos)
        respuesta = client.post("/edit/1", data=datos)
        assert respuesta.status_code == 302, "La edición debería redirigir al índice"
        return datos

    return _guardar
