"""
Fixtures compartidas por las pruebas unitarias del Ejercicio 1 (SQL Injection).

Las pruebas no necesitan Docker ni un servidor levantado: cada test recibe una
base SQLite nueva en un directorio temporal, cargada con los mismos datos que
usa la aplicación (init_db.py). Así los tests son independientes entre sí y no
modifican el archivo cine.db real.
"""
import sqlite3
from types import SimpleNamespace

import pytest

import init_db as init_db_module
from app import app as flask_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Aplicación Flask apuntando a una base de datos temporal recién creada."""
    db_path = tmp_path / "cine_test.db"

    # init_db() siempre escribe en Ejercicio1/cine.db; se redirige su conexión
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
def app_context(app):
    """Contexto de aplicación necesario para llamar a buscar_funciones()."""
    with app.app_context():
        yield


@pytest.fixture
def client(app):
    """Cliente HTTP de prueba de Flask (no levanta ningún servidor real)."""
    return app.test_client()
