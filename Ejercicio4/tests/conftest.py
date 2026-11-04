"""
Configuración de las pruebas de integración del Ejercicio 4 (SSTI / SpEL
Injection).

Estas pruebas se ejecutan contra la aplicación real levantada con Docker
(docker compose up), enviando búsquedas maliciosas por HTTP.

Variable de entorno:
  EJ4_BASE_URL  URL base de la aplicación (por defecto http://localhost:8084).
"""
import os
import time

import pytest
import requests

BASE_URL = os.environ.get("EJ4_BASE_URL", "http://localhost:8084").rstrip("/")


@pytest.fixture(scope="session")
def base_url():
    """Espera a que la aplicación responda; si no está levantada, aborta."""
    limite = time.time() + 60
    while time.time() < limite:
        try:
            if requests.get(f"{BASE_URL}/", timeout=3).status_code < 500:
                return BASE_URL
        except requests.ConnectionError:
            pass
        time.sleep(2)
    pytest.exit(
        f"La aplicación del Ejercicio 4 no responde en {BASE_URL}. "
        "Levantala con: cd Ejercicio4 && docker compose up -d --build",
        returncode=2,
    )


@pytest.fixture
def buscar(base_url):
    """Realiza una búsqueda (GET /?buscar=...) y devuelve la respuesta."""

    def _buscar(texto):
        return requests.get(f"{base_url}/", params={"buscar": texto}, timeout=15)

    return _buscar
