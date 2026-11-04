"""
Configuración de las pruebas de integración del Ejercicio 3 (File Upload).

Estas pruebas se ejecutan contra la aplicación real levantada con Docker
(docker compose up), enviando peticiones HTTP como lo haría un atacante.

Variable de entorno:
  EJ3_BASE_URL  URL base de la aplicación (por defecto http://localhost:8083).
"""
import os
import re
import struct
import time
import uuid
import zlib

import pytest
import requests

BASE_URL = os.environ.get("EJ3_BASE_URL", "http://localhost:8083").rstrip("/")

# Película sobre la que se suben los afiches de prueba (Inception en data.sql).
PELICULA_ID = 1


def png_valido(ancho=1, alto=1):
    """Genera los bytes de un PNG real (RGB) sin depender de librerías externas."""

    def chunk(tipo, datos):
        return (
            struct.pack(">I", len(datos))
            + tipo
            + datos
            + struct.pack(">I", zlib.crc32(tipo + datos) & 0xFFFFFFFF)
        )

    cabecera = struct.pack(">IIBBBBB", ancho, alto, 8, 2, 0, 0, 0)
    filas = b"".join(b"\x00" + b"\xff\x00\x00" * ancho for _ in range(alto))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", cabecera)
        + chunk(b"IDAT", zlib.compress(filas))
        + chunk(b"IEND", b"")
    )


def nombre_unico(base, extension):
    """Nombre de archivo único por ejecución (evita choques con subidas previas)."""
    return f"{base}-{uuid.uuid4().hex[:8]}.{extension}"


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
        f"La aplicación del Ejercicio 3 no responde en {BASE_URL}. "
        "Levantala con: cd Ejercicio3 && docker compose up -d --build",
        returncode=2,
    )


@pytest.fixture
def subir(base_url):
    """Sube un archivo como afiche de la película de prueba."""

    def _subir(nombre, contenido, content_type="application/octet-stream"):
        return requests.post(
            f"{base_url}/upload/{PELICULA_ID}",
            files={"afiche": (nombre, contenido, content_type)},
            allow_redirects=False,
            timeout=15,
        )

    return _subir


@pytest.fixture
def afiche_actual(base_url):
    """Devuelve el nombre de archivo con el que quedó guardado el afiche."""

    def _afiche_actual():
        pagina = requests.get(f"{base_url}/upload/{PELICULA_ID}", timeout=10).text
        coincidencia = re.search(r'<img src="/uploads/([^"]+)" alt="Afiche actual"', pagina)
        return requests.utils.unquote(coincidencia.group(1)) if coincidencia else None

    return _afiche_actual
