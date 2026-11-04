"""
Pruebas de integración de la mitigación de Unrestricted File Upload (CWE-434)
del Ejercicio 3.

Vulnerabilidad original: POST /upload/{id} guardaba cualquier archivo con el
nombre original que mandaba el cliente y GET /uploads/{nombre} lo servía
"inline" con el Content-Type deducido de la extensión. Un atacante podía:
  * subir un .html/.svg con JavaScript y obtener XSS almacenado en el dominio,
  * disfrazar contenido arbitrario con extensión de imagen,
  * usar "../" en el nombre para escribir fuera del directorio de uploads.

Mitigación esperada:
  * Lista blanca de extensiones de imagen (png, jpg, jpeg, gif).
  * Validación del contenido real (debe decodificarse como imagen).
  * El archivo se guarda con un nombre aleatorio generado por el servidor.
  * Límite de tamaño con respuesta controlada (sin error 500).
  * Los archivos se sirven con X-Content-Type-Options: nosniff.

Resultado esperado:
  * Branch main        -> las pruebas FALLAN (código vulnerable).
  * Branch practico-2  -> todas las pruebas PASAN (código mitigado).
"""
import re

import pytest
import requests

from conftest import nombre_unico, png_valido

SCRIPT = b"<script>alert(document.domain)</script>"
SVG_CON_SCRIPT = (
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">'
    b"<script>alert(1)</script></svg>"
)


def assert_rechazado(respuesta, nombre, base_url, afiche_actual):
    """Un archivo rechazado: 400, no queda accesible y no se asigna como afiche."""
    assert respuesta.status_code == 400, (
        f"Se esperaba 400 al subir {nombre!r} y se obtuvo {respuesta.status_code}"
    )
    servido = requests.get(f"{base_url}/uploads/{nombre}", timeout=10)
    assert servido.status_code != 200, f"{nombre!r} quedó publicado en /uploads"
    assert afiche_actual() != nombre


# --------------------------------------------------------------------------
# Extensiones peligrosas: deben rechazarse aunque el contenido parezca imagen.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "extension, contenido, content_type",
    [
        pytest.param("html", SCRIPT, "text/html", id="html"),
        pytest.param("htm", SCRIPT, "text/html", id="htm"),
        pytest.param("svg", SVG_CON_SCRIPT, "image/svg+xml", id="svg-con-script"),
        pytest.param("jsp", b'<% out.println("pwned"); %>', "text/plain", id="jsp"),
        pytest.param("js", b"alert(1)", "application/javascript", id="js"),
    ],
)
def test_extension_peligrosa_es_rechazada(base_url, subir, afiche_actual, extension, contenido, content_type):
    nombre = nombre_unico("ataque", extension)

    respuesta = subir(nombre, contenido, content_type)

    assert_rechazado(respuesta, nombre, base_url, afiche_actual)


def test_extension_peligrosa_con_bytes_de_png_es_rechazada(base_url, subir, afiche_actual):
    """El Content-Type y los bytes no alcanzan: la extensión también se valida."""
    nombre = nombre_unico("png-disfrazado", "html")

    respuesta = subir(nombre, png_valido(), "image/png")

    assert_rechazado(respuesta, nombre, base_url, afiche_actual)


# --------------------------------------------------------------------------
# Contenido disfrazado: extensión de imagen pero el contenido no lo es.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "extension, contenido",
    [
        pytest.param("png", SCRIPT, id="html-como-png"),
        pytest.param("jpg", b"<?php system($_GET['c']); ?>", id="php-como-jpg"),
        pytest.param("gif", b"GIF89a<script>alert(1)</script>", id="cabecera-gif-falsa"),
    ],
)
def test_contenido_que_no_es_imagen_es_rechazado(base_url, subir, afiche_actual, extension, contenido):
    nombre = nombre_unico("falsa-imagen", extension)

    respuesta = subir(nombre, contenido, f"image/{extension}")

    assert_rechazado(respuesta, nombre, base_url, afiche_actual)


def test_doble_extension_es_rechazada(base_url, subir, afiche_actual):
    nombre = nombre_unico("afiche.png", "html")

    respuesta = subir(nombre, SCRIPT, "image/png")

    assert_rechazado(respuesta, nombre, base_url, afiche_actual)


# --------------------------------------------------------------------------
# Nombre de archivo controlado por el servidor (evita path traversal y
# sobrescritura de archivos existentes).
# --------------------------------------------------------------------------
def test_path_traversal_en_el_nombre_no_se_usa_como_ruta(subir, afiche_actual):
    nombre = "../../tmp/" + nombre_unico("traversal", "png")

    respuesta = subir(nombre, png_valido(), "image/png")

    guardado = afiche_actual()
    if respuesta.status_code == 302:
        assert guardado is not None
        assert ".." not in guardado and "/" not in guardado and "\\" not in guardado, (
            f"El servidor guardó el archivo usando la ruta del cliente: {guardado!r}"
        )
    else:
        assert respuesta.status_code == 400
        assert guardado is None or ".." not in guardado


def test_imagen_valida_se_guarda_con_nombre_generado_por_el_servidor(base_url, subir, afiche_actual):
    nombre = nombre_unico("afiche-legitimo", "png")

    respuesta = subir(nombre, png_valido(), "image/png")

    assert respuesta.status_code == 302, "Una imagen PNG válida debe aceptarse"
    guardado = afiche_actual()
    assert guardado is not None
    assert guardado != nombre, "El archivo no debe conservar el nombre enviado por el cliente"
    assert re.fullmatch(r"[0-9a-f\-]{32,36}\.png", guardado), (
        f"Nombre inesperado para el archivo guardado: {guardado!r}"
    )


def test_imagen_valida_se_sirve_con_cabeceras_seguras(base_url, subir, afiche_actual):
    subir(nombre_unico("afiche-cabeceras", "png"), png_valido(), "image/png")
    guardado = afiche_actual()
    assert guardado is not None

    servido = requests.get(f"{base_url}/uploads/{guardado}", timeout=10)

    assert servido.status_code == 200
    assert servido.headers.get("Content-Type", "").startswith("image/png")
    assert servido.headers.get("X-Content-Type-Options") == "nosniff"
    assert servido.content == png_valido()


# --------------------------------------------------------------------------
# Límite de tamaño: un archivo enorme se rechaza de forma controlada.
# --------------------------------------------------------------------------
def test_archivo_demasiado_grande_se_rechaza_sin_error_500(subir):
    contenido = png_valido() + b"\x00" * (6 * 1024 * 1024)

    respuesta = subir(nombre_unico("gigante", "png"), contenido, "image/png")

    assert respuesta.status_code in (400, 413), (
        f"Se esperaba 400/413 y se obtuvo {respuesta.status_code}"
    )


# --------------------------------------------------------------------------
# Lectura: no se puede salir del directorio de uploads al descargar.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ruta",
    ["..%2F..%2Fetc%2Fpasswd", "..%252F..%252Fetc%252Fpasswd", "%2e%2e%2fapp.jar"],
)
def test_descarga_con_path_traversal_no_devuelve_archivos(base_url, ruta):
    respuesta = requests.get(f"{base_url}/uploads/{ruta}", timeout=10)

    assert respuesta.status_code != 200
    assert "root:" not in respuesta.text
