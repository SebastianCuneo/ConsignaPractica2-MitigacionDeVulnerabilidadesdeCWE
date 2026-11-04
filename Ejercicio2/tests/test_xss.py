"""
Pruebas unitarias de la mitigación de Cross Site Scripting (CWE-79) del
Ejercicio 2.

Vulnerabilidad original (XSS almacenado): la descripción de la película se
guarda tal cual en la base y la plantilla edit.html la mostraba con el filtro
`| safe`, que desactiva el escapado automático de Jinja2. Cualquier HTML o
JavaScript guardado en la descripción se ejecutaba en el navegador de quien
abriera la página de edición.

Mitigación esperada:
  * Toda salida de datos del usuario se escapa (sin `| safe`).
  * Las respuestas incluyen una Content-Security-Policy que bloquea scripts
    inline (defensa en profundidad).

Resultado esperado:
  * Branch main        -> las pruebas de XSS FALLAN (código vulnerable).
  * Branch practico-2  -> todas las pruebas PASAN (código mitigado).
"""
import pytest
from flask import render_template
from markupsafe import escape

PAYLOADS_XSS = [
    pytest.param("<script>alert('XSS')</script>", id="script"),
    pytest.param("<img src=x onerror=alert(document.cookie)>", id="img-onerror"),
    pytest.param("<svg onload=alert(1)>", id="svg-onload"),
    pytest.param("<iframe src=javascript:alert(1)></iframe>", id="iframe-javascript"),
    pytest.param("</textarea><script>alert(1)</script>", id="cierre-textarea"),
]


def html(respuesta):
    return respuesta.get_data(as_text=True)


# --------------------------------------------------------------------------
# Prueba unitaria de la plantilla: se renderiza edit.html de forma aislada,
# sin base de datos ni HTTP, con una película cuya descripción es maliciosa.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_plantilla_edit_escapa_la_descripcion(app, payload):
    pelicula = {
        "id": 1,
        "nombre": "Dune",
        "genero": "Ciencia Ficción",
        "director": "Denis Villeneuve",
        "descripcion": payload,
    }
    with app.test_request_context():
        salida = render_template("edit.html", pelicula=pelicula)

    assert payload not in salida, "La descripción se insertó sin escapar en el HTML"
    assert str(escape(payload)) in salida


# --------------------------------------------------------------------------
# XSS almacenado: se guarda el payload con POST y se verifica cada página
# donde la descripción se muestra.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_xss_almacenado_en_descripcion_no_se_ejecuta_en_edicion(client, guardar_pelicula, payload):
    guardar_pelicula(descripcion=payload)

    pagina = html(client.get("/edit/1"))

    assert payload not in pagina
    assert str(escape(payload)) in pagina


@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_xss_almacenado_en_descripcion_no_se_ejecuta_en_listado(client, guardar_pelicula, payload):
    guardar_pelicula(descripcion=payload)

    pagina = html(client.get("/", query_string={"buscar": "Dune"}))

    assert payload not in pagina


def test_xss_almacenado_en_nombre_no_escapa_del_atributo_value(client, guardar_pelicula):
    payload = '"><script>alert(1)</script>'
    guardar_pelicula(nombre=payload)

    pagina = html(client.get("/edit/1"))

    assert payload not in pagina
    assert "<script>alert(1)</script>" not in pagina


# --------------------------------------------------------------------------
# XSS reflejado: el término de búsqueda se muestra en la página de resultados.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("payload", PAYLOADS_XSS)
def test_xss_reflejado_en_busqueda_se_escapa(client, payload):
    pagina = html(client.get("/", query_string={"buscar": payload}))

    assert payload not in pagina


# --------------------------------------------------------------------------
# Defensa en profundidad: Content-Security-Policy.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("ruta", ["/", "/edit/1"])
def test_respuestas_incluyen_content_security_policy(client, ruta):
    respuesta = client.get(ruta)
    csp = respuesta.headers.get("Content-Security-Policy", "")

    assert "script-src" in csp or "default-src" in csp, "Falta la cabecera CSP"
    assert "'unsafe-inline'" not in csp.split("script-src")[-1].split(";")[0], (
        "La CSP no debe permitir scripts inline"
    )


def test_respuestas_incluyen_x_content_type_options(client):
    respuesta = client.get("/")

    assert respuesta.headers.get("X-Content-Type-Options") == "nosniff"


# --------------------------------------------------------------------------
# Control: la edición legítima sigue funcionando y conserva el texto.
# --------------------------------------------------------------------------
def test_edicion_legitima_conserva_el_texto(client, guardar_pelicula):
    guardar_pelicula(descripcion="Paul se une a los Fremen & busca venganza")

    pagina = html(client.get("/edit/1"))

    assert "Paul se une a los Fremen &amp; busca venganza" in pagina
