"""
Pruebas unitarias de la mitigación de SQL Injection (CWE-89) del Ejercicio 1.

Vulnerabilidad original: buscar_funciones() armaba la consulta concatenando el
texto de búsqueda (`buscar`) y el sentido de orden (`sentido`) directamente en
el SQL, por lo que un atacante podía alterar la consulta.

Mitigación esperada:
  * El texto de búsqueda viaja como parámetro (`?`) y nunca forma parte del SQL.
  * El sentido de orden y la columna se validan contra una lista blanca.

Resultado esperado:
  * Branch main        -> las pruebas de inyección FALLAN (código vulnerable).
  * Branch practico-2  -> todas las pruebas PASAN (código mitigado).
"""
import sqlite3

import pytest

from app import buscar_funciones


# --------------------------------------------------------------------------
# Control: la búsqueda legítima tiene que seguir funcionando con la mitigación.
# --------------------------------------------------------------------------
def test_busqueda_legitima_devuelve_las_funciones_de_la_pelicula(app_context):
    resultados = buscar_funciones("Dune")

    assert len(resultados) == 3
    assert all(fila["pelicula"] == "Dune: Parte Dos" for fila in resultados)


def test_ordenamiento_legitimo_descendente_por_fecha(app_context):
    resultados = buscar_funciones("Dune", "fecha", "DESC")
    fechas = [fila["fecha_hora"] for fila in resultados]

    assert fechas == sorted(fechas, reverse=True)


# --------------------------------------------------------------------------
# Inyección en el parámetro `buscar` (cláusula WHERE).
# Ninguna película se llama literalmente como estos payloads, así que una
# consulta parametrizada debe devolver 0 filas y nunca lanzar un error SQL.
# --------------------------------------------------------------------------
PAYLOADS_WHERE = [
    pytest.param("' OR '1'='1", id="tautologia"),
    pytest.param("zzz' OR 1=1 --", id="tautologia-con-comentario"),
    pytest.param("zzz' UNION SELECT name, sql, 1 FROM sqlite_master --", id="union-sqlite_master"),
    pytest.param("zzz' UNION SELECT nombre, director, id FROM peliculas --", id="union-otra-tabla"),
]


@pytest.mark.parametrize("payload", PAYLOADS_WHERE)
def test_inyeccion_en_busqueda_se_trata_como_texto_literal(app_context, payload):
    resultados = buscar_funciones(payload)

    assert resultados == [], (
        f"El payload {payload!r} alteró la consulta y devolvió {len(resultados)} filas"
    )


def test_union_no_expone_el_esquema_de_la_base(app_context):
    payload = "zzz' UNION SELECT name, sql, 1 FROM sqlite_master --"
    resultados = buscar_funciones(payload)

    peliculas = {fila["pelicula"] for fila in resultados}
    assert "peliculas" not in peliculas
    assert "funciones" not in peliculas


@pytest.mark.parametrize("payload", ["'", "Dune'", "\" OR \"\"=\"", "%' --"])
def test_caracteres_especiales_no_rompen_la_consulta(app_context, payload):
    """Una comilla suelta no debe provocar un error de sintaxis SQL
    (error-based SQLi / fuga de información en mensajes de error)."""
    try:
        buscar_funciones(payload)
    except sqlite3.Error as error:  # pragma: no cover - solo ocurre si es vulnerable
        pytest.fail(f"El payload {payload!r} rompió la consulta SQL: {error}")


# --------------------------------------------------------------------------
# Inyección en el parámetro `sentido` (cláusula ORDER BY).
# --------------------------------------------------------------------------
def test_inyeccion_en_sentido_no_modifica_la_consulta(app_context):
    """`ASC LIMIT 1` recortaría el resultado si se concatena en el SQL."""
    resultados = buscar_funciones("Dune", "nombre", "ASC LIMIT 1")

    assert len(resultados) == 3


def test_sentido_con_sentencia_apilada_no_se_ejecuta(app, app_context):
    payload = "ASC; DROP TABLE funciones; --"
    try:
        buscar_funciones("Dune", "nombre", payload)
    except sqlite3.Error as error:  # pragma: no cover - solo ocurre si es vulnerable
        pytest.fail(f"El sentido {payload!r} se interpretó como SQL: {error}")

    conexion = sqlite3.connect(app.config["DATABASE"])
    tablas = {fila[0] for fila in conexion.execute("SELECT name FROM sqlite_master")}
    conexion.close()
    assert "funciones" in tablas


@pytest.mark.parametrize(
    "sentido",
    ["ASC, (SELECT 1)", "DESC LIMIT 0", "ASC UNION SELECT 1,2,3"],
)
def test_sentido_invalido_se_ignora(app_context, sentido):
    resultados = buscar_funciones("Dune", "nombre", sentido)

    assert len(resultados) == 3


# --------------------------------------------------------------------------
# Verificación a través del endpoint HTTP (cliente de prueba de Flask).
# --------------------------------------------------------------------------
def test_endpoint_no_devuelve_todas_las_funciones_con_tautologia(client):
    respuesta = client.get("/", query_string={"buscar": "' OR '1'='1"})

    assert respuesta.status_code == 200
    assert "No se encontraron funciones" in respuesta.get_data(as_text=True)


def test_endpoint_responde_200_ante_comilla_suelta(client):
    respuesta = client.get("/", query_string={"buscar": "'"})

    assert respuesta.status_code == 200


def test_endpoint_inyeccion_en_sentido(client):
    respuesta = client.get(
        "/", query_string={"buscar": "Dune", "sentido": "ASC LIMIT 1"}
    )

    assert respuesta.status_code == 200
    assert "3 función(es) encontrada(s)" in respuesta.get_data(as_text=True)
