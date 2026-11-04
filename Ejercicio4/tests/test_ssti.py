"""
Pruebas de integración de la mitigación de Server Side Template Injection /
Expression Language Injection (CWE-917 / CWE-1336) del Ejercicio 4.

Vulnerabilidad original: el texto del buscador se evaluaba como una expresión
SpEL (Spring Expression Language) con un StandardEvaluationContext, que permite
acceder a cualquier clase Java. Escribir `T(java.lang.Runtime).getRuntime()
.exec('...')` en el buscador ejecutaba comandos en el servidor (RCE).

Mitigación esperada:
  * La entrada del usuario NUNCA se evalúa como expresión: se usa como texto
    literal para filtrar las funciones.
  * Entradas inválidas no provocan errores 500 ni filtran trazas.

Cada payload produce un resultado reconocible si se evalúa (un número, un
texto concatenado, un objeto Process...). Las pruebas verifican que ese
resultado NO aparezca y que el texto original se muestre tal cual.

Resultado esperado:
  * Branch main        -> las pruebas FALLAN (código vulnerable).
  * Branch practico-2  -> todas las pruebas PASAN (código mitigado).
"""
import html

import pytest

# (payload, texto que aparecería en la respuesta si el payload se evaluara)
PAYLOADS_EVALUABLES = [
    pytest.param("1337*1337", "1787569", id="aritmetica"),
    pytest.param("'ss'.concat('ti-ejecutado')", "ssti-ejecutado", id="metodo-string"),
    pytest.param("T(java.lang.Math).abs(-424242)", "buscando por: 424242", id="clase-estatica"),
    pytest.param("T(java.lang.System).getProperty('user.dir')", "buscando por: /app", id="propiedades-sistema"),
    pytest.param("T(java.lang.Runtime).getRuntime().exec('id')", "Process[pid=", id="rce-runtime-exec"),
    pytest.param("new java.lang.ProcessBuilder('id').start()", "Process[pid=", id="rce-processbuilder"),
    pytest.param("new java.io.File('/').list()", "[Ljava.lang.String;", id="listar-filesystem"),
    pytest.param("#system.getenv()", "PATH=", id="variable-system"),
]


def mensaje_de_busqueda(respuesta):
    """Texto plano de la respuesta (con entidades HTML decodificadas)."""
    return html.unescape(respuesta.text)


# --------------------------------------------------------------------------
# Control: la búsqueda legítima sigue funcionando.
# --------------------------------------------------------------------------
def test_busqueda_legitima_devuelve_funciones(buscar):
    """En la versión vulnerable incluso esta búsqueda falla (HTTP 500): el texto
    `Inception` se evalúa como una referencia SpEL a una propiedad inexistente."""
    respuesta = buscar("Inception")

    assert respuesta.status_code == 200
    assert "Resultados buscando por: Inception" in mensaje_de_busqueda(respuesta)
    assert respuesta.text.count('class="funcion-card"') >= 2


def test_busqueda_vacia_muestra_todas_las_funciones(buscar):
    respuesta = buscar("")

    assert respuesta.status_code == 200
    assert "Mostrando todas las funciones." in respuesta.text


# --------------------------------------------------------------------------
# Inyección de expresiones: nunca deben evaluarse.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("payload, evidencia", PAYLOADS_EVALUABLES)
def test_expresion_no_se_evalua(buscar, payload, evidencia):
    respuesta = buscar(payload)

    assert respuesta.status_code == 200, (
        f"El payload {payload!r} provocó un error {respuesta.status_code}"
    )
    assert evidencia not in mensaje_de_busqueda(respuesta), (
        f"El payload {payload!r} fue evaluado en el servidor"
    )


@pytest.mark.parametrize("payload, _evidencia", PAYLOADS_EVALUABLES)
def test_expresion_se_muestra_como_texto_literal(buscar, payload, _evidencia):
    respuesta = buscar(payload)

    assert f"buscando por: {payload}" in mensaje_de_busqueda(respuesta)


def test_aritmetica_no_filtra_resultados_por_el_valor_calculado(buscar):
    """'Incep'+'tion' evaluado daría 'Inception' y devolvería sus funciones."""
    respuesta = buscar("'Incep'+'tion'")

    assert respuesta.status_code == 200
    assert 'class="funcion-card"' not in respuesta.text


# --------------------------------------------------------------------------
# Entradas mal formadas: respuesta controlada, sin traza de error.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("payload", ["'", ")(", "T(", "#{7*7}", "${7*7}", "*{7*7}"])
def test_entrada_mal_formada_no_provoca_error(buscar, payload):
    respuesta = buscar(payload)

    assert respuesta.status_code == 200, (
        f"El payload {payload!r} provocó un error {respuesta.status_code}"
    )
    assert "SpelParseException" not in respuesta.text
    assert "Whitelabel Error Page" not in respuesta.text
    assert "49" not in mensaje_de_busqueda(respuesta).split("buscando por:")[-1][:20]
