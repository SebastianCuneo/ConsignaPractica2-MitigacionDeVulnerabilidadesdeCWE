#!/usr/bin/env bash
# Ejecuta todas las pruebas de seguridad del Práctico 4 y muestra un resumen.
#
# Uso:
#   ./ejecutar_pruebas.sh             # unitarias + integración
#   ./ejecutar_pruebas.sh unitarias   # solo Ejercicios 1, 2 y 5
#   ./ejecutar_pruebas.sh integracion # solo Ejercicios 3 y 4 (levanta Docker)
#
# En la branch main se espera que las pruebas FALLEN (código vulnerable) y en
# la branch practico-2 que PASEN (código mitigado).
set -uo pipefail

RAIZ="$(cd "$(dirname "$0")" && pwd)"
MODO="${1:-todas}"
VENV="$RAIZ/.venv"
MAVEN_IMAGEN="maven:3.9.11-eclipse-temurin-17-noble"
declare -a RESUMEN=()

preparar_python() {
    if [ ! -x "$VENV/bin/pytest" ]; then
        echo ">> Creando entorno virtual en .venv e instalando dependencias..."
        python3 -m venv "$VENV"
        "$VENV/bin/pip" install -q -r "$RAIZ/requirements-test.txt"
    fi
}

registrar() { # $1 = nombre, $2 = código de salida
    # Código 2 = pytest abortó porque la aplicación no responde (problema de
    # ambiente, no de seguridad): se informa como ERROR para no confundirlo
    # con una vulnerabilidad detectada.
    case "$2" in
        0) RESUMEN+=("PASA   $1") ;;
        2) RESUMEN+=("ERROR  $1 (la aplicación no respondió, revisar Docker)") ;;
        *) RESUMEN+=("FALLA  $1") ;;
    esac
}

pytest_en() { # $1 = directorio del ejercicio, $2 = descripción
    echo; echo "=================== $2 ==================="
    (cd "$RAIZ/$1" && "$VENV/bin/pytest" -v)
    registrar "$2" $?
}

junit_ejercicio5() {
    echo; echo "=================== Ejercicio 5 - Almacenamiento inseguro (JUnit) ==================="
    if command -v mvn >/dev/null && mvn -v 2>/dev/null | grep -qE 'Java version: (1[7-9]|[2-9][0-9])'; then
        (cd "$RAIZ/Ejercicio5" && mvn -B test)
    else
        echo ">> No hay Maven con JDK 17+ local: se ejecuta dentro de Docker ($MAVEN_IMAGEN)"
        docker run --rm -v "$RAIZ/Ejercicio5":/app -v "$HOME/.m2":/root/.m2 -w /app \
            "$MAVEN_IMAGEN" mvn -B test
    fi
    registrar "Ejercicio 5 - Almacenamiento inseguro (JUnit)" $?
}

levantar() { # $1 = directorio del ejercicio
    echo ">> Levantando $1 con Docker (build incluido)..."
    (cd "$RAIZ/$1" && docker compose up -d --build --force-recreate)
}

if [ "$MODO" = "todas" ] || [ "$MODO" = "unitarias" ]; then
    preparar_python
    pytest_en Ejercicio1 "Ejercicio 1 - SQL Injection (pytest)"
    pytest_en Ejercicio2 "Ejercicio 2 - XSS (pytest)"
    junit_ejercicio5
fi

if [ "$MODO" = "todas" ] || [ "$MODO" = "integracion" ]; then
    preparar_python
    if ! docker info >/dev/null 2>&1; then
        echo ">> ERROR: Docker no está disponible; no se ejecutan las pruebas de integración."
        RESUMEN+=("ERROR  Ejercicio 3 - File Upload (Docker no disponible)")
        RESUMEN+=("ERROR  Ejercicio 4 - SSTI (Docker no disponible)")
    else
        for ej in "3:File Upload" "4:SSTI"; do
            numero="${ej%%:*}"; nombre="Ejercicio $numero - ${ej#*:} (integración)"
            if levantar "Ejercicio$numero"; then
                pytest_en "Ejercicio$numero" "$nombre"
            else
                RESUMEN+=("ERROR  $nombre (no se pudo levantar el contenedor)")
            fi
        done
    fi
fi

echo; echo "=================== RESUMEN ($(git -C "$RAIZ" branch --show-current)) ==================="
printf '%s\n' "${RESUMEN[@]}"
