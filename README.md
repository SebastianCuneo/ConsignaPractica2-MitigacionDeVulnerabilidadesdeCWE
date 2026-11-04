# Mitigación de Vulnerabilidades CWE — Pruebas de seguridad

Repositorio de los prácticos de **Desarrollo de Software Seguro** (UCU).

| Branch        | Contenido                                                     | Resultado esperado de las pruebas |
|---------------|---------------------------------------------------------------|-----------------------------------|
| `main`        | Aplicaciones originales **vulnerables** + pruebas de seguridad | ❌ Las pruebas **fallan**          |
| `practico-2`  | Aplicaciones **mitigadas** (Práctico 2) + las mismas pruebas   | ✅ Las pruebas **pasan**           |

Las pruebas son idénticas en las dos branches. Su objetivo es detectar que una
vulnerabilidad ya mitigada **no se reintroduzca** en una versión posterior: si
alguien vuelve a escribir código vulnerable, las pruebas fallan.

| Ejercicio | Vulnerabilidad                         | Tipo de prueba | Tecnología        | Archivo de pruebas |
|-----------|----------------------------------------|----------------|-------------------|--------------------|
| 1         | SQL Injection (CWE-89)                 | Unitaria       | Pytest            | [Ejercicio1/tests/test_sqli.py](Ejercicio1/tests/test_sqli.py) |
| 2         | Cross Site Scripting (CWE-79)          | Unitaria       | Pytest            | [Ejercicio2/tests/test_xss.py](Ejercicio2/tests/test_xss.py) |
| 3         | Unrestricted File Upload (CWE-434)     | Integración    | Pytest + requests | [Ejercicio3/tests/test_file_upload.py](Ejercicio3/tests/test_file_upload.py) |
| 4         | SSTI / SpEL Injection (CWE-917)        | Integración    | Pytest + requests | [Ejercicio4/tests/test_ssti.py](Ejercicio4/tests/test_ssti.py) |
| 5         | Almacenamiento inseguro (CWE-257/321)  | Unitaria       | JUnit 5 + Mockito | [Ejercicio5/src/test/java/.../AlmacenamientoSeguroTest.java](Ejercicio5/src/test/java/com/cinebuscador/controller/AlmacenamientoSeguroTest.java) |

---

## Requisitos

- **Python 3.10+** (Ejercicios 1 a 4).
- **Docker** con Docker Compose (Ejercicios 3 y 4; también sirve para el 5 si no hay JDK 17).
- **JDK 17+ y Maven 3.9+** para el Ejercicio 5 (opcional: se puede usar Docker).

Preparar el entorno de Python una sola vez, desde la raíz del repositorio:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-test.txt
```

## Ejecutar todo con un comando

```bash
./ejecutar_pruebas.sh               # unitarias + integración
./ejecutar_pruebas.sh unitarias     # solo Ejercicios 1, 2 y 5
./ejecutar_pruebas.sh integracion   # solo Ejercicios 3 y 4 (levanta los contenedores)
```

El script crea el `.venv` si no existe, levanta los contenedores necesarios
y al final muestra un resumen `PASA` / `FALLA` por ejercicio.

Para comparar las dos branches:

```bash
git checkout main        && ./ejecutar_pruebas.sh   # todas FALLAN
git checkout practico-2  && ./ejecutar_pruebas.sh   # todas PASAN
```

---

## Pruebas unitarias

No requieren ningún ambiente levantado: se ejecutan desde la línea de comandos.

### Ejercicio 1 — SQL Injection (Pytest)

```bash
cd Ejercicio1
pytest -v
```

Cada test crea una base SQLite temporal con los datos de `init_db.py` y llama
directamente a `buscar_funciones()` (y al endpoint `/` con el cliente de
prueba de Flask). Se verifica que:

- payloads en `buscar` (tautología `' OR '1'='1`, comentarios `--`, `UNION SELECT`
  sobre `sqlite_master` u otras tablas) se traten como texto literal y no devuelvan filas;
- una comilla suelta no rompa la consulta (sin errores SQL);
- valores maliciosos en `sentido` (`ASC LIMIT 1`, `ASC; DROP TABLE ...`) se ignoren
  y no alteren ni dañen la base;
- la búsqueda y el ordenamiento legítimos sigan funcionando.

### Ejercicio 2 — Cross Site Scripting (Pytest)

```bash
cd Ejercicio2
pytest -v
```

Se usa el cliente de prueba de Flask con una base SQLite temporal. Se verifica que:

- la plantilla `edit.html`, renderizada de forma aislada, escape la descripción;
- un payload guardado en la descripción (XSS almacenado: `<script>`, `<img onerror>`,
  `<svg onload>`, `<iframe src=javascript:>`, cierre de `</textarea>`) se muestre
  escapado en la página de edición y en el listado;
- un payload en el nombre no escape del atributo `value`;
- el término de búsqueda reflejado se escape (XSS reflejado);
- las respuestas incluyan `Content-Security-Policy` sin `'unsafe-inline'` para
  scripts y `X-Content-Type-Options: nosniff`.

### Ejercicio 5 — Almacenamiento inseguro (JUnit)

Con JDK 17+ y Maven instalados:

```bash
cd Ejercicio5
mvn test
```

Sin JDK 17 local, con Docker:

```bash
cd Ejercicio5
docker run --rm -v "$PWD":/app -v "$HOME/.m2":/root/.m2 -w /app \
  maven:3.9.11-eclipse-temurin-17-noble mvn -B test
```

`AuthController` se prueba con un `UserRepository` simulado (Mockito), sin
Spring ni base de datos. Se verifica que:

- la contraseña no se guarde en texto plano;
- no se pueda descifrar con la clave AES que estaba embebida en el código;
- se guarde como hash **BCrypt** con costo ≥ 10;
- dos usuarios con la misma contraseña tengan valores distintos (uso de sal);
- la clase `EncryptionService` (clave embebida) no exista;
- ni el registro ni el login envíen el valor almacenado a la vista;
- el login siga funcionando con la contraseña correcta y rechace la incorrecta.

---

## Pruebas de integración

Se ejecutan contra las aplicaciones reales dockerizadas, enviando peticiones
HTTP como lo haría un atacante. Cada ejercicio usa un puerto distinto para
poder levantarlos a la vez.

| Ejercicio | URL por defecto         | Variable para cambiarla |
|-----------|-------------------------|-------------------------|
| 3         | `http://localhost:8083` | `EJ3_BASE_URL`          |
| 4         | `http://localhost:8084` | `EJ4_BASE_URL`          |

> Al cambiar de branch, reconstruí los contenedores (`--build --force-recreate`)
> para que la imagen corresponda al código de esa branch.

### Ejercicio 3 — File Upload

```bash
cd Ejercicio3
docker compose up -d --build --force-recreate
pytest -v
docker compose down
```

Se verifica que:

- se rechacen (HTTP 400) archivos con extensiones peligrosas (`.html`, `.htm`, `.svg`,
  `.jsp`, `.js`) y dobles extensiones (`afiche.png.html`), y que no queden publicados en `/uploads`;
- se rechacen archivos con extensión de imagen cuyo contenido no es una imagen real;
- el nombre enviado por el cliente (incluido `../`) no se use como ruta: el servidor
  guarda la imagen con un nombre aleatorio (UUID);
- una imagen válida se sirva con `Content-Type: image/png` y `X-Content-Type-Options: nosniff`;
- un archivo demasiado grande se rechace sin error 500;
- no se pueda descargar archivos fuera del directorio de uploads.

### Ejercicio 4 — Server Side Template Injection (SpEL)

```bash
cd Ejercicio4
docker compose up -d --build --force-recreate
pytest -v
docker compose down
```

Se envían búsquedas con expresiones SpEL que, si se evaluaran, producen un
resultado reconocible: aritmética (`1337*1337`), llamadas a métodos, clases
estáticas (`T(java.lang.System)`), ejecución de comandos
(`T(java.lang.Runtime).getRuntime().exec('id')`, `ProcessBuilder`), acceso al
sistema de archivos y a variables de entorno. Se verifica que:

- ninguna expresión se evalúe (el resultado no aparece en la respuesta);
- el texto ingresado se muestre literalmente como término de búsqueda;
- entradas mal formadas (`'`, `)(`, `${7*7}`, `#{7*7}`...) no provoquen errores 500;
- la búsqueda legítima (por ejemplo `Inception`) siga funcionando.

---

## Ejecutar las aplicaciones

| Ejercicio | Comando                                              | URL                     |
|-----------|------------------------------------------------------|-------------------------|
| 1         | `cd Ejercicio1 && docker compose up -d --build`      | `http://localhost:5000` |
| 2         | `cd Ejercicio2 && docker compose up -d --build`      | `http://localhost:5000` |
| 3         | `cd Ejercicio3 && docker compose up -d --build`      | `http://localhost:8083` |
| 4         | `cd Ejercicio4 && docker compose up -d --build`      | `http://localhost:8084` |
| 5         | `cd Ejercicio5 && docker compose up -d --build`      | `http://localhost:8080` |
