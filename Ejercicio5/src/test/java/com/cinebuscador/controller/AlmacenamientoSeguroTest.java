package com.cinebuscador.controller;

import com.cinebuscador.model.User;
import com.cinebuscador.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.ExtendedModelMap;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

/**
 * Pruebas unitarias de la mitigación de Almacenamiento Inseguro de contraseñas
 * (CWE-257 / CWE-321 / CWE-327) del Ejercicio 5.
 *
 * <p><b>Vulnerabilidad original:</b> las contraseñas se guardaban cifradas con
 * AES/ECB usando una clave embebida en el código fuente
 * ({@code EncryptionService}). Con acceso al código (o al JAR) cualquiera puede
 * descifrar todas las contraseñas; además ECB, al no usar sal ni IV, produce el
 * mismo valor para contraseñas iguales. La vista mostraba el valor almacenado.</p>
 *
 * <p><b>Mitigación esperada:</b></p>
 * <ul>
 *   <li>Las contraseñas se guardan con un hash adaptativo y con sal (BCrypt),
 *       que no se puede revertir.</li>
 *   <li>No existe ninguna clave de cifrado embebida en el código.</li>
 *   <li>El valor almacenado nunca se envía a la vista.</li>
 * </ul>
 *
 * <p>Son pruebas unitarias: el {@link UserRepository} se reemplaza por un mock
 * de Mockito respaldado por un {@code Map}, por lo que no se necesita base de
 * datos, Docker ni levantar Spring.</p>
 *
 * <p><b>Resultado esperado:</b> en la branch {@code main} las pruebas FALLAN
 * (código vulnerable); en la branch {@code practico-2} todas PASAN.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Ejercicio 5 - Almacenamiento seguro de contraseñas")
class AlmacenamientoSeguroTest {

    /** Clave que estaba embebida en EncryptionService (versión vulnerable). */
    private static final String CLAVE_FILTRADA = "MySup3rS3cr3tK3y!2024CineBuscadorAES";

    /** Formato de un hash BCrypt: $2a$, $2b$ o $2y$ + costo + 53 caracteres. */
    private static final Pattern FORMATO_BCRYPT =
            Pattern.compile("^\\$2[aby]\\$(\\d{2})\\$[./A-Za-z0-9]{53}$");

    private static final String CONTRASENA = "Sup3r-Secreta!2026";

    @Mock
    private UserRepository userRepository;

    private AuthController controller;

    /** "Base de datos" en memoria detrás del mock del repositorio. */
    private final Map<String, User> usuarios = new HashMap<>();

    @BeforeEach
    void configurarRepositorioEnMemoria() {
        lenient().when(userRepository.findByUsername(anyString()))
                .thenAnswer(inv -> Optional.ofNullable(usuarios.get(inv.<String>getArgument(0))));
        lenient().when(userRepository.save(any(User.class)))
                .thenAnswer(inv -> {
                    User usuario = inv.getArgument(0);
                    usuarios.put(usuario.getUsername(), usuario);
                    return usuario;
                });
        controller = new AuthController(userRepository);
    }

    // ------------------------------------------------------------------
    // Utilidades
    // ------------------------------------------------------------------

    private ExtendedModelMap registrar(String usuario, String contrasena) {
        ExtendedModelMap modelo = new ExtendedModelMap();
        controller.register(usuario, contrasena, contrasena, modelo);
        assertTrue(usuarios.containsKey(usuario), "El usuario debería haberse guardado");
        return modelo;
    }

    private String valorAlmacenado(String usuario) {
        return usuarios.get(usuario).getPassword();
    }

    /** Intenta descifrar como lo haría un atacante con la clave filtrada. */
    private static String descifrarConClaveFiltrada(String almacenado) {
        try {
            byte[] clave = Arrays.copyOf(CLAVE_FILTRADA.getBytes(StandardCharsets.UTF_8), 32);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clave, "AES"));
            byte[] claro = cipher.doFinal(Base64.getDecoder().decode(almacenado));
            return new String(claro, StandardCharsets.UTF_8);
        } catch (Exception noSePudoDescifrar) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Almacenamiento
    // ------------------------------------------------------------------

    @Test
    @DisplayName("La contraseña no se almacena en texto plano")
    void contrasenaNoSeAlmacenaEnTextoPlano() {
        registrar("ana", CONTRASENA);

        String almacenado = valorAlmacenado("ana");
        assertNotEquals(CONTRASENA, almacenado);
        assertFalse(almacenado.contains(CONTRASENA));
    }

    @Test
    @DisplayName("La contraseña no se puede descifrar con la clave que estaba embebida en el código")
    void contrasenaNoEsDescifrableConLaClaveEmbebida() {
        registrar("bruno", CONTRASENA);

        String descifrada = descifrarConClaveFiltrada(valorAlmacenado("bruno"));

        assertNotEquals(CONTRASENA, descifrada,
                "Un atacante con el código fuente puede recuperar la contraseña");
    }

    @Test
    @DisplayName("La contraseña se almacena como hash BCrypt con costo >= 10")
    void contrasenaSeAlmacenaComoHashAdaptativo() {
        registrar("carla", CONTRASENA);

        Matcher matcher = FORMATO_BCRYPT.matcher(valorAlmacenado("carla"));
        assertTrue(matcher.matches(), "El valor almacenado no es un hash BCrypt");
        assertTrue(Integer.parseInt(matcher.group(1)) >= 10, "El factor de costo es demasiado bajo");
    }

    @Test
    @DisplayName("Dos usuarios con la misma contraseña tienen valores almacenados distintos (sal)")
    void mismaContrasenaProduceValoresDistintos() {
        registrar("diego", CONTRASENA);
        registrar("elena", CONTRASENA);

        assertNotEquals(valorAlmacenado("diego"), valorAlmacenado("elena"),
                "Sin sal, un atacante identifica usuarios con la misma contraseña");
    }

    @Test
    @DisplayName("No existe la clase con la clave de cifrado embebida")
    void noExisteServicioConClaveEmbebida() {
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("com.cinebuscador.config.EncryptionService"),
                "EncryptionService (clave AES en el código) no debe reintroducirse");
    }

    // ------------------------------------------------------------------
    // Exposición del valor almacenado en la vista
    // ------------------------------------------------------------------

    @Test
    @DisplayName("El registro no envía la contraseña almacenada a la vista")
    void registroNoExponeLaContrasenaAlmacenada() {
        ExtendedModelMap modelo = registrar("fede", CONTRASENA);

        String almacenado = valorAlmacenado("fede");
        assertFalse(modelo.containsAttribute("encryptedPassword"));
        assertFalse(modelo.containsValue(almacenado));
        assertFalse(modelo.containsValue(CONTRASENA));
    }

    @Test
    @DisplayName("El login exitoso no envía la contraseña almacenada a la vista")
    void loginNoExponeLaContrasenaAlmacenada() {
        registrar("gabi", CONTRASENA);
        ExtendedModelMap modelo = new ExtendedModelMap();

        controller.login("gabi", CONTRASENA, modelo);

        assertEquals(Boolean.TRUE, modelo.getAttribute("loginSuccess"));
        assertFalse(modelo.containsAttribute("encryptedPassword"));
        assertFalse(modelo.containsValue(valorAlmacenado("gabi")));
    }

    // ------------------------------------------------------------------
    // Controles funcionales: la autenticación sigue funcionando
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Login con la contraseña correcta es exitoso")
    void loginConContrasenaCorrecta() {
        registrar("hugo", CONTRASENA);
        ExtendedModelMap modelo = new ExtendedModelMap();

        controller.login("hugo", CONTRASENA, modelo);

        assertEquals(Boolean.TRUE, modelo.getAttribute("loginSuccess"));
        assertNull(modelo.getAttribute("loginError"));
    }

    @Test
    @DisplayName("Login con la contraseña incorrecta es rechazado")
    void loginConContrasenaIncorrecta() {
        registrar("ines", CONTRASENA);
        ExtendedModelMap modelo = new ExtendedModelMap();

        controller.login("ines", "otra-contrasena", modelo);

        assertNull(modelo.getAttribute("loginSuccess"));
        assertNotNull(modelo.getAttribute("loginError"));
    }

    @Test
    @DisplayName("Login de un usuario inexistente es rechazado")
    void loginDeUsuarioInexistente() {
        ExtendedModelMap modelo = new ExtendedModelMap();

        controller.login("nadie", CONTRASENA, modelo);

        assertNull(modelo.getAttribute("loginSuccess"));
        assertNotNull(modelo.getAttribute("loginError"));
    }
}
