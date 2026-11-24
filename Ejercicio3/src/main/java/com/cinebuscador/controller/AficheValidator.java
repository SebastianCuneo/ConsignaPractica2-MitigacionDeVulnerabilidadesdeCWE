package com.cinebuscador.controller;

import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

/**
 * Validación de los afiches subidos (mitigación CWE-434).
 *
 * <ul>
 *   <li>Lista blanca de extensiones de imagen.</li>
 *   <li>El contenido debe decodificarse como una imagen del mismo formato que la
 *       extensión (no alcanza con el Content-Type ni con los primeros bytes).</li>
 *   <li>Límites de tamaño en bytes y en píxeles (evita "image bombs").</li>
 * </ul>
 */
final class AficheValidator {

    /** Extensión permitida -> formato que debe reportar ImageIO. */
    static final Map<String, String> EXTENSIONES_PERMITIDAS = Map.of(
            "png", "png",
            "jpg", "jpeg",
            "jpeg", "jpeg",
            "gif", "gif");

    static final long TAMANIO_MAXIMO_BYTES = 2L * 1024 * 1024;
    private static final int DIMENSION_MAXIMA = 5000;

    private AficheValidator() {}

    /** Resultado de la validación: la extensión normalizada o un mensaje de error. */
    record Resultado(String extension, String error) {
        boolean esValido() { return error == null; }
    }

    static Resultado validar(MultipartFile archivo) throws IOException {
        if (archivo == null || archivo.isEmpty()) {
            return error("Seleccioná un archivo de imagen.");
        }
        if (archivo.getSize() > TAMANIO_MAXIMO_BYTES) {
            return error("El archivo supera el tamaño máximo de 2 MB.");
        }

        String extension = extension(archivo.getOriginalFilename());
        String formatoEsperado = EXTENSIONES_PERMITIDAS.get(extension);
        if (formatoEsperado == null) {
            return error("Solo se permiten imágenes PNG, JPG o GIF.");
        }
        if (!esImagenDelFormato(archivo.getBytes(), formatoEsperado)) {
            return error("El archivo no es una imagen válida.");
        }
        // Se guarda siempre con la extensión canónica del formato validado.
        return new Resultado("jpeg".equals(formatoEsperado) ? "jpg" : formatoEsperado, null);
    }

    private static Resultado error(String mensaje) {
        return new Resultado(null, mensaje);
    }

    private static String extension(String nombreOriginal) {
        if (nombreOriginal == null) {
            return "";
        }
        int punto = nombreOriginal.lastIndexOf('.');
        return punto < 0 ? "" : nombreOriginal.substring(punto + 1).toLowerCase(Locale.ROOT);
    }

    private static boolean esImagenDelFormato(byte[] contenido, String formatoEsperado) {
        try (ImageInputStream entrada = ImageIO.createImageInputStream(new ByteArrayInputStream(contenido))) {
            Iterator<ImageReader> lectores = ImageIO.getImageReaders(entrada);
            if (!lectores.hasNext()) {
                return false;
            }
            ImageReader lector = lectores.next();
            try {
                if (!formatoEsperado.equalsIgnoreCase(lector.getFormatName())) {
                    return false;
                }
                lector.setInput(entrada, true, true);
                int ancho = lector.getWidth(0);
                int alto = lector.getHeight(0);
                if (ancho <= 0 || alto <= 0 || ancho > DIMENSION_MAXIMA || alto > DIMENSION_MAXIMA) {
                    return false;
                }
                return lector.read(0) != null;
            } finally {
                lector.dispose();
            }
        } catch (IOException | RuntimeException contenidoInvalido) {
            return false;
        }
    }
}
