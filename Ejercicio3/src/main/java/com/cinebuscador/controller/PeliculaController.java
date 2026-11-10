package com.cinebuscador.controller;

import com.cinebuscador.model.Pelicula;
import com.cinebuscador.repository.PeliculaRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.MediaType;
import org.springframework.core.io.UrlResource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Controller
public class PeliculaController {

    /** Nombres que genera el servidor: UUID + extensión de imagen permitida. */
    private static final Pattern NOMBRE_GUARDADO =
        Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.(png|jpg|gif)$");

    private final PeliculaRepository peliculaRepo;

    @Value("${app.upload-dir}")
    private String uploadDir;

    public PeliculaController(PeliculaRepository peliculaRepo) {
        this.peliculaRepo = peliculaRepo;
    }

    @GetMapping("/")
    public String index(@RequestParam(required = false) String buscar,
                        @RequestParam(required = false, defaultValue = "nombre") String ordenarPor,
                        @RequestParam(required = false, defaultValue = "ASC") String sentido,
                        Model model) {

        if (buscar != null && !buscar.isBlank()) {
            List<Object[]> resultadosRaw;
            if ("DESC".equalsIgnoreCase(sentido)) {
                resultadosRaw = peliculaRepo.searchWithFuncionesDesc(buscar, ordenarPor);
            } else {
                resultadosRaw = peliculaRepo.searchWithFunciones(buscar, ordenarPor);
            }

            // Wrap Object[] in Maps for cleaner Thymeleaf access
            List<Map<String, Object>> resultados = new java.util.ArrayList<>();
            for (Object[] row : resultadosRaw) {
                Map<String, Object> map = new HashMap<>();
                map.put("id",        row[0]);
                map.put("nombre",    row[1]);
                map.put("fechaHora", row[2]);
                map.put("disponibles", row[3]);
                map.put("descripcion", row[4]);
                map.put("afichePath", row[5]);
                resultados.add(map);
            }
            model.addAttribute("resultados", resultados);
        }

        model.addAttribute("query", buscar != null ? buscar : "");
        model.addAttribute("sort_by", ordenarPor);
        model.addAttribute("sort_dir", sentido);
        return "index";
    }

    @GetMapping("/upload/{id}")
    public String uploadForm(@PathVariable Integer id, Model model) {
        Pelicula pelicula = peliculaRepo.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Pelicula no encontrada"));
        model.addAttribute("pelicula", pelicula);
        return "upload";
    }

    @PostMapping("/upload/{id}")
    public String uploadFile(@PathVariable Integer id,
                             @RequestParam("afiche") MultipartFile archivo,
                             Model model,
                             HttpServletResponse response) throws IOException {
        Pelicula pelicula = peliculaRepo.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Pelicula no encontrada"));

        // Mitigación CWE-434: extensión en lista blanca + contenido de imagen real.
        AficheValidator.Resultado validacion = AficheValidator.validar(archivo);
        if (!validacion.esValido()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            model.addAttribute("pelicula", pelicula);
            model.addAttribute("error", validacion.error());
            return "upload";
        }

        // El nombre lo genera el servidor: el nombre del cliente (que puede traer
        // "../" o extensiones engañosas) nunca se usa como ruta.
        String filename = UUID.randomUUID() + "." + validacion.extension();
        Path directorio = directorioUploads();
        Files.createDirectories(directorio);
        Path destino = directorio.resolve(filename).normalize();
        if (!destino.getParent().equals(directorio)) {
            throw new IllegalStateException("Ruta de destino invalida");
        }
        Files.write(destino, archivo.getBytes(), StandardOpenOption.CREATE_NEW);

        pelicula.setAfichePath(filename);
        peliculaRepo.save(pelicula);

        return "redirect:/";
    }

    @GetMapping("/uploads/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> serveFile(@PathVariable String filename) throws IOException {
        // Solo se sirven nombres con el formato que genera el servidor.
        Matcher nombre = NOMBRE_GUARDADO.matcher(filename);
        if (!nombre.matches()) {
            return ResponseEntity.notFound().build();
        }
        Path directorio = directorioUploads();
        Path filePath = directorio.resolve(filename).normalize();
        if (!filePath.getParent().equals(directorio) || !Files.isRegularFile(filePath)) {
            return ResponseEntity.notFound().build();
        }

        MediaType mediaType = "png".equals(nombre.group(1)) ? MediaType.IMAGE_PNG
                : "gif".equals(nombre.group(1)) ? MediaType.IMAGE_GIF
                : MediaType.IMAGE_JPEG;

        return ResponseEntity.ok()
            .contentType(mediaType)
            .header("X-Content-Type-Options", "nosniff")
            .header("Content-Security-Policy", "default-src 'none'; sandbox")
            .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + filename + "\"")
            .body(new UrlResource(filePath.toUri()));
    }

    private Path directorioUploads() {
        return Paths.get(uploadDir).toAbsolutePath().normalize();
    }

}
