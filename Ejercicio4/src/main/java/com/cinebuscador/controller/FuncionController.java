package com.cinebuscador.controller;

import com.cinebuscador.model.Funcion;
import com.cinebuscador.repository.FuncionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@Controller
public class FuncionController {

    /** Largo máximo aceptado para el término de búsqueda. */
    static final int LARGO_MAXIMO_BUSQUEDA = 100;

    private final FuncionRepository funcionRepo;

    @Autowired
    public FuncionController(FuncionRepository funcionRepo) {
        this.funcionRepo = funcionRepo;
    }

    /**
     * Mitigación CWE-917 (Expression Language Injection / SSTI):
     * el texto ingresado por el usuario se trata SIEMPRE como un literal.
     * Antes se evaluaba como expresión SpEL con un StandardEvaluationContext,
     * lo que permitía ejecutar código arbitrario en el servidor
     * (por ejemplo T(java.lang.Runtime).getRuntime().exec(...)).
     * Ya no existe ninguna evaluación de expresiones sobre datos del usuario.
     */
    @GetMapping("/")
    public String search(@RequestParam(required = false) String buscar, Model model) {

        String termino = buscar == null ? "" : buscar.strip();
        if (termino.length() > LARGO_MAXIMO_BUSQUEDA) {
            termino = termino.substring(0, LARGO_MAXIMO_BUSQUEDA);
        }
        model.addAttribute("query", termino);

        if (termino.isEmpty()) {
            model.addAttribute("resultados", funcionRepo.findAll());
            model.addAttribute("mensaje", "Mostrando todas las funciones.");
            return "index";
        }

        String terminoNormalizado = termino.toLowerCase(Locale.ROOT);
        List<Funcion> resultados = funcionRepo.findAll().stream()
            .filter(f -> f.getNombreFuncion() != null &&
                         f.getNombreFuncion().toLowerCase(Locale.ROOT).contains(terminoNormalizado))
            .collect(Collectors.toList());

        model.addAttribute("resultados", resultados);
        // th:text escapa el valor al renderizarlo: el término se muestra tal cual.
        model.addAttribute("mensaje", "Resultados buscando por: " + termino);
        return "index";
    }
}
