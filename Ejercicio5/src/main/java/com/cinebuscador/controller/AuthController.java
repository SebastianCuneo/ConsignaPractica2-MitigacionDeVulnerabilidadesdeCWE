package com.cinebuscador.controller;

import com.cinebuscador.repository.UserRepository;
import com.cinebuscador.model.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    /**
     * Mitigación CWE-257 / CWE-321 / CWE-327 (almacenamiento inseguro):
     * las contraseñas ya no se cifran con AES/ECB y una clave embebida en el
     * código (reversible por cualquiera con acceso al código). Se guarda un hash
     * BCrypt: unidireccional, con sal aleatoria por usuario y costo ajustable.
     */
    static final int COSTO_BCRYPT = 12;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(COSTO_BCRYPT);

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ==================== LOGIN PAGE ====================
    @GetMapping("/")
    public String loginPage(Model model) {
        model.addAttribute("loginForm", new LoginForm());
        model.addAttribute("registerForm", new RegisterForm());
        return "index";
    }

    // ==================== LOGIN ====================
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, Model model) {
        User user = userRepository.findByUsername(username).orElse(null);

        // Se compara contra el hash; la contraseña almacenada nunca se descifra
        // ni se envía a la vista.
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("loginSuccess", true);
            model.addAttribute("welcomeUser", username);
            return "index";
        }
        model.addAttribute("loginError", "Usuario o contraseña incorrecta");
        addForms(model);
        return "index";
    }

    // ==================== REGISTER ====================
    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password,
                           @RequestParam String confirmPwd, Model model) {
        if (!password.equals(confirmPwd)) {
            model.addAttribute("registerError", "Las contraseñas no coinciden");
            addForms(model);
            return "index";
        }

        if (userRepository.findByUsername(username).isPresent()) {
            model.addAttribute("registerError", "El usuario ya existe");
            addForms(model);
            return "index";
        }


        com.cinebuscador.model.User nuevoUsuario = new com.cinebuscador.model.User();
        nuevoUsuario.setUsername(username);
        nuevoUsuario.setPassword(passwordEncoder.encode(password));
        userRepository.save(nuevoUsuario);

        model.addAttribute("registerSuccess", true);
        model.addAttribute("registeredUsername", username);
        addForms(model);
        return "index";
    }

    // ==================== FORM BEANS ====================
    public static class LoginForm {
        private String username, password;
        public String getUsername() { return username; }
        public void setUsername(String u) { username = u; }
        public String getPassword() { return password; }
        public void setPassword(String p) { password = p; }
    }

    public static class RegisterForm {
        private String username, password, confirmPwd;
        public String getUsername() { return username; }
        public void setUsername(String u) { username = u; }
        public String getPassword() { return password; }
        public void setPassword(String p) { password = p; }
        public String getConfirmPwd() { return confirmPwd; }
        public void setConfirmPwd(String c) { confirmPwd = c; }
    }

    private void addForms(Model model) {
        model.addAttribute("loginForm", new LoginForm());
        model.addAttribute("registerForm", new RegisterForm());
    }
}
