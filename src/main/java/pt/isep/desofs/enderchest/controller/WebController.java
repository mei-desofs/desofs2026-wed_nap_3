package pt.isep.desofs.enderchest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    @GetMapping("/login")
    public String login() {
        // Retorna o nome do ficheiro HTML em 'src/main/resources/templates/'
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        // Esta página só será acessível após o login
        return "dashboard";
    }
    
    @GetMapping("/register")
    public String register() {
        return "register";
    }

    // DEV_TEAM: O formulário de upload estaria no 'dashboard.html' ou noutra página
    // e faria um POST para o endpoint /api/files/upload do FileController.
}