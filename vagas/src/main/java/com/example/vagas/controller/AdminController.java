package com.example.vagas.controller; // Confirme seu pacote

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin")
public class AdminController {

    // Este método serve a página principal do dashboard do administrador.
    // Ele não precisa de injeções de serviço se apenas redireciona para a view.
    @GetMapping("/index") // Mapeia para http://localhost:8080/admin/index
    public String showAdminDashboard() {
        return "admin/index"; // Retorna o nome do template Thymeleaf
                             // (src/main/resources/templates/admin/index.html)
    }

}