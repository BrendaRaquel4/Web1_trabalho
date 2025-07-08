package com.example.vagas;

import com.example.vagas.model.Administrador; 
import com.example.vagas.repository.UsuarioRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class VagasApplication {

    public static void main(String[] args) {
        SpringApplication.run(VagasApplication.class, args);
    }

    @Bean
    CommandLineRunner initAdmin(UsuarioRepository usuarioRepo, PasswordEncoder encoder) {
        return args -> {
           
            if (usuarioRepo.findByEmail("admin@admin.com").isEmpty()) {
              
                Administrador admin = new Administrador();
                admin.setEmail("admin@admin.com");
                admin.setSenha(encoder.encode("admin"));
                admin.setNome("Administrador do Sistema");
                admin.setRole("ROLE_ADMIN"); // Garante que a role esteja definida
                usuarioRepo.save(admin); 
            }
        };
    }
}