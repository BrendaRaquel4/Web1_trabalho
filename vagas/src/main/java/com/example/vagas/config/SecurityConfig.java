package com.example.vagas.config;

import com.example.vagas.security.CustomAuthenticationSuccessHandler;
import com.example.vagas.security.UsuarioDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler successHandler;
    private final UsuarioDetailsService usuarioDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler,
                          UsuarioDetailsService usuarioDetailsService,
                          PasswordEncoder passwordEncoder) {
        this.successHandler = successHandler;
        this.usuarioDetailsService = usuarioDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // R4: Listagem de todas as vagas (em aberto) em uma única página (não requer login). 
                .requestMatchers("/", "/login", "/vagas/listagem", "/css/**", "/js/**").permitAll()

                // R1: CRUD de profissionais (requer login de administrador)
                // R2: CRUD de empresas (requer login de administrador)
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // R3: Cadastro de vagas de estágio/trabalho (requer login da empresa) 
                // R6: Listagem de todas as vagas de uma empresa (requer login da empresa) 
                // R8: Análise de candidaturas (requer login da empresa) 
                .requestMatchers("/empresa/**", "/vagas/cadastro", "/vagas/minhas", "/candidaturas/analise/**").hasRole("EMPRESA")

                // R5: Candidatura a vaga de estágio/trabalho (requer login do profissional) 
                // R7: Listagem de todas as candidaturas de um profissional (requer login do profissional) 
                .requestMatchers("/profissional/**", "/candidaturas/nova", "/candidaturas/minhas").hasRole("PROFISSIONAL")
                
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .successHandler(successHandler)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/?logout")
                .permitAll()
            );

        return http.build();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // Configura o UserDetailsService e o PasswordEncoder para a autenticação
        auth.userDetailsService(usuarioDetailsService)
            .passwordEncoder(passwordEncoder);
    }
}