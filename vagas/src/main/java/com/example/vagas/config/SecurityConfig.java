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
                // Permite acesso a páginas públicas sem autenticação
                // R4: Listagem de todas as vagas (em aberto) em uma única página (não requer login). 
                // Também permite acesso a recursos estáticos (CSS, JS) e páginas de login.
                .requestMatchers("/", "/login", "/vagas/listagem", "/css/**", "/js/**").permitAll()

                // R1: CRUD de profissionais (requer login de administrador) [cite: 7]
                // R2: CRUD de empresas (requer login de administrador) [cite: 8]
                // Assumindo que URLs de admin começam com /admin/
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // R3: Cadastro de vagas de estágio/trabalho (requer login da empresa) 
                // R6: Listagem de todas as vagas de uma empresa (requer login da empresa) 
                // R8: Análise de candidaturas (requer login da empresa) 
                // Assumindo que URLs para empresa começam com /empresa/ ou específicas de vaga/candidatura para empresa
                .requestMatchers("/empresa/**", "/vagas/cadastro", "/vagas/minhas", "/candidaturas/analise/**").hasRole("EMPRESA")

                // R5: Candidatura a vaga de estágio/trabalho (requer login do profissional) 
                // R7: Listagem de todas as candidaturas de um profissional (requer login do profissional) 
                // Assumindo que URLs para profissional começam com /profissional/ ou específicas de candidatura para profissional
                // Sua regra original usava "PROFISSIONAIS", ajustei para "PROFISSIONAL" para consistência com as roles definidas.
                .requestMatchers("/profissional/**", "/candidaturas/nova", "/candidaturas/minhas").hasRole("PROFISSIONAL")
                
                // Qualquer outra requisição requer autenticação
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .successHandler(successHandler) // Redirecionamento customizado após login bem-sucedido
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/?logout") // URL para onde redirecionar após logout
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