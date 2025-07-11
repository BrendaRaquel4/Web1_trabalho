package com.example.vagas.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.springframework.security.core.*;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {

        if (authentication.getAuthorities().stream()
                .anyMatch(role -> role.getAuthority().equals("ROLE_ADMIN"))) {
            response.sendRedirect("/admin/index");
        } else if (authentication.getAuthorities().stream()
                .anyMatch(role -> role.getAuthority().equals("ROLE_EMPRESA"))) {
            response.sendRedirect("/vagas/index");
        } else if (authentication.getAuthorities().stream()
                .anyMatch(role -> role.getAuthority().equals("ROLE_PROFISSIONAL"))) {
            response.sendRedirect("/vagas/listagem");
        } else {
            response.sendRedirect("/");
        }
    }
}