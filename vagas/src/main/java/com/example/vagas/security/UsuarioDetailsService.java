package com.example.vagas.security;

import com.example.vagas.model.Usuario; // Importa a classe Usuario
import com.example.vagas.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UsuarioDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Busca um usuário pelo email no repositório genérico de Usuario
        Optional<Usuario> usuarioOpt = usuarioRepo.findByEmail(email);

        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            // a classe Usuario agora implementa UserDetails e tem o campo 'role',
            // podemos retornar a própria instância de Usuario.
            // Spring Security usará os métodos getUsername(), getPassword(), getAuthorities()
            // que foram implementados na classe Usuario.
            return usuario;
        }

        throw new UsernameNotFoundException("Usuário não encontrado: " + email);
    }
}