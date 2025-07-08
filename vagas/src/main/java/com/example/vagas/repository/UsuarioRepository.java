package com.example.vagas.repository;

import com.example.vagas.model.Usuario;
import org.springframework.data.repository.CrudRepository;
import java.util.Optional;

public interface UsuarioRepository extends CrudRepository<Usuario, Long> {
    // Este método buscará um Usuario (ou suas subclasses: Empresa ou Profissional) pelo email
    Optional<Usuario> findByEmail(String email);
}