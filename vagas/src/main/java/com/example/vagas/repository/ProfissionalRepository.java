package com.example.vagas.repository;

import com.example.vagas.model.Profissional;
import org.springframework.data.repository.CrudRepository;
import java.util.Optional;

// Alterando a interface para estender CrudRepository
public interface ProfissionalRepository extends CrudRepository<Profissional, Long> {
    Optional<Profissional> findByEmail(String email);
}