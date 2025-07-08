package com.example.vagas.repository;

import com.example.vagas.model.Empresa;
import org.springframework.data.repository.CrudRepository;
import java.util.Optional;

// Alterando a interface para estender CrudRepository
public interface EmpresaRepository extends CrudRepository<Empresa, Long> {
    Optional<Empresa> findByEmail(String email);
}