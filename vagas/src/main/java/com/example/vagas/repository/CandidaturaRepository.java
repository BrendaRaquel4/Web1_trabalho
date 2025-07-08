package com.example.vagas.repository;

import com.example.vagas.model.*;
import org.springframework.data.repository.CrudRepository;
import java.util.List;

// Alterando a interface para estender CrudRepository
public interface CandidaturaRepository extends CrudRepository<Candidatura, Long> {
    List<Candidatura> findByProfissionalOrderByDataCandidaturaDesc(Profissional profissional);
    List<Candidatura> findByVagaOrderByDataCandidaturaDesc(Vaga vaga);
    boolean existsByVagaAndProfissional(Vaga vaga, Profissional profissional);
}