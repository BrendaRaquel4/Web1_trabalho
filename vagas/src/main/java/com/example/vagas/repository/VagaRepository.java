package com.example.vagas.repository;

import com.example.vagas.model.Empresa;
import com.example.vagas.model.Vaga;
// Importe CrudRepository em vez de PagingAndSortingRepository
import org.springframework.data.repository.CrudRepository; // <-- ALTERADO AQUI
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.List;

// Altere a interface para estender CrudRepository
public interface VagaRepository extends CrudRepository<Vaga, Long> {
    List<Vaga> findByDataLimiteInscricaoAfter(LocalDate hoje);
    List<Vaga> findByCidadeAndDataLimiteInscricaoAfter(String cidade, LocalDate hoje);
    List<Vaga> findByEmpresaOrderByDataLimiteInscricaoDesc(Empresa empresa);
    List<Vaga> findByEmpresaAndDataLimiteInscricaoAfter(Empresa empresa, LocalDate data);

    @Query("SELECT v FROM Vaga v WHERE v.dataLimiteInscricao >= CURRENT_DATE")
    List<Vaga> findAllAbertas();
}