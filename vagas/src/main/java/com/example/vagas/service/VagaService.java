package com.example.vagas.service;

import com.example.vagas.model.Empresa;
import com.example.vagas.model.Vaga;
import com.example.vagas.repository.VagaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class VagaService {

    private final VagaRepository vagaRepository;
    private final EmpresaService empresaService; // busca a empresa associada à vaga

    @Autowired
    public VagaService(VagaRepository vagaRepository, EmpresaService empresaService) {
        this.vagaRepository = vagaRepository;
        this.empresaService = empresaService;
    }

    // Método para cadastrar uma nova vaga (R3)
    public Vaga cadastrarVaga(Vaga vaga) {
        if (vaga.getDataLimiteInscricao() != null && vaga.getDataLimiteInscricao().isBefore(LocalDate.now())) {
            throw new IllegalArgumentException("A data limite de inscrição não pode ser no passado.");
        }
        
        return vagaRepository.save(vaga);
    }

    // Métodos para R4: Listagem de todas as vagas (em aberto)
    public List<Vaga> listarTodasVagasEmAberto() {
        return vagaRepository.findAllAbertas();
    }

    public List<Vaga> listarVagasEmAbertoPorCidade(String cidade) {
        if (cidade == null || cidade.trim().isEmpty()) {
            return listarTodasVagasEmAberto(); 
        }
       
        return vagaRepository.findByCidadeAndDataLimiteInscricaoAfter(cidade, LocalDate.now().minusDays(1)); // ajustado para incluir vagas ativas hoje
    }

    // Método para R6: Listagem de todas as vagas de uma empresa
    public List<Vaga> listarVagasPorEmpresa(Empresa empresa) { 
        return vagaRepository.findByEmpresaOrderByDataLimiteInscricaoDesc(empresa);
    }

    public Optional<Vaga> buscarVagaPorId(Long id) {
        return vagaRepository.findById(id);
    }

    public Optional<Vaga> atualizarVaga(Long id, Vaga vagaAtualizada) {
        return vagaRepository.findById(id).map(vagaExistente -> {
            vagaExistente.setDescricao(vagaAtualizada.getDescricao());
            vagaExistente.setRemuneracao(vagaAtualizada.getRemuneracao());
            vagaExistente.setDataLimiteInscricao(vagaAtualizada.getDataLimiteInscricao());
            vagaExistente.setCidade(vagaAtualizada.getCidade());

            if (vagaExistente.getDataLimiteInscricao() != null && vagaExistente.getDataLimiteInscricao().isBefore(LocalDate.now())) {
                throw new IllegalArgumentException("A data limite de inscrição não pode ser no passado para uma vaga ativa.");
            }

            return vagaRepository.save(vagaExistente);
        });
    }

    public boolean deletarVaga(Long id) {
        if (vagaRepository.existsById(id)) {
            vagaRepository.deleteById(id);
            return true;
        }
        return false;
    }

    // Método auxiliar para buscar uma empresa pelo ID
    public Optional<Empresa> buscarEmpresaPorId(Long empresaId) {
        return empresaService.buscarEmpresaPorId(empresaId);
    }
}