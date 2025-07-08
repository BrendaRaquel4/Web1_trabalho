package com.example.vagas.service;

import com.example.vagas.model.Candidatura;
import com.example.vagas.model.Profissional;
import com.example.vagas.model.Vaga;
import com.example.vagas.model.StatusCandidatura;
import com.example.vagas.repository.CandidaturaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;


@Service
public class CandidaturaService {

    private final CandidaturaRepository candidaturaRepository;
    private final VagaService vagaService;
    private final ProfissionalService profissionalService;
    private final EmailService emailService;

    @Autowired
    public CandidaturaService(CandidaturaRepository candidaturaRepository,
                              VagaService vagaService,
                              ProfissionalService profissionalService,
                              EmailService emailService) {
        this.candidaturaRepository = candidaturaRepository;
        this.vagaService = vagaService;
        this.profissionalService = profissionalService;
        this.emailService = emailService;
    }

    // R5: Candidatura a vaga
    public Candidatura criarCandidatura(Long vagaId, Profissional profissional, String mensagem, String curriculoNome, byte[] curriculo) {
        Vaga vaga = vagaService.buscarVagaPorId(vagaId)
                               .orElseThrow(() -> new IllegalArgumentException("Vaga não encontrada com o ID: " + vagaId));

        Profissional profissionalExistente = profissionalService.buscarProfissionalPorId(profissional.getId())
                                                               .orElseThrow(() -> new IllegalArgumentException("Profissional não encontrado."));

        if (candidaturaRepository.existsByVagaAndProfissional(vaga, profissionalExistente)) {
            throw new IllegalStateException("Você já se candidatou a esta vaga.");
        }

        if (vaga.getDataLimiteInscricao().isBefore(LocalDate.now())) {
            throw new IllegalStateException("Esta vaga já expirou e não aceita mais candidaturas.");
        }

        Candidatura candidatura = new Candidatura();
        candidatura.setVaga(vaga);
        candidatura.setProfissional(profissionalExistente);
        candidatura.setMensagem(mensagem);
        candidatura.setCurriculoNome(curriculoNome);
        candidatura.setCurriculo(curriculo);
        candidatura.setDataCandidatura(LocalDateTime.now());
        candidatura.setStatus(StatusCandidatura.ABERTO);

        return candidaturaRepository.save(candidatura);
    }

    // R7: Listagem de candidaturas de um profissional
    public List<Candidatura> listarCandidaturasPorProfissional(Profissional profissional) {
        profissionalService.buscarProfissionalPorId(profissional.getId())
                           .orElseThrow(() -> new IllegalArgumentException("Profissional não encontrado."));
        return candidaturaRepository.findByProfissionalOrderByDataCandidaturaDesc(profissional);
    }

    // R8: Listagem de candidaturas para uma vaga específica (para a empresa)
    public List<Candidatura> listarCandidaturasPorVaga(Vaga vaga) {
        vagaService.buscarVagaPorId(vaga.getId())
                   .orElseThrow(() -> new IllegalArgumentException("Vaga não encontrada."));
        return candidaturaRepository.findByVagaOrderByDataCandidaturaDesc(vaga);
    }

    // R8: Atualização do status da candidatura e detalhes da entrevista
    public Optional<Candidatura> atualizarStatusCandidatura(Long candidaturaId, StatusCandidatura novoStatus, LocalDateTime dataEntrevista, String linkEntrevista) {
        return candidaturaRepository.findById(candidaturaId).map(candidaturaExistente -> {
            candidaturaExistente.setStatus(novoStatus);
            candidaturaExistente.setDataEntrevista(dataEntrevista);
            candidaturaExistente.setLinkEntrevista(linkEntrevista);

            Candidatura candidaturaAtualizada = candidaturaRepository.save(candidaturaExistente);

            //  Envio de e-mail (Parte do R8)
            Profissional candidato = candidaturaAtualizada.getProfissional();
            Vaga vaga = candidaturaAtualizada.getVaga();
            String destinatario = candidato.getEmail();

            if (novoStatus == StatusCandidatura.ENTREVISTA) {
                emailService.enviarEmailEntrevista(
                    destinatario,
                    vaga.getDescricao(),
                    dataEntrevista,
                    linkEntrevista
                );
            } else if (novoStatus == StatusCandidatura.NAO_SELECIONADO) {
                emailService.enviarEmailRejeicao(
                    destinatario,
                    vaga.getDescricao(), //
                    "Seu perfil não foi selecionado para esta oportunidade."
                );
            }

            return candidaturaAtualizada;
        });
    }

    // Método para buscar uma candidatura por ID
    public Optional<Candidatura> buscarCandidaturaPorId(Long id) {
        return candidaturaRepository.findById(id);
    }

    // Método para deletar candidatura
    public boolean deletarCandidatura(Long id) {
        if (candidaturaRepository.existsById(id)) {
            candidaturaRepository.deleteById(id);
            return true;
        }
        return false;
    }
}