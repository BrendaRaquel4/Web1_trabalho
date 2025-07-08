package com.example.vagas.controller;

import com.example.vagas.model.*;
import com.example.vagas.repository.*;
import com.example.vagas.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@Controller
@RequestMapping("/empresa/vagas")
public class EmpresaVagaController {

    @Autowired
    private VagaRepository vagaRepo;
    
    @Autowired
    private CandidaturaRepository candidaturaRepo;
    
    @Autowired
    private EmpresaRepository empresaRepo;
    
    @Autowired
    private EmailService emailService;

    // R6: Listar vagas da empresa
    @GetMapping
    public String listarVagasEmpresa(Model model, Authentication authentication) {
        Empresa empresa = empresaRepo.findByEmail(authentication.getName()).orElseThrow();
        List<Vaga> vagas = vagaRepo.findByEmpresaOrderByDataLimiteInscricaoDesc(empresa);
        model.addAttribute("vagas", vagas);
        return "empresa/vagas/list";
    }

    // R8: Listar candidaturas para uma vaga
    @GetMapping("/{id}/candidaturas")
    public String listarCandidaturasVaga(@PathVariable Long id, Model model, Authentication authentication) {
        Vaga vaga = vagaRepo.findById(id).orElseThrow();
        
        // Verifica se a vaga pertence à empresa logada
        if(!vaga.getEmpresa().getEmail().equals(authentication.getName())) {
            return "redirect:/empresa/vagas?error=acesso";
        }
        
        List<Candidatura> candidaturas = candidaturaRepo.findByVagaOrderByDataCandidaturaDesc(vaga);
        model.addAttribute("candidaturas", candidaturas);
        model.addAttribute("vaga", vaga);
        return "empresa/candidaturas/list";
    }

    // R8: Marcar entrevista
    @PostMapping("/{vagaId}/candidaturas/{id}/entrevista")
    public String marcarEntrevista(
            @PathVariable Long vagaId,
            @PathVariable Long id,
            @RequestParam String dataEntrevista,
            @RequestParam String linkEntrevista,
            Authentication authentication) {
        
        Candidatura candidatura = candidaturaRepo.findById(id).orElseThrow();
        
        // Verifica se a vaga pertence à empresa logada
        if(!candidatura.getVaga().getEmpresa().getEmail().equals(authentication.getName())) {
            return "redirect:/empresa/vagas?error=acesso";
        }
        
        candidatura.setStatus(StatusCandidatura.ENTREVISTA);
        candidatura.setDataEntrevista(LocalDateTime.parse(dataEntrevista));
        candidatura.setLinkEntrevista(linkEntrevista);
        candidaturaRepo.save(candidatura);
        
        // Envia e-mail de notificação
        emailService.enviarEmailEntrevista(
            candidatura.getProfissional().getEmail(),
            candidatura.getVaga().getDescricao(),
            candidatura.getDataEntrevista(),
            candidatura.getLinkEntrevista()
        );
        
        return "redirect:/empresa/vagas/" + vagaId + "/candidaturas?success";
    }

    // R8: Rejeitar candidatura
    @PostMapping("/{vagaId}/candidaturas/{id}/rejeitar")
    public String rejeitarCandidatura(
            @PathVariable Long vagaId,
            @PathVariable Long id,
            @RequestParam(required = false) String mensagem,
            Authentication authentication) {
        
        Candidatura candidatura = candidaturaRepo.findById(id).orElseThrow();
        
        // Verifica se a vaga pertence à empresa logada
        if(!candidatura.getVaga().getEmpresa().getEmail().equals(authentication.getName())) {
            return "redirect:/empresa/vagas?error=acesso";
        }
        
        candidatura.setStatus(StatusCandidatura.NAO_SELECIONADO);
        candidaturaRepo.save(candidatura);
        
        // Envia e-mail de notificação
        emailService.enviarEmailRejeicao(
            candidatura.getProfissional().getEmail(),
            candidatura.getVaga().getDescricao(),
            mensagem
        );
        
        return "redirect:/empresa/vagas/" + vagaId + "/candidaturas?success";
    }
}