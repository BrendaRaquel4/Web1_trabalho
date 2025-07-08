package com.example.vagas.controller;

import com.example.vagas.model.Candidatura;
import com.example.vagas.model.Profissional;
import com.example.vagas.model.Empresa;
import com.example.vagas.model.Vaga;

import com.example.vagas.service.CandidaturaService;
import com.example.vagas.service.ProfissionalService;
import com.example.vagas.service.VagaService;
import com.example.vagas.service.EmpresaService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/profissional/candidaturas")
public class CandidaturaController {

    private final CandidaturaService candidaturaService;
    private final VagaService vagaService;
    private final ProfissionalService profissionalService;
    private final EmpresaService empresaService;

    @Autowired
    public CandidaturaController(CandidaturaService candidaturaService,
                                 VagaService vagaService,
                                 ProfissionalService profissionalService,
                                 EmpresaService empresaService) {
        this.candidaturaService = candidaturaService;
        this.vagaService = vagaService;
        this.profissionalService = profissionalService;
        this.empresaService = empresaService;
    }

    // R5: Processar candidatura (requer login do profissional)
    @PostMapping("/nova")
    public String processarCandidatura(
            @RequestParam("vagaId") Long vagaId,
            @RequestParam("curriculo") MultipartFile curriculo,
            @RequestParam(value = "mensagem", required = false) String mensagem,
            Authentication authentication,
            RedirectAttributes redirectAttributes) throws IOException {

        try {
            Profissional profissional = profissionalService.buscarProfissionalPorEmail(authentication.getName())
                    .orElseThrow(() -> new IllegalArgumentException("Profissional logado não encontrado."));

            candidaturaService.criarCandidatura(
                    vagaId,
                    profissional,
                    mensagem,
                    curriculo.getOriginalFilename(),
                    curriculo.getBytes()
            );

            redirectAttributes.addFlashAttribute("successMessage", "Candidatura enviada com sucesso!");
        } catch (IllegalArgumentException | IllegalStateException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/vagas/listagem";
        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao ler arquivo de currículo.");
            return "redirect:/vagas/listagem";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro inesperado ao enviar candidatura: " + e.getMessage());
            return "redirect:/vagas/listagem";
        }

        return "redirect:/profissional/candidaturas";
    }

    // R7: Listar candidaturas do profissional (requer login do profissional)
    @GetMapping
    public String listarCandidaturas(Model model, Authentication authentication, RedirectAttributes redirectAttributes) {
        try {
            Profissional profissional = profissionalService.buscarProfissionalPorEmail(authentication.getName())
                    .orElseThrow(() -> new IllegalArgumentException("Profissional logado não encontrado."));

            List<Candidatura> candidaturas = candidaturaService.listarCandidaturasPorProfissional(profissional);
            model.addAttribute("candidaturas", candidaturas);
            return "profissional/candidaturas";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao carregar suas candidaturas: " + e.getMessage());
            return "redirect:/";
        }
    }

    // Download do currículo (requer login - profissional dono OU empresa da vaga)
    @GetMapping("/{id}/curriculo")
    @ResponseBody
    public ResponseEntity<byte[]> baixarCurriculo(@PathVariable Long id, Authentication authentication) {
        try {
            Optional<Candidatura> candidaturaOpt = candidaturaService.buscarCandidaturaPorId(id);
            if (candidaturaOpt.isEmpty()) {
                throw new IllegalArgumentException("Candidatura não encontrada.");
            }

            Candidatura candidatura = candidaturaOpt.get();
            String userEmail = authentication.getName();

            Profissional profissionalLogado = profissionalService.buscarProfissionalPorEmail(userEmail).orElse(null);

            
            Vaga vaga = vagaService.buscarVagaPorId(candidatura.getVaga().getId())
                                   .orElseThrow(() -> new IllegalArgumentException("Vaga associada à candidatura não encontrada."));


            if (profissionalLogado != null && profissionalLogado.getId().equals(candidatura.getProfissional().getId())) {
            
            } else {
                Empresa empresaLogada = empresaService.buscarPorUsuario(userEmail);

                if (empresaLogada != null && vaga.getEmpresa().getId().equals(empresaLogada.getId())) {
                } else {
                    throw new SecurityException("Acesso negado. Você não tem permissão para baixar este currículo.");
                }
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            String fileExtension = "";
            int dotIndex = candidatura.getCurriculoNome().lastIndexOf('.');
            if (dotIndex > 0 && dotIndex < candidatura.getCurriculoNome().length() - 1) {
                fileExtension = candidatura.getCurriculoNome().substring(dotIndex + 1).toLowerCase();
            }

            if (fileExtension.equals("pdf")) {
                headers.setContentType(MediaType.APPLICATION_PDF);
            } else if (fileExtension.equals("doc") || fileExtension.equals("docx")) {
                headers.setContentType(MediaType.valueOf("application/msword"));
                if (fileExtension.equals("docx")) {
                    headers.setContentType(MediaType.valueOf("application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
                }
            } else {
                headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            }

            headers.setContentDispositionFormData("attachment", candidatura.getCurriculoNome());
            headers.setContentLength(candidatura.getCurriculo().length);

            return new ResponseEntity<>(candidatura.getCurriculo(), headers, HttpStatus.OK);

        } catch (IllegalArgumentException | SecurityException e) {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            return new ResponseEntity<>(e.getMessage().getBytes(), headers, HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            return new ResponseEntity<>("Erro interno ao baixar o currículo.".getBytes(), headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}