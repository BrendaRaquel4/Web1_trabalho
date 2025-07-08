package com.example.vagas.controller;

import com.example.vagas.model.Candidatura;
import com.example.vagas.model.Empresa;
import com.example.vagas.model.Vaga;
import com.example.vagas.model.StatusCandidatura;
import com.example.vagas.service.CandidaturaService; 
import com.example.vagas.service.EmpresaService;
import com.example.vagas.service.VagaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/vagas")
public class VagaController {

    private final VagaService vagaService;
    private final EmpresaService empresaService;
    private final CandidaturaService candidaturaService; // <--- ADICIONADO: Injetar CandidaturaService

    @Autowired
    public VagaController(VagaService vagaService, EmpresaService empresaService,
                          CandidaturaService candidaturaService) { // <--- ADICIONADO: Parâmetro no construtor
        this.vagaService = vagaService;
        this.empresaService = empresaService;
        this.candidaturaService = candidaturaService; // <--- ADICIONADO: Inicialização
    }

    // R4: Listagem de todas as vagas (não requer login)
    @GetMapping("/listagem")
    public String listarVagas(Model model, @RequestParam(required = false) String cidade) {
        List<Vaga> vagas;
        if (cidade == null || cidade.isEmpty()) {
            vagas = vagaService.listarTodasVagasEmAberto();
        } else {
            vagas = vagaService.listarVagasEmAbertoPorCidade(cidade);
        }
        model.addAttribute("vagas", vagas);
        model.addAttribute("cidadeAtual", cidade);
        return "vagas/listagem";
    }

    // R6: Listagem de vagas de uma empresa (requer login da empresa)
    @GetMapping("/index")
    public String indexEmpresa(Model model, Authentication authentication, RedirectAttributes redirectAttributes) {
        Empresa empresaLogada = empresaService.buscarPorUsuario(authentication.getName());
        if (empresaLogada == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada para o usuário logado.");
            return "redirect:/login";
        }

        List<Vaga> vagas = vagaService.listarVagasPorEmpresa(empresaLogada);
        model.addAttribute("vagas", vagas);
        model.addAttribute("empresa", empresaLogada);
        return "vagas/index";
    }

    // R8: Visualizar Candidaturas de uma Vaga Específica (requer login da empresa)
    // URL: /vagas/{vagaId}/candidaturas
    @GetMapping("/{vagaId}/candidaturas")
    public String listarCandidaturasPorVaga(@PathVariable Long vagaId, Model model,
                                            Authentication authentication, RedirectAttributes redirectAttributes) {
        Empresa empresaLogada = empresaService.buscarPorUsuario(authentication.getName());
        if (empresaLogada == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada para o usuário logado.");
            return "redirect:/login";
        }

        Optional<Vaga> vagaOpt = vagaService.buscarVagaPorId(vagaId);
        if (vagaOpt.isEmpty()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Vaga não encontrada.");
            return "redirect:/vagas/index"; // Redireciona para a lista de vagas da empresa
        }

        Vaga vaga = vagaOpt.get();
        // Validação de segurança: garantir que a empresa logada é a dona da vaga
        if (!vaga.getEmpresa().getId().equals(empresaLogada.getId())) {
            redirectAttributes.addFlashAttribute("errorMessage", "Você não tem permissão para visualizar candidaturas desta vaga.");
            return "redirect:/vagas/index";
        }

        List<Candidatura> candidaturas = candidaturaService.listarCandidaturasPorVaga(vaga);
        model.addAttribute("vaga", vaga); // Adiciona a vaga ao modelo
        model.addAttribute("candidaturas", candidaturas); // Adiciona as candidaturas ao modelo
        return "vagas/candidaturas"; // Nome da view para exibir candidaturas de uma vaga
    }

    // R8: Atualizar Status da Candidatura (requer login da empresa)
    // Este endpoint receberá os dados do formulário para atualização
    // URL: /vagas/{vagaId}/candidaturas/{candidaturaId}/atualizar-status
    @PostMapping("/{vagaId}/candidaturas/{candidaturaId}/atualizar-status")
    public String atualizarStatusCandidatura(@PathVariable Long vagaId, @PathVariable Long candidaturaId,
                                             @RequestParam("novoStatus") String novoStatusStr,
                                             @RequestParam(value = "dataEntrevista", required = false) String dataEntrevistaStr,
                                             @RequestParam(value = "horaEntrevista", required = false) String horaEntrevistaStr,
                                             @RequestParam(value = "linkEntrevista", required = false) String linkEntrevista,
                                             Authentication authentication, RedirectAttributes redirectAttributes) {

        Empresa empresaLogada = empresaService.buscarPorUsuario(authentication.getName());
        if (empresaLogada == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada para o usuário logado.");
            return "redirect:/login";
        }

        // 1. Valida se a vaga existe e pertence à empresa logada (segurança)
        Optional<Vaga> vagaOpt = vagaService.buscarVagaPorId(vagaId);
        if (vagaOpt.isEmpty() || !vagaOpt.get().getEmpresa().getId().equals(empresaLogada.getId())) {
            redirectAttributes.addFlashAttribute("errorMessage", "Acesso negado ou vaga não encontrada.");
            return "redirect:/vagas/index";
        }

        // 2. Valida se a candidatura existe e pertence à vaga correta
        Optional<Candidatura> candidaturaOpt = candidaturaService.buscarCandidaturaPorId(candidaturaId);
        if (candidaturaOpt.isEmpty() || !candidaturaOpt.get().getVaga().getId().equals(vagaId)) {
            redirectAttributes.addFlashAttribute("errorMessage", "Candidatura não encontrada para esta vaga.");
            return "redirect:/vagas/" + vagaId + "/candidaturas";
        }

        try {
            StatusCandidatura novoStatus = StatusCandidatura.valueOf(novoStatusStr); // Converte String para Enum

            LocalDateTime dataHoraEntrevista = null;
            if (novoStatus == StatusCandidatura.ENTREVISTA) {
                if (dataEntrevistaStr == null || dataEntrevistaStr.isEmpty() ||
                    horaEntrevistaStr == null || horaEntrevistaStr.isEmpty()) {
                    throw new IllegalArgumentException("Data e hora da entrevista são obrigatórias para o status ENTREVISTA.");
                }
                // Combina data e hora e parseia
                String fullDateTimeStr = dataEntrevistaStr + "T" + horaEntrevistaStr;
                dataHoraEntrevista = LocalDateTime.parse(fullDateTimeStr); // Assume formato YYYY-MM-DDTHH:MM
            }

            candidaturaService.atualizarStatusCandidatura(candidaturaId, novoStatus, dataHoraEntrevista, linkEntrevista);
            redirectAttributes.addFlashAttribute("successMessage", "Status da candidatura atualizado com sucesso!");

        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro de validação: " + e.getMessage());
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao atualizar status: " + e.getMessage());
        }

        return "redirect:/vagas/" + vagaId + "/candidaturas"; // Redireciona de volta para a lista de candidaturas da vaga
    }

    // R3: Cadastro de vagas (requer login da empresa)
    @PostMapping // Lida com o salvamento de novas vagas e atualizações
    public String salvar(@ModelAttribute Vaga vaga, Authentication authentication, RedirectAttributes redirectAttributes) {
        Empresa empresaLogada = empresaService.buscarPorUsuario(authentication.getName());
        if (empresaLogada == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada. Não foi possível associar a vaga.");
            return "redirect:/vagas/index";
        }

        vaga.setEmpresa(empresaLogada);

        try {
            if (vaga.getId() == null) {
                vagaService.cadastrarVaga(vaga);
                redirectAttributes.addFlashAttribute("successMessage", "Vaga cadastrada com sucesso!");
            } else {
                Optional<Vaga> vagaExistenteOpt = vagaService.buscarVagaPorId(vaga.getId());
                if (vagaExistenteOpt.isEmpty() || !vagaExistenteOpt.get().getEmpresa().getId().equals(empresaLogada.getId())) {
                    redirectAttributes.addFlashAttribute("errorMessage", "Você não tem permissão para editar esta vaga.");
                    return "redirect:/vagas/index";
                }
                vagaService.atualizarVaga(vaga.getId(), vaga);
                redirectAttributes.addFlashAttribute("successMessage", "Vaga atualizada com sucesso!");
            }
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro de validação: " + e.getMessage());
            redirectAttributes.addFlashAttribute("vaga", vaga);
            return "redirect:/vagas/form";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao salvar vaga: " + e.getMessage());
            return "redirect:/vagas/index";
        }
        return "redirect:/vagas/index";
    }

    @GetMapping("/form") // Formulário para cadastrar ou editar vaga
    public String form(Model model) {
        if (!model.containsAttribute("vaga")) {
            model.addAttribute("vaga", new Vaga());
        }
        return "vagas/form";
    }

    @GetMapping("/editar/{id}")
    public String editar(@PathVariable Long id, Model model, Authentication authentication, RedirectAttributes redirectAttributes) {
        Empresa empresaLogada = empresaService.buscarPorUsuario(authentication.getName());
        if (empresaLogada == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada.");
            return "redirect:/login";
        }

        Optional<Vaga> vagaOpt = vagaService.buscarVagaPorId(id);
        if (vagaOpt.isEmpty()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Vaga não encontrada.");
            return "redirect:/vagas/index";
        }

        Vaga vaga = vagaOpt.get();
        if (!vaga.getEmpresa().getId().equals(empresaLogada.getId())) {
            redirectAttributes.addFlashAttribute("errorMessage", "Você não tem permissão para editar esta vaga.");
            return "redirect:/vagas/index";
        }

        model.addAttribute("vaga", vaga);
        return "vagas/form";
    }

    @PostMapping("/excluir/{id}")
    public String excluir(@PathVariable Long id, Authentication authentication, RedirectAttributes redirectAttributes) {
        Empresa empresaLogada = empresaService.buscarPorUsuario(authentication.getName());
        if (empresaLogada == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada.");
            return "redirect:/login";
        }

        Optional<Vaga> vagaOpt = vagaService.buscarVagaPorId(id);
        if (vagaOpt.isEmpty()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Vaga não encontrada para exclusão.");
            return "redirect:/vagas/index";
        }

        Vaga vaga = vagaOpt.get();
        if (!vaga.getEmpresa().getId().equals(empresaLogada.getId())) {
            redirectAttributes.addFlashAttribute("errorMessage", "Você não tem permissão para excluir esta vaga.");
            return "redirect:/vagas/index";
        }

        try {
            if (vagaService.deletarVaga(id)) {
                redirectAttributes.addFlashAttribute("successMessage", "Vaga excluída com sucesso!");
            } else {
                redirectAttributes.addFlashAttribute("errorMessage", "Não foi possível excluir a vaga.");
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao excluir vaga: " + e.getMessage());
        }
        return "redirect:/vagas/index";
    }
}