package com.example.vagas.controller;

import com.example.vagas.model.Profissional;
import com.example.vagas.service.ProfissionalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
@RequestMapping("/admin/profissionais")
public class ProfissionalController {

    private final ProfissionalService profissionalService;

    @Autowired
    public ProfissionalController(ProfissionalService profissionalService) {
        this.profissionalService = profissionalService;
    }

    @GetMapping
    public String listar(Model model) {
        model.addAttribute("profissionais", profissionalService.listarTodosProfissionais());
        return "profissionais/list"; // Retorna o nome da view para listar profissionais
    }

    @GetMapping("/form")
    public String form(Model model) {
        model.addAttribute("profissional", new Profissional());
        return "profissionais/form"; // Retorna o nome da view do formulário
    }

    @PostMapping
    public String salvar(@ModelAttribute Profissional profissional, RedirectAttributes redirectAttributes) {
        try {
            if (profissional.getId() == null) {
                if (profissionalService.buscarProfissionalPorEmail(profissional.getEmail()).isPresent()) {
                    redirectAttributes.addFlashAttribute("errorMessage", "Email já cadastrado.");
                    return "redirect:/admin/profissionais/form"; // Redireciona de volta ao formulário
                }
                profissionalService.criarProfissional(profissional);
                redirectAttributes.addFlashAttribute("successMessage", "Profissional criado com sucesso!");
            } else {
                profissionalService.atualizarProfissional(profissional.getId(), profissional);
                redirectAttributes.addFlashAttribute("successMessage", "Profissional atualizado com sucesso!");
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao salvar profissional: " + e.getMessage());
            return "redirect:/admin/profissionais";
        }
        return "redirect:/admin/profissionais"; // Redireciona para a lista após salvar
    }

    @GetMapping("/editar/{id}")
    public String editar(@PathVariable Long id, Model model, RedirectAttributes redirectAttributes) {
        Optional<Profissional> profissionalOpt = profissionalService.buscarProfissionalPorId(id);
        if (profissionalOpt.isPresent()) {
            model.addAttribute("profissional", profissionalOpt.get());
            return "profissionais/form"; // Retorna o formulário preenchido para edição
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Profissional não encontrado para edição.");
            return "redirect:/admin/profissionais"; // Redireciona se não encontrar
        }
    }

    @GetMapping("/excluir/{id}")
    public String excluir(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        if (profissionalService.deletarProfissional(id)) {
            redirectAttributes.addFlashAttribute("successMessage", "Profissional excluído com sucesso!");
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Profissional não encontrado para exclusão.");
        }
        return "redirect:/admin/profissionais"; // Redireciona para a lista após exclusão
    }
}