package com.example.vagas.controller;

import com.example.vagas.model.Empresa;
import com.example.vagas.service.EmpresaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
@RequestMapping("/admin/empresas")
public class EmpresaController {

    private final EmpresaService empresaService;

    @Autowired
    public EmpresaController(EmpresaService empresaService) {
        this.empresaService = empresaService;
    }

    // R2: CRUD de empresas
    @GetMapping
    public String listar(Model model) {
        model.addAttribute("empresas", empresaService.listarTodasEmpresas());
        return "empresas/list"; // Retorna o nome da view para listar empresas
    }

    @GetMapping("/form")
    public String form(Model model) {
        model.addAttribute("empresa", new Empresa());
        return "empresas/form"; // Retorna o nome da view do formulário
    }

    // R2: CRUD de empresas - C (Create) / U (Update)
    @PostMapping
    public String salvar(@ModelAttribute Empresa empresa, RedirectAttributes redirectAttributes) {
        try {
            if (empresa.getId() == null) {
                if (empresaService.buscarEmpresaPorEmail(empresa.getEmail()).isPresent()) {
                    redirectAttributes.addFlashAttribute("errorMessage", "Email já cadastrado.");
                    return "redirect:/admin/empresas/form"; // Redireciona de volta ao formulário
                }
                
                empresaService.criarEmpresa(empresa);
                redirectAttributes.addFlashAttribute("successMessage", "Empresa criada com sucesso!");
            } else {
                empresaService.atualizarEmpresa(empresa.getId(), empresa);
                redirectAttributes.addFlashAttribute("successMessage", "Empresa atualizada com sucesso!");
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro ao salvar empresa: " + e.getMessage());
            return "redirect:/admin/empresas"; // Ou para o formulário dependendo do erro
        }
        return "redirect:/admin/empresas"; // Redireciona para a lista após salvar
    }

    // R2: CRUD de empresas - U (Update): (método de edição, carrega dados para o formulário)
    @GetMapping("/editar/{id}") 
    public String editar(@PathVariable Long id, Model model, RedirectAttributes redirectAttributes) {
        Optional<Empresa> empresaOpt = empresaService.buscarEmpresaPorId(id);
        if (empresaOpt.isPresent()) {
            model.addAttribute("empresa", empresaOpt.get());
            return "empresas/form"; // Retorna o formulário preenchido para edição
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada para edição.");
            return "redirect:/admin/empresas"; // Redireciona se não encontrar
        }
    }

    // R2: CRUD de empresas - D (Delete)
    @GetMapping("/excluir/{id}")
    public String excluir(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        if (empresaService.deletarEmpresa(id)) {
            redirectAttributes.addFlashAttribute("successMessage", "Empresa excluída com sucesso!");
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Empresa não encontrada para exclusão.");
        }
        return "redirect:/admin/empresas"; // Redireciona para a lista após exclusão
    }
}