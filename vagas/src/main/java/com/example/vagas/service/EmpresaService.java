package com.example.vagas.service;

import com.example.vagas.model.Empresa;
import com.example.vagas.repository.EmpresaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors; 
import java.util.stream.StreamSupport; 

@Service
public class EmpresaService {

    private final EmpresaRepository empresaRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public EmpresaService(EmpresaRepository empresaRepository, PasswordEncoder passwordEncoder) {
        this.empresaRepository = empresaRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Empresa buscarPorUsuario(String email) {
        return empresaRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("Empresa não encontrada"));
    }

    public Empresa criarEmpresa(Empresa empresa) {
        empresa.setSenha(passwordEncoder.encode(empresa.getSenha()));
        empresa.setRole("ROLE_EMPRESA");
        return empresaRepository.save(empresa);
    }

    public List<Empresa> listarTodasEmpresas() {
        return StreamSupport.stream(empresaRepository.findAll().spliterator(), false)
                            .collect(Collectors.toList());
    }

    public Optional<Empresa> buscarEmpresaPorId(Long id) {
        return empresaRepository.findById(id);
    }

    public Optional<Empresa> atualizarEmpresa(Long id, Empresa empresaAtualizada) {
        return empresaRepository.findById(id).map(empresaExistente -> {
            empresaExistente.setNome(empresaAtualizada.getNome());
            empresaExistente.setDescricao(empresaAtualizada.getDescricao());
            empresaExistente.setCidade(empresaAtualizada.getCidade());

            if (empresaAtualizada.getSenha() != null && !empresaAtualizada.getSenha().isEmpty()) {
                empresaExistente.setSenha(passwordEncoder.encode(empresaAtualizada.getSenha()));
            }
            return empresaRepository.save(empresaExistente);
        });
    }

    public boolean deletarEmpresa(Long id) {
        if (empresaRepository.existsById(id)) {
            empresaRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public Optional<Empresa> buscarEmpresaPorEmail(String email) {
        return empresaRepository.findByEmail(email);
    }
}