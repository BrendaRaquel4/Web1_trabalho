package com.example.vagas.service;

import com.example.vagas.model.Profissional;
import com.example.vagas.repository.ProfissionalRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors; 
import java.util.stream.StreamSupport; 

@Service
public class ProfissionalService {

    private final ProfissionalRepository profissionalRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ProfissionalService(ProfissionalRepository profissionalRepository, PasswordEncoder passwordEncoder) {
        this.profissionalRepository = profissionalRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Profissional criarProfissional(Profissional profissional) {
        profissional.setSenha(passwordEncoder.encode(profissional.getSenha()));
        // Define a role para o profissional (ROLE_PROFISSIONAL)
        profissional.setRole("ROLE_PROFISSIONAL");
        return profissionalRepository.save(profissional);
    }

    public List<Profissional> listarTodosProfissionais() {
        return StreamSupport.stream(profissionalRepository.findAll().spliterator(), false)
                            .collect(Collectors.toList());
    }

    public Optional<Profissional> buscarProfissionalPorId(Long id) {
        return profissionalRepository.findById(id);
    }

    public Optional<Profissional> atualizarProfissional(Long id, Profissional profissionalAtualizado) {
        return profissionalRepository.findById(id).map(profissionalExistente -> {
            profissionalExistente.setNome(profissionalAtualizado.getNome());
            
            if (profissionalAtualizado.getSenha() != null && !profissionalAtualizado.getSenha().isEmpty()) {
                profissionalExistente.setSenha(passwordEncoder.encode(profissionalAtualizado.getSenha()));
            }
            profissionalExistente.setTelefone(profissionalAtualizado.getTelefone());
            profissionalExistente.setSexo(profissionalAtualizado.getSexo());
            profissionalExistente.setDataNascimento(profissionalAtualizado.getDataNascimento());
            return profissionalRepository.save(profissionalExistente);
        });
    }

    public boolean deletarProfissional(Long id) {
        if (profissionalRepository.existsById(id)) {
            profissionalRepository.deleteById(id);
            return true;
        }
        return false;
    }

    // Método para buscar profissional por email
    public Optional<Profissional> buscarProfissionalPorEmail(String email) {
        return profissionalRepository.findByEmail(email);
    }
}