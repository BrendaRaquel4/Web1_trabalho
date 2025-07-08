package com.example.vagas.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.Table;
import java.time.LocalDate;


@Entity
@Table(name = "profissional") // Mapeia para a tabela 'profissional'
@PrimaryKeyJoinColumn(name = "id") // Chave primária de Profissional também é FK para Usuario
public class Profissional extends Usuario { // Profissional agora estende apenas Usuario

    @Column(unique = true, nullable = false)
    private String cpf;

    private String telefone;
    private String sexo;
    private LocalDate dataNascimento;

    public Profissional() {
        super(); // Chama construtor padrão da superclasse
        this.setRole("ROLE_PROFISSIONAL"); // Define a role específica para Profissionais
    }

    public Profissional(String email, String senha, String nome, String cpf, String telefone, String sexo, LocalDate dataNascimento) {
        // Chama construtor parametrizado da superclasse, passando a role
        super(email, senha, nome, "ROLE_PROFISSIONAL");
        this.cpf = cpf;
        this.telefone = telefone;
        this.sexo = sexo;
        this.dataNascimento = dataNascimento;
    }

    // Getters e Setters específicos de Profissional
    public String getCpf() { 
        return cpf; 
    }
    public void setCpf(String cpf) { 
        this.cpf = cpf; 
    }
    public String getTelefone() { 
        return telefone; 
    }
    public void setTelefone(String telefone) { 
        this.telefone = telefone; 
    }
    public String getSexo() { 
        return sexo; 
    }
    public void setSexo(String sexo) { 
        this.sexo = sexo; 
    }
    public LocalDate getDataNascimento() { 
        return dataNascimento; 
    }
    public void setDataNascimento(LocalDate dataNascimento) { 
        this.dataNascimento = dataNascimento; 
    }

    // Os métodos de UserDetails (getAuthorities, getPassword, getUsername, etc.)
    // são agora herdados diretamente de Usuario. Não precisam ser sobrescritos aqui,
    // a menos que haja um comportamento muito específico para Profissional.
    // O getAuthorities em Usuario já retornará "ROLE_PROFISSIONAL" porque o construtor o define.
}