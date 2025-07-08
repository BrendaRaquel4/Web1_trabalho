package com.example.vagas.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrimaryKeyJoinColumn;
import jakarta.persistence.Table;


@Entity
@Table(name = "empresa") // Mapeia para a tabela 'empresa'
@PrimaryKeyJoinColumn(name = "id") // Chave primária de Empresa também é FK para Usuario
public class Empresa extends Usuario { // Empresa agora estende apenas Usuario, que já implementa UserDetails

    @Column(unique = true, nullable = false)
    private String cnpj;

    private String descricao;
    private String cidade;

    public Empresa() {
        super(); // Chama construtor padrão da superclasse
        this.setRole("ROLE_EMPRESA"); // Define a role específica para Empresas
    }

    public Empresa(String email, String senha, String nome, String cnpj, String descricao, String cidade) {
        // Chama construtor parametrizado da superclasse, passando a role
        super(email, senha, nome, "ROLE_EMPRESA");
        this.cnpj = cnpj;
        this.descricao = descricao;
        this.cidade = cidade;
    }

    // Getters e Setters específicos de Empresa
    public String getCnpj() { 
        return cnpj; 
    }
    public void setCnpj(String cnpj) { 
        this.cnpj = cnpj; 
    }
    public String getDescricao() { 
        return descricao; 
    }
    public void setDescricao(String descricao) { 
        this.descricao = descricao; 
    }
    public String getCidade() { 
        return cidade; 
    }
    public void setCidade(String cidade) { 
        this.cidade = cidade; 
    }

    // Os métodos de UserDetails (getAuthorities, getPassword, getUsername, etc.)
    // são agora herdados diretamente de Usuario. Não precisam ser sobrescritos aqui,
    // a menos que haja um comportamento muito específico para Empresa.
    // O getAuthorities em Usuario já retornará "ROLE_EMPRESA" porque o construtor o define.
}