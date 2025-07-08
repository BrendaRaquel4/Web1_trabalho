package com.example.vagas.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.PrimaryKeyJoinColumn;

@Entity
@Table(name = "administrador") // Opcional, o JPA pode usar o nome da classe.
@PrimaryKeyJoinColumn(name = "id") // Garante que a seja a FK para Usuario
public class Administrador extends Usuario {

    public Administrador() {
        super();
    }

    // Construtor para facilitar a criação, herdando de Usuario
    public Administrador(String email, String senha, String nome) {
        super(email, senha, nome, "ROLE_ADMIN"); // Define a role 
    }

}