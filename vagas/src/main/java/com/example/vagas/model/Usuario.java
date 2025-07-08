package com.example.vagas.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class Usuario implements UserDetails { // Implementa UserDetails

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String senha;

    @Column(nullable = false)
    private String nome;

    @Column(nullable = false)
    private String role; // Novo campo para definir a role (ADMIN, EMPRESA, PROFISSIONAL)

    public Usuario() {
    }

    public Usuario(String email, String senha, String nome, String role) {
        this.email = email;
        this.senha = senha;
        this.nome = nome;
        this.role = role;
    }

    // Getters e Setters
    public Long getId() { 
        return id; 
    }
    public void setId(Long id) { 
        this.id = id; 
    }
    public String getEmail() { 
        return email; 
    }
    public void setEmail(String email) { 
        this.email = email; 
    }
    public String getSenha() { 
        return senha; 
    }
    public void setSenha(String senha) { 
        this.senha = senha; 
    }
    public String getNome() { 
        return nome; 
    }
    public void setNome(String nome) { 
        this.nome = nome; 
    }
    public String getRole() { 
        return role; 
    } // Getter para o novo campo role
    public void setRole(String role) { 
        this.role = role; 
    } // Setter para o novo campo role

    @Override
    public String toString() {
        return "Usuario{" +
               "id=" + id +
               ", email='" + email + '\'' +
               ", nome='" + nome + '\'' +
               ", role='" + role + '\'' +
               '}';
    }

    // Implementações de UserDetails
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Retorna a role do usuário. Ex: "ROLE_ADMIN", "ROLE_EMPRESA", "ROLE_PROFISSIONAL"
        return List.of(new SimpleGrantedAuthority(this.role));
    }

    @Override
    public String getPassword() {
        return this.senha;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    // Métodos padrão do UserDetails (podem ser true por default para a maioria dos casos)
    @Override
    public boolean isAccountNonExpired() { 
        return true; 
    }

    @Override
    public boolean isAccountNonLocked() { 
        return true; 
    }

    @Override
    public boolean isCredentialsNonExpired() { 
        return true; 
    }

    @Override
    public boolean isEnabled() { 
        return true; 
    }
}