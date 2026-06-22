package com.prasiddha.gateway.model.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "gateway_users", indexes = {
    @Index(name = "idx_user_username", columnList = "username", unique = true)
})
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class GatewayUser {

    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    /** BCrypt-hashed — never stored in plaintext */
    @Column(nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    @Column(nullable = false)
    private boolean enabled;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    private Instant lastLoginAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        if (role == null) role = Role.USER;
        enabled = true;
    }

    public enum Role { USER, ADMIN }
}
