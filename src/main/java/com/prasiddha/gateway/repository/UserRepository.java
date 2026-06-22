package com.prasiddha.gateway.repository;

import com.prasiddha.gateway.model.entity.GatewayUser;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<GatewayUser, String> {
    Optional<GatewayUser> findByUsername(String username);
    boolean existsByUsername(String username);
}
