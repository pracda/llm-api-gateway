package com.prasiddha.gateway.repository;

import com.prasiddha.gateway.model.entity.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface ApiKeyRepository extends JpaRepository<ApiKey, String> {

    Optional<ApiKey> findByKeyHash(String keyHash);

    List<ApiKey> findByOrganizationIdOrderByCreatedAtDesc(String organizationId);

    List<ApiKey> findByUsernameOrderByCreatedAtDesc(String username);

    List<ApiKey> findByStatusAndExpiresAtBefore(ApiKey.Status status, Instant instant);
}
