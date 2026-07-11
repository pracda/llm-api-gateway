package com.prasiddha.gateway.service;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.repository.OrganizationRepository;
import com.prasiddha.gateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrganizationService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OrganizationRepository organizationRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Organization create(String name) {
        if (organizationRepository.existsByName(name)) {
            throw new GatewayException("An organization named '" + name + "' already exists", HttpStatus.BAD_REQUEST);
        }
        Organization org = Organization.builder().name(name).build();
        Organization saved = organizationRepository.save(org);
        log.info("Organization created: {} (id={})", name, saved.getId());
        return saved;
    }

    public java.util.List<Organization> listAll() {
        return organizationRepository.findAll();
    }

    public Organization get(String orgId) {
        return organizationRepository.findById(orgId)
            .orElseThrow(() -> new GatewayException("Organization not found: " + orgId, HttpStatus.NOT_FOUND));
    }

    /**
     * Adds a user to an organization, auto-provisioning the GatewayUser account
     * if it doesn't already exist — removes the earlier requirement that a
     * member self-register via /auth/register before an admin can add them.
     * If passwordOverride is null for a newly-created account, a random
     * password is generated and returned once (same one-time-reveal pattern
     * as API key creation) so the admin can hand it to the person if they'll
     * ever need dashboard/JWT login; machine-only members can just ignore it.
     */
    public AddMemberResult addMember(String orgId, String username, String passwordOverride) {
        Organization org = get(orgId);
        var existing = userRepository.findByUsername(username);

        GatewayUser user;
        boolean created = false;
        String generatedPassword = null;

        if (existing.isPresent()) {
            user = existing.get();
        } else {
            created = true;
            generatedPassword = passwordOverride != null ? null : generateRandomPassword();
            String rawPassword = passwordOverride != null ? passwordOverride : generatedPassword;
            user = GatewayUser.builder()
                .username(username)
                .passwordHash(passwordEncoder.encode(rawPassword))
                .role(GatewayUser.Role.USER)
                .build();
            user = userRepository.save(user);
            log.info("Auto-provisioned new GatewayUser '{}' while adding as org member", username);
        }

        user.setOrganizationId(org.getId());
        GatewayUser saved = userRepository.save(user);
        log.info("Added user '{}' to organization '{}'", username, org.getName());
        return new AddMemberResult(saved, created, generatedPassword);
    }

    private String generateRandomPassword() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public record AddMemberResult(GatewayUser user, boolean created, String generatedPassword) {}
}
