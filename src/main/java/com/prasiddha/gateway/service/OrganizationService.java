package com.prasiddha.gateway.service;

import com.prasiddha.gateway.exception.GatewayException;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.model.entity.Organization;
import com.prasiddha.gateway.repository.OrganizationRepository;
import com.prasiddha.gateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrganizationService {

    private final OrganizationRepository organizationRepository;
    private final UserRepository userRepository;

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

    public GatewayUser addMember(String orgId, String username) {
        Organization org = get(orgId);
        GatewayUser user = userRepository.findByUsername(username)
            .orElseThrow(() -> new GatewayException("User not found: " + username, HttpStatus.NOT_FOUND));
        user.setOrganizationId(org.getId());
        GatewayUser saved = userRepository.save(user);
        log.info("Added user '{}' to organization '{}'", username, org.getName());
        return saved;
    }
}
