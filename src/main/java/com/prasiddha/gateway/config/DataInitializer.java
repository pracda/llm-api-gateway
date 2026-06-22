package com.prasiddha.gateway.config;

import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds an admin user on first startup if none exists.
 *
 * Default credentials (change immediately in production):
 *   username: admin
 *   password: admin123
 *
 * In production, set ADMIN_PASSWORD environment variable.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (!userRepository.existsByUsername("admin")) {
            GatewayUser admin = GatewayUser.builder()
                .username("admin")
                .passwordHash(passwordEncoder.encode("admin123"))
                .role(GatewayUser.Role.ADMIN)
                .build();
            userRepository.save(admin);
            log.info("Admin user created — username: admin (change password immediately in production!)");
        }
    }
}
