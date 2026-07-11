package com.prasiddha.gateway.config;

import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds an admin user on first startup if none exists.
 *
 * Default credentials (change immediately in production):
 *   username: admin
 *   password: value of the ADMIN_PASSWORD environment variable, falling
 *             back to "admin123" if unset (local dev only).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private static final String INSECURE_DEFAULT_PASSWORD = "admin123";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.default-password}")
    private String adminPassword;

    @Override
    public void run(String... args) {
        if (!userRepository.existsByUsername("admin")) {
            GatewayUser admin = GatewayUser.builder()
                .username("admin")
                .passwordHash(passwordEncoder.encode(adminPassword))
                .role(GatewayUser.Role.ADMIN)
                .build();
            userRepository.save(admin);

            if (INSECURE_DEFAULT_PASSWORD.equals(adminPassword)) {
                log.warn("Admin user created with the INSECURE DEFAULT password 'admin123' — " +
                    "set the ADMIN_PASSWORD environment variable before deploying to production!");
            } else {
                log.info("Admin user created — username: admin (password from ADMIN_PASSWORD)");
            }
        }
    }
}
