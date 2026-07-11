package com.prasiddha.gateway.security;

import com.prasiddha.gateway.model.entity.ApiKey;
import com.prasiddha.gateway.model.entity.GatewayUser;
import com.prasiddha.gateway.repository.ApiKeyRepository;
import com.prasiddha.gateway.repository.UserRepository;
import com.prasiddha.gateway.service.ApiKeyService;
import com.prasiddha.gateway.service.AuditService;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Validates the X-API-Key header on every request. On success, sets the
 * same kind of authenticated principal as JwtAuthFilter, plus an extra
 * "API_KEY_AUTH" authority — the hook SecurityConfig uses to require an
 * API key specifically for /api/v1/chat (JWT alone is not enough there).
 *
 * Must run AFTER JwtAuthFilter in the chain (see SecurityConfig) so that
 * if a caller sends both headers, the API-key authentication wins on
 * /chat. Lockout is intentionally NOT checked here — it's ephemeral
 * Redis state checked once per real usage point (ChatController /
 * AuthController), not on every filter invocation.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_AUTHORITY = "API_KEY_AUTH";
    public static final String API_KEY_ID_ATTRIBUTE = "apiKeyId";

    private final ApiKeyRepository apiKeyRepository;
    private final UserRepository userRepository;
    private final ApiKeyService apiKeyService;

    @Override
    protected void doFilterInternal(
        HttpServletRequest req, HttpServletResponse res, FilterChain chain
    ) throws ServletException, IOException {

        String rawKey = req.getHeader("X-API-Key");

        if (StringUtils.hasText(rawKey)) {
            String hash = AuditService.hash(rawKey);
            Optional<ApiKey> found = apiKeyRepository.findByKeyHash(hash);

            if (found.isPresent() && isUsable(found.get())) {
                ApiKey apiKey = found.get();
                Optional<GatewayUser> owner = userRepository.findByUsername(apiKey.getUsername());

                if (owner.isPresent() && owner.get().isEnabled()) {
                    GatewayUser user = owner.get();
                    var auth = new UsernamePasswordAuthenticationToken(
                        user.getUsername(), null,
                        List.of(
                            new SimpleGrantedAuthority("ROLE_" + user.getRole().name()),
                            new SimpleGrantedAuthority(API_KEY_AUTHORITY)
                        )
                    );
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    req.setAttribute(API_KEY_ID_ATTRIBUTE, apiKey.getId());

                    apiKeyService.touchLastUsedAsync(apiKey.getId());
                    log.debug("Authenticated via API key: user='{}' keyId='{}'", user.getUsername(), apiKey.getId());
                }
            }
        }

        chain.doFilter(req, res);
    }

    private boolean isUsable(ApiKey key) {
        return key.getStatus() == ApiKey.Status.ACTIVE
            && (key.getExpiresAt() == null || key.getExpiresAt().isAfter(Instant.now()));
    }

    /** See JwtAuthFilter.shouldNotFilterAsyncDispatch() — same reasoning applies to /chat/stream. */
    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }
}
