package com.prasiddha.gateway.security;

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
import java.util.List;

/**
 * Validates Bearer token on every request.
 * On success: sets authenticated principal in SecurityContext.
 * On failure: continues chain — Spring Security rejects at authorization layer.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
        HttpServletRequest req, HttpServletResponse res, FilterChain chain
    ) throws ServletException, IOException {

        String token = extractBearer(req);
        if (!StringUtils.hasText(token) && "/api/v1/admin/stream".equals(req.getRequestURI())) {
            // Browsers' native EventSource can't set an Authorization header — this is the
            // standard, narrow workaround, deliberately scoped to this exact SSE path only.
            token = req.getParameter("token");
        }

        if (StringUtils.hasText(token) && jwtUtil.validateToken(token)) {
            String username = jwtUtil.extractUsername(token);
            String role     = jwtUtil.extractRole(token);

            var auth = new UsernamePasswordAuthenticationToken(
                username, null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role))
            );
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
            SecurityContextHolder.getContext().setAuthentication(auth);

            log.debug("Authenticated: user='{}' role='{}'", username, role);
        }

        chain.doFilter(req, res);
    }

    private String extractBearer(HttpServletRequest req) {
        String header = req.getHeader("Authorization");
        return (StringUtils.hasText(header) && header.startsWith("Bearer "))
            ? header.substring(7) : null;
    }

    /**
     * SseEmitter responses (admin live-stream, /chat/stream) trigger an ASYNC
     * dispatch to finalize the response once the emitter completes. OncePerRequestFilter
     * skips ASYNC dispatches by default, so without this override the SecurityContext set
     * during the original REQUEST dispatch is gone by the time AuthorizationFilter re-checks
     * on that completion pass, and it denies it — harmless to the already-sent data, but it
     * throws a server-side AccessDeniedException on every streaming call. Re-running this
     * filter (idempotent — same header, same request) keeps the context populated for that pass.
     */
    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }
}
