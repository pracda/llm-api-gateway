package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.config.ProvidersProperties;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.model.response.ProviderModels;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Model discovery — lets clients ask which models this gateway accepts
 * instead of guessing and getting a 400 from the allow-list check in
 * LlmProxyService. The response mirrors the app.llm.providers.* configuration.
 *
 * As of F3a the provider list is config-driven: response keys are the configured
 * provider names (upper-cased for backward compatibility with the original
 * OPENAI/ANTHROPIC keys), so newly-configured providers appear here automatically.
 *
 * Requires authentication (any principal — JWT or API key both satisfy
 * SecurityConfig's anyRequest().authenticated(), unlike /chat which needs
 * an API key specifically).
 *
 * Exposing the full default/allowed model list here is intentional, not an
 * oversight: the entire point of this endpoint is letting an authenticated
 * caller discover exactly what LlmProxyService's allow-list will accept.
 * Restricting the response would defeat that purpose — see PR #1 review
 * finding #12, treated as accepted-by-design rather than fixed.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Model Discovery")
public class ModelsController {

    /**
     * Model IDs are provider-controlled strings (e.g. "gpt-4o-mini", "claude-sonnet-5") —
     * deliberately permissive, but rejects anything that couldn't plausibly be a model ID
     * (whitespace, control characters, etc.) so a misconfigured value never gets echoed
     * back to clients verbatim.
     */
    private static final Pattern VALID_MODEL_ID = Pattern.compile("[A-Za-z0-9._-]+");

    private final ProvidersProperties providersProperties;

    public ModelsController(ProvidersProperties providersProperties) {
        this.providersProperties = providersProperties;
    }

    @GetMapping("/models")
    @PreAuthorize("isAuthenticated()")
    @Operation(
        summary = "List the models this gateway accepts, per provider",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponse(
        responseCode = "200",
        description = "Keys are provider names (e.g. OPENAI, ANTHROPIC). Each value has a `default` "
            + "model (used when a chat request omits `model`) and `allowed` — the full "
            + "allow-list LlmProxyService validates an explicit `model` against. An empty "
            + "`allowed` array means no explicit model string is accepted for that provider "
            + "(a request can still omit `model` entirely to use `default`).",
        content = @Content(schema = @Schema(example =
            "{\"OPENAI\":{\"default\":\"gpt-4o-mini\",\"allowed\":[\"gpt-4o-mini\",\"gpt-4o\"]},"
                + "\"ANTHROPIC\":{\"default\":\"claude-haiku-4-5-20251001\",\"allowed\":[\"claude-haiku-4-5-20251001\"]}}"))
    )
    public ResponseEntity<Map<String, ProviderModels>> models(
        @AuthenticationPrincipal String username
    ) {
        log.debug("Model discovery requested by '{}'", username);
        Map<String, ProviderModels> body = new LinkedHashMap<>();
        providersProperties.getProviders().forEach((name, cfg) -> {
            String key = name.trim().toUpperCase();
            body.put(key, new ProviderModels(
                requireConfigured("app.llm.providers." + name + ".default-model", cfg.getDefaultModel()),
                validatedModels("app.llm.providers." + name + ".allowed-models", cfg)
            ));
        });
        return ResponseEntity.ok(body);
    }

    /**
     * Fails fast with a clear, property-specific message at startup rather than letting a
     * misconfigured provider silently return a null default model.
     */
    private static String requireConfigured(String propertyName, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                "Required property '" + propertyName + "' is missing or blank — ModelsController cannot start without it.");
        }
        return value;
    }

    /**
     * Filters out (with a warning log) any allowed-models entry that doesn't look like a
     * plausible model ID, so a misconfigured value never gets echoed back to clients verbatim.
     */
    private static List<String> validatedModels(String propertyName, ProviderConfig cfg) {
        List<String> models = cfg.getAllowedModels();
        if (models == null) {
            return List.of();
        }
        return models.stream()
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .filter(s -> {
                boolean valid = VALID_MODEL_ID.matcher(s).matches();
                if (!valid) {
                    log.warn("Ignoring malformed model entry in '{}': '{}'", propertyName, s);
                }
                return valid;
            })
            .toList();
    }
}
