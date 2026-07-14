package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ProviderModels;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Model discovery — lets clients ask which models this gateway accepts
 * instead of guessing and getting a 400 from the allow-list check in
 * LlmProxyService. The response mirrors the app.llm.* configuration.
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

    private final String openAiDefault;
    private final List<String> openAiAllowed;
    private final String anthropicDefault;
    private final List<String> anthropicAllowed;

    public ModelsController(
        @Value("${app.llm.openai.default-model}") String openAiDefault,
        @Value("${app.llm.openai.allowed-models}") String openAiAllowedCsv,
        @Value("${app.llm.anthropic.default-model}") String anthropicDefault,
        @Value("${app.llm.anthropic.allowed-models}") String anthropicAllowedCsv
    ) {
        this.openAiDefault = requireConfigured("app.llm.openai.default-model", openAiDefault);
        this.openAiAllowed = toValidatedList("app.llm.openai.allowed-models", openAiAllowedCsv);
        this.anthropicDefault = requireConfigured("app.llm.anthropic.default-model", anthropicDefault);
        this.anthropicAllowed = toValidatedList("app.llm.anthropic.allowed-models", anthropicAllowedCsv);
    }

    @GetMapping("/models")
    @PreAuthorize("isAuthenticated()")
    @Operation(
        summary = "List the models this gateway accepts, per provider",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponse(
        responseCode = "200",
        description = "Keys are provider names (OPENAI, ANTHROPIC). Each value has a `default` "
            + "model (used when a chat request omits `model`) and `allowed` — the full "
            + "allow-list LlmProxyService validates an explicit `model` against. An empty "
            + "`allowed` array means no explicit model string is accepted for that provider "
            + "(a request can still omit `model` entirely to use `default`).",
        content = @Content(schema = @Schema(example =
            "{\"OPENAI\":{\"default\":\"gpt-4o-mini\",\"allowed\":[\"gpt-4o-mini\",\"gpt-4o\"]},"
                + "\"ANTHROPIC\":{\"default\":\"claude-haiku-4-5-20251001\",\"allowed\":[\"claude-haiku-4-5-20251001\"]}}"))
    )
    public ResponseEntity<Map<ChatRequest.LlmProvider, ProviderModels>> models(
        @AuthenticationPrincipal String username
    ) {
        log.debug("Model discovery requested by '{}'", username);
        Map<ChatRequest.LlmProvider, ProviderModels> body = new EnumMap<>(ChatRequest.LlmProvider.class);
        body.put(ChatRequest.LlmProvider.OPENAI, new ProviderModels(openAiDefault, openAiAllowed));
        body.put(ChatRequest.LlmProvider.ANTHROPIC, new ProviderModels(anthropicDefault, anthropicAllowed));
        return ResponseEntity.ok(body);
    }

    /**
     * Fails fast with a clear, property-specific message at startup rather than letting Spring
     * throw an opaque BeanCreationException if app.llm.*.default-model is missing or blank.
     */
    private static String requireConfigured(String propertyName, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                "Required property '" + propertyName + "' is missing or blank — ModelsController cannot start without it.");
        }
        return value;
    }

    /**
     * Same fail-fast requirement as requireConfigured, plus filters out (with a warning log)
     * any comma-separated entry that doesn't look like a plausible model ID — trailing/leading
     * commas and whitespace are silently dropped (intentional), anything else malformed is
     * dropped rather than echoed back to clients verbatim.
     */
    private static List<String> toValidatedList(String propertyName, String csv) {
        if (csv == null) {
            throw new IllegalStateException(
                "Required property '" + propertyName + "' is missing — ModelsController cannot start without it.");
        }
        return Arrays.stream(csv.split(","))
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
