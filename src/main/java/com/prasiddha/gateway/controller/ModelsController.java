package com.prasiddha.gateway.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Model discovery — lets clients ask which models this gateway accepts
 * instead of guessing and getting a 400 from the allow-list check in
 * LlmProxyService. The response mirrors the app.llm.* configuration.
 *
 * Requires authentication (any principal), same as the rest of /api/v1.
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Model Discovery")
public class ModelsController {

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
        this.openAiDefault = openAiDefault;
        this.openAiAllowed = toList(openAiAllowedCsv);
        this.anthropicDefault = anthropicDefault;
        this.anthropicAllowed = toList(anthropicAllowedCsv);
    }

    @GetMapping("/models")
    @Operation(
        summary = "List the models this gateway accepts, per provider",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> models() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("OPENAI", Map.of("default", openAiDefault, "allowed", openAiAllowed));
        body.put("ANTHROPIC", Map.of("default", anthropicDefault, "allowed", anthropicAllowed));
        return ResponseEntity.ok(body);
    }

    private static List<String> toList(String csv) {
        return Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .toList();
    }
}
