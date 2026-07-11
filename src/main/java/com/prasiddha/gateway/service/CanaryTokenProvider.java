package com.prasiddha.gateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * A fixed per-deployment marker appended to every hardened system prompt
 * (see OpenAiProvider/AnthropicProvider). If this string ever appears in
 * an LLM response, the system prompt was leaked back to the model's
 * output — OutputScanService treats that as a confirmed OWASP LLM #06
 * prompt-leak and blocks the response.
 */
@Slf4j
@Component
public class CanaryTokenProvider {

    private final String token;

    public CanaryTokenProvider(@Value("${app.security.canary-token:}") String configured) {
        if (configured != null && !configured.isBlank()) {
            this.token = configured;
        } else {
            this.token = "cnry-" + UUID.randomUUID();
            log.info("No CANARY_TOKEN configured — generated one for this run: {}", this.token);
        }
    }

    public String get() {
        return token;
    }
}
