package com.prasiddha.gateway.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Per-provider model info returned by {@code GET /api/v1/models} — mirrors the
 * app.llm.{provider}.default-model / allowed-models configuration.
 *
 * {@code default} is a reserved Java keyword, hence the field/JSON-name split.
 */
public record ProviderModels(
    @JsonProperty("default") String defaultModel,
    List<String> allowed
) {}
