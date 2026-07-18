package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.config.ProvidersProperties;
import com.prasiddha.gateway.config.ProvidersProperties.ProviderConfig;
import com.prasiddha.gateway.model.response.ProviderModels;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plain unit tests for ModelsController's config validation, model-list sanitisation, and
 * response shape — no Spring context needed since the controller's only collaborator is the
 * {@link ProvidersProperties} config bean. HTTP-level auth enforcement is covered separately
 * in ModelsControllerAuthBoundaryTest.
 *
 * As of F3a the controller is driven by the config-driven provider registry, so response keys
 * are the configured provider names upper-cased (OPENAI, ANTHROPIC, …) for backward
 * compatibility with the original enum-named keys.
 */
@DisplayName("ModelsController — config parsing, validation, and response shape")
class ModelsControllerTest {

    /** Builds a two-provider registry config (openai + anthropic) for the controller under test. */
    private static ProvidersProperties props(
        String openAiDefault, List<String> openAiAllowed,
        String anthropicDefault, List<String> anthropicAllowed
    ) {
        var props = new ProvidersProperties();
        Map<String, ProviderConfig> map = new LinkedHashMap<>();
        map.put("openai", providerConfig("openai-compatible", openAiDefault, openAiAllowed));
        map.put("anthropic", providerConfig("anthropic", anthropicDefault, anthropicAllowed));
        props.setProviders(map);
        return props;
    }

    private static ProviderConfig providerConfig(String type, String defaultModel, List<String> allowed) {
        var cfg = new ProviderConfig();
        cfg.setType(type);
        cfg.setDefaultModel(defaultModel);
        if (allowed != null) {
            cfg.setAllowedModels(allowed);
        }
        return cfg;
    }

    @Nested
    @DisplayName("Happy path")
    class HappyPath {

        @Test
        void returnsBothProvidersWithDefaultAndAllowedModels() {
            var controller = new ModelsController(props(
                "gpt-4o-mini", List.of("gpt-4o-mini", "gpt-4o", "gpt-4-turbo"),
                "claude-haiku-4-5-20251001", List.of("claude-haiku-4-5-20251001", "claude-sonnet-5")
            ));

            ResponseEntity<Map<String, ProviderModels>> response = controller.models("someuser");

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            var body = response.getBody();
            assertThat(body).containsKeys("OPENAI", "ANTHROPIC");

            ProviderModels openai = body.get("OPENAI");
            assertThat(openai.defaultModel()).isEqualTo("gpt-4o-mini");
            assertThat(openai.allowed()).containsExactly("gpt-4o-mini", "gpt-4o", "gpt-4-turbo");

            ProviderModels anthropic = body.get("ANTHROPIC");
            assertThat(anthropic.defaultModel()).isEqualTo("claude-haiku-4-5-20251001");
            assertThat(anthropic.allowed()).containsExactly("claude-haiku-4-5-20251001", "claude-sonnet-5");
        }
    }

    @Nested
    @DisplayName("Allowed-models sanitisation")
    class AllowedModelsSanitisation {

        @Test
        void trimsWhitespaceAroundEntries() {
            var controller = new ModelsController(props(
                "gpt-4o-mini", List.of(" gpt-4 ", " gpt-3.5-turbo "),
                "claude-haiku-4-5-20251001", List.of("claude-sonnet-5")
            ));
            assertThat(controller.models("u").getBody().get("OPENAI").allowed())
                .containsExactly("gpt-4", "gpt-3.5-turbo");
        }

        @Test
        void filtersBlankEntries() {
            var controller = new ModelsController(props(
                "gpt-4o-mini", java.util.Arrays.asList("gpt-4o-mini", "   "),
                "claude-haiku-4-5-20251001", List.of("claude-sonnet-5")
            ));
            assertThat(controller.models("u").getBody().get("OPENAI").allowed())
                .containsExactly("gpt-4o-mini");
        }

        @Test
        void emptyAllowedModelsListYieldsEmptyArray_defaultStillAvailable() {
            // An empty allow-list means no explicit "model" string is accepted for this provider —
            // it does NOT mean "allow all". A request that omits `model` still falls back to
            // `default`, since LlmProxyService only validates when a model is explicitly given.
            var controller = new ModelsController(props(
                "gpt-4o-mini", List.of(),
                "claude-haiku-4-5-20251001", List.of("claude-sonnet-5")
            ));
            ProviderModels openai = controller.models("u").getBody().get("OPENAI");
            assertThat(openai.allowed()).isEmpty();
            assertThat(openai.defaultModel()).isEqualTo("gpt-4o-mini");
        }

        @Test
        void filtersOutMalformedEntriesRatherThanEchoingThemBack() {
            var controller = new ModelsController(props(
                "gpt-4o-mini", List.of("gpt-4o-mini", "not a model!", "<script>alert(1)</script>"),
                "claude-haiku-4-5-20251001", List.of("claude-sonnet-5")
            ));
            assertThat(controller.models("u").getBody().get("OPENAI").allowed())
                .containsExactly("gpt-4o-mini");
        }
    }

    @Nested
    @DisplayName("Required configuration — fails fast with a clear message")
    class RequiredConfiguration {

        @Test
        void blankDefaultModelThrows() {
            var controller = new ModelsController(props(
                "  ", List.of("gpt-4o-mini"),
                "claude-haiku-4-5-20251001", List.of("claude-sonnet-5")
            ));
            assertThatThrownBy(() -> controller.models("u"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.llm.providers.openai.default-model");
        }
    }
}
