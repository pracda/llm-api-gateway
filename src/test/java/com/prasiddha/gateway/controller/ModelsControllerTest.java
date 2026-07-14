package com.prasiddha.gateway.controller;

import com.prasiddha.gateway.model.request.ChatRequest;
import com.prasiddha.gateway.model.response.ProviderModels;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plain unit tests for ModelsController's constructor validation, CSV parsing, and response
 * shape — no Spring context needed since the controller has no other collaborators. HTTP-level
 * auth enforcement is covered separately in ModelsControllerAuthBoundaryTest.
 */
@DisplayName("ModelsController — config parsing, validation, and response shape")
class ModelsControllerTest {

    @Nested
    @DisplayName("Happy path")
    class HappyPath {

        @Test
        void returnsBothProvidersWithDefaultAndAllowedModels() {
            var controller = new ModelsController(
                "gpt-4o-mini", "gpt-4o-mini,gpt-4o,gpt-4-turbo",
                "claude-haiku-4-5-20251001", "claude-haiku-4-5-20251001,claude-sonnet-5"
            );

            ResponseEntity<java.util.Map<ChatRequest.LlmProvider, ProviderModels>> response =
                controller.models("someuser");

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            var body = response.getBody();
            assertThat(body).containsKeys(ChatRequest.LlmProvider.OPENAI, ChatRequest.LlmProvider.ANTHROPIC);

            ProviderModels openai = body.get(ChatRequest.LlmProvider.OPENAI);
            assertThat(openai.defaultModel()).isEqualTo("gpt-4o-mini");
            assertThat(openai.allowed()).containsExactly("gpt-4o-mini", "gpt-4o", "gpt-4-turbo");

            ProviderModels anthropic = body.get(ChatRequest.LlmProvider.ANTHROPIC);
            assertThat(anthropic.defaultModel()).isEqualTo("claude-haiku-4-5-20251001");
            assertThat(anthropic.allowed()).containsExactly("claude-haiku-4-5-20251001", "claude-sonnet-5");
        }
    }

    @Nested
    @DisplayName("CSV parsing")
    class CsvParsing {

        @Test
        void trimsWhitespaceAroundEntries() {
            var controller = new ModelsController(
                "gpt-4o-mini", "gpt-4 , gpt-3.5-turbo",
                "claude-haiku-4-5-20251001", "claude-sonnet-5"
            );
            assertThat(controller.models("u").getBody().get(ChatRequest.LlmProvider.OPENAI).allowed())
                .containsExactly("gpt-4", "gpt-3.5-turbo");
        }

        @Test
        void filtersEmptySegmentsFromTrailingCommas() {
            var controller = new ModelsController(
                "gpt-4o-mini", "gpt-4o-mini,",
                "claude-haiku-4-5-20251001", "claude-sonnet-5"
            );
            assertThat(controller.models("u").getBody().get(ChatRequest.LlmProvider.OPENAI).allowed())
                .containsExactly("gpt-4o-mini");
        }

        @Test
        void emptyAllowedModelsListYieldsEmptyArray_defaultStillAvailable() {
            // An empty allow-list means no explicit "model" string is accepted for this provider —
            // it does NOT mean "allow all". A request that omits `model` still falls back to
            // `default`, since LlmProxyService only validates when a model is explicitly given.
            var controller = new ModelsController(
                "gpt-4o-mini", "   ",
                "claude-haiku-4-5-20251001", "claude-sonnet-5"
            );
            ProviderModels openai = controller.models("u").getBody().get(ChatRequest.LlmProvider.OPENAI);
            assertThat(openai.allowed()).isEmpty();
            assertThat(openai.defaultModel()).isEqualTo("gpt-4o-mini");
        }

        @Test
        void filtersOutMalformedEntriesRatherThanEchoingThemBack() {
            var controller = new ModelsController(
                "gpt-4o-mini", "gpt-4o-mini,not a model!,<script>alert(1)</script>",
                "claude-haiku-4-5-20251001", "claude-sonnet-5"
            );
            assertThat(controller.models("u").getBody().get(ChatRequest.LlmProvider.OPENAI).allowed())
                .containsExactly("gpt-4o-mini");
        }
    }

    @Nested
    @DisplayName("Required configuration — fails fast with a clear message")
    class RequiredConfiguration {

        @Test
        void blankDefaultModelThrows() {
            assertThatThrownBy(() -> new ModelsController(
                "  ", "gpt-4o-mini",
                "claude-haiku-4-5-20251001", "claude-sonnet-5"
            )).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.llm.openai.default-model");
        }

        @Test
        void nullAllowedModelsCsvThrows() {
            assertThatThrownBy(() -> new ModelsController(
                "gpt-4o-mini", null,
                "claude-haiku-4-5-20251001", "claude-sonnet-5"
            )).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.llm.openai.allowed-models");
        }
    }
}
