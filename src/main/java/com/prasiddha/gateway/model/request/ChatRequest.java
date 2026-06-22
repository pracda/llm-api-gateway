package com.prasiddha.gateway.model.request;

import jakarta.validation.constraints.*;
import lombok.Data;
import java.util.List;

/**
 * What clients POST to /api/v1/chat
 *
 * {
 *   "provider": "OPENAI",
 *   "model": "gpt-4o-mini",          // optional — uses default if omitted
 *   "systemPrompt": "You are ...",   // optional
 *   "userMessage": "Hello!",
 *   "history": []                    // optional — prior turns
 * }
 */
@Data
public class ChatRequest {

    @NotNull(message = "provider is required (OPENAI or ANTHROPIC)")
    private LlmProvider provider;

    @Size(max = 100)
    private String model;

    @Size(max = 2000, message = "systemPrompt must not exceed 2000 characters")
    private String systemPrompt;

    @NotBlank(message = "userMessage must not be blank")
    @Size(max = 8000, message = "userMessage must not exceed 8000 characters")
    private String userMessage;

    private List<HistoryEntry> history;

    public enum LlmProvider { OPENAI, ANTHROPIC }

    @Data
    public static class HistoryEntry {
        @NotBlank private String role;     // "user" or "assistant"
        @NotBlank private String content;
    }
}
