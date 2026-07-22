package com.prasiddha.gateway.model.request;

import jakarta.validation.constraints.*;
import lombok.Data;
import java.util.List;

/**
 * What clients POST to /api/v1/chat
 *
 * {
 *   "provider": "openai",            // any configured provider key; case-insensitive
 *   "model": "gpt-4o-mini",          // optional — uses default if omitted; "auto" = let the gateway pick
 *   "task": "coding",                // optional — task-based routing; overrides provider/model
 *   "systemPrompt": "You are ...",   // optional
 *   "userMessage": "Hello!",
 *   "history": []                    // optional — prior turns
 * }
 *
 * As of F3a, {@code provider} is a free-form string key resolved against the configured
 * provider registry ({@code app.llm.providers.*}) instead of a fixed enum, so new
 * providers need no code change. Legacy callers sending "OPENAI"/"ANTHROPIC" still work —
 * {@link #providerKey()} normalises case. An unknown key yields a clean 400 at routing time.
 *
 * Routing precedence (highest first): {@code task} (task-profile routing) → {@code model:"auto"}
 * (complexity routing, F3b) → explicit {@code provider}/{@code model}.
 */
@Data
public class ChatRequest {

    @NotBlank(message = "provider is required (e.g. openai or anthropic)")
    @Size(max = 50)
    private String provider;

    @Size(max = 100)
    private String model;

    /** Optional task label (e.g. "coding", "reasoning") routed to a configured profile — see F3b task routing. */
    @Size(max = 50)
    private String task;

    @Size(max = 2000, message = "systemPrompt must not exceed 2000 characters")
    private String systemPrompt;

    @NotBlank(message = "userMessage must not be blank")
    @Size(max = 8000, message = "userMessage must not exceed 8000 characters")
    private String userMessage;

    private List<HistoryEntry> history;

    /** Canonical lower-case provider key used for registry lookup, pricing, and audit. */
    public String providerKey() {
        return provider == null ? null : provider.trim().toLowerCase();
    }

    /** Canonical lower-case task key for profile lookup, or null when no task was requested. */
    public String taskKey() {
        return task == null || task.isBlank() ? null : task.trim().toLowerCase();
    }

    /**
     * Copy of this request for a fallback rung on a DIFFERENT provider (F6): the explicit
     * {@code model} is dropped so the new provider uses its own default (the requested model
     * is provider-specific and would 404 elsewhere). Prompt/history are carried over.
     */
    public ChatRequest copyForProvider() {
        ChatRequest c = new ChatRequest();
        c.setProvider(this.provider);
        c.setModel(null);
        c.setSystemPrompt(this.systemPrompt);
        c.setUserMessage(this.userMessage);
        c.setHistory(this.history);
        return c;
    }

    @Data
    public static class HistoryEntry {
        @NotBlank private String role;     // "user" or "assistant"
        @NotBlank private String content;
    }
}
